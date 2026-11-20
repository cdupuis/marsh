//! Ownership-map and in-daemon source-overlap rules through the real adapter
//! against the stock model. No real SBX is invoked.
use super::*;

const FOREIGN: &str = "11111111-1111-4111-8111-111111111111";

#[test]
fn ownership_map_refuses_foreign_recreates_absent_and_never_removes_foreign() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let model = StockModel::new();
    model.seed_vm("unrecorded");
    model.seed_vm("replaced");
    let adapter = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(map.clone())
        .unwrap();
    // A recorded name whose stock UUID differs was replaced by someone else.
    adapter.ownership.record("replaced", FOREIGN).unwrap();

    // Foreign: present but unrecorded, or present with a different UUID.
    assert_eq!(
        adapter.classify_vm("unrecorded", false).unwrap(),
        VmClass::Foreign
    );
    assert_eq!(
        adapter.classify_vm("replaced", false).unwrap(),
        VmClass::Foreign
    );
    // Warm classification reuses the cached view.
    assert_eq!(model.count("ls"), 1);
    let deadline = Instant::now() + Duration::from_secs(5);
    assert!(matches!(
        adapter.remove_owned_vm("unrecorded", deadline),
        Err(SbxError::ForeignVm(_))
    ));
    assert!(matches!(
        adapter.remove_owned_vm("replaced", deadline),
        Err(SbxError::ForeignVm(_))
    ));
    assert!(matches!(
        adapter.stop_quarantined_name("unrecorded", "test".into()),
        Err(SbxError::ForeignVm(_))
    ));
    assert_eq!(model.mutations(), 0, "foreign VMs must never be touched");

    // Absent: a new VM appears (stock create) and its UUID is recorded durably.
    assert_eq!(adapter.classify_vm("mine", true).unwrap(), VmClass::Absent);
    let created = model.seed_vm("mine");
    assert_eq!(adapter.adopt_created("mine").unwrap(), created);
    assert_eq!(
        adapter.classify_vm("mine", false).unwrap(),
        VmClass::Owned {
            uuid: created.clone(),
            running: true
        }
    );
    let reloaded = VmOwnership::persisted(map).unwrap();
    assert_eq!(reloaded.uuid("mine").as_deref(), Some(created.as_str()));

    // Owned removal is fenced to the recorded UUID, addressed by name (local
    // stock SBX rejects UUIDs), then forgets it.
    assert!(adapter.remove_owned_vm("mine", deadline).unwrap());
    assert_eq!(
        model.calls_of("rm")[0].args.last().map(String::as_str),
        Some("mine")
    );
    assert_eq!(adapter.ownership.uuid("mine"), None);
    assert_eq!(model.vm_names(), ["replaced", "unrecorded"]);
}

#[test]
fn source_overlap_is_rejected_within_batch_and_against_active_grants() {
    let root = scratch();
    let project = root.path().join("project");
    let nested = project.join("nested");
    let unrelated = directory(root.path(), "unrelated");
    fs::create_dir_all(&nested).unwrap();
    let model = StockModel::new();
    let adapter = model.adapter();
    model.seed_owned(&adapter, "marsh-kit-fixture");
    let rw = MountAccess::ReadWrite;

    let batch = [
        grant(project.clone(), "/Users/alice/project", rw),
        grant(nested.clone(), "/Users/alice/nested", rw),
    ];
    assert!(matches!(
        adapter.preflight_host_grants(&batch),
        Err(SbxError::HostGrantFence(message)) if message.contains("overlaps")
    ));

    // An active job grant on the project.
    adapter
        .prepare_grants(
            &kit_vm("marsh-kit-fixture"),
            "attempt-active",
            &[grant(project.clone(), "/Users/alice/project", rw)],
        )
        .unwrap();
    let calls = model.calls().len();
    // A nested source under an active grant is refused; the identical source
    // (shared by shell and Kit VMs) and unrelated sources are admitted.
    assert!(matches!(
        adapter.preflight_host_grants(&[grant(nested, "/Users/alice/nested", rw)]),
        Err(SbxError::HostGrantFence(message)) if message.contains("overlaps active grant")
    ));
    adapter
        .preflight_host_grants(&[grant(project, "/Users/alice/project", rw)])
        .unwrap();
    adapter
        .preflight_host_grants(&[grant(unrelated, "/Users/alice/unrelated", rw)])
        .unwrap();
    assert_eq!(
        model.calls().len(),
        calls,
        "admission runs no stock command"
    );
}

#[test]
fn admission_preflight_refuses_live_grants_but_not_idle_retained_ones() {
    let root = scratch();
    let project = root.path().join("project");
    let nested = project.join("nested");
    fs::create_dir_all(&nested).unwrap();
    let model = StockModel::new();
    let adapter = model.adapter();
    model.seed_owned(&adapter, "marsh-kit-fixture");
    let vm = kit_vm("marsh-kit-fixture");
    let rw = MountAccess::ReadWrite;

    let live = adapter
        .prepare_grants(
            &vm,
            "attempt-active",
            &[grant(project.clone(), "/Users/alice/project", rw)],
        )
        .unwrap();
    // A job holds the parent: the nested source is refused at admission too.
    assert!(matches!(
        adapter.preflight_host_grants_evicting_idle(&[grant(
            nested.clone(),
            "/Users/alice/nested",
            rw
        )]),
        Err(SbxError::HostGrantFence(message)) if message.contains("overlaps active grant")
    ));

    // The job ends; the mount stays retained while the VM is warm, but idle.
    adapter.revoke_grants(&live).unwrap();
    let calls = model.calls().len();
    adapter
        .preflight_host_grants_evicting_idle(&[grant(nested.clone(), "/Users/alice/nested", rw)])
        .unwrap();
    assert_eq!(
        model.calls().len(),
        calls,
        "admission runs no stock command"
    );
    // The mount step itself still evicts the idle parent before it re-checks.
    adapter
        .prepare_grants(
            &vm,
            "attempt-nested",
            &[grant(nested, "/Users/alice/nested", rw)],
        )
        .unwrap();
    assert_eq!(model.count("umount"), 1);
}

#[test]
fn create_intent_persists_before_create_and_restart_adopts_present_and_keeps_absent() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let model = StockModel::new();
    let first = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(map.clone())
        .unwrap();
    let created = first.vm_name(VmPurpose::Kit, "kit-a").unwrap();
    let never = first.vm_name(VmPurpose::Kit, "kit-b").unwrap();
    assert!(created.starts_with("marsh-k-") && created.len() == 16);
    assert_ne!(created, never);
    assert_eq!(first.vm_name(VmPurpose::Kit, "kit-a").unwrap(), created);
    // The intent is durable before any stock call.
    assert!(model.calls().is_empty());
    assert!(fs::read_to_string(&map).unwrap().contains(&created));
    // Crash after `sbx create` succeeded but before the UUID was recorded.
    let uuid = model.seed_vm(&created);
    drop(first);

    let restarted = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(map)
        .unwrap();
    assert_eq!(
        restarted.classify_vm(&created, true).unwrap(),
        VmClass::Owned {
            uuid,
            running: true
        }
    );
    // An intent that stays absent is never dropped, however many inventories
    // list without it: its create may still land. The Kit reuses its name.
    for _ in 0..3 {
        restarted.ownership.invalidate();
        assert!(matches!(
            restarted.classify_vm(&created, true).unwrap(),
            VmClass::Owned { .. }
        ));
    }
    assert_eq!(restarted.vm_name(VmPurpose::Kit, "kit-b").unwrap(), never);
    assert_eq!(restarted.vm_name(VmPurpose::Kit, "kit-a").unwrap(), created);
    // The adopted VM is removable once fenced to its exact UUID.
    assert!(
        restarted
            .remove_owned_vm(&created, Instant::now() + Duration::from_secs(5))
            .unwrap()
    );
    assert_eq!(model.vm_names(), [] as [std::string::String; 0]);
}

/// Audit B-06: an `sbx create` still in flight when the daemon restarted
/// lands after the new daemon's first inventory. Its intent must survive that
/// inventory, so the VM is adopted by its UUID and `marsh gc` can remove it
/// (only it) instead of leaving an orphan no marsh command touches.
#[test]
fn a_create_that_lands_after_a_restart_is_adopted_and_removable_by_uuid() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let model = StockModel::new();
    let first = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(map.clone())
        .unwrap();
    let name = first.vm_name(VmPurpose::Kit, "kit-a").unwrap();
    // The daemon dies while `sbx create` is still pulling the Kit's image.
    drop(first);
    let stranger = model.seed_vm("marsh-k-other");
    model.with_vm("marsh-k-other", |vm| vm.running = false);

    let restarted = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(map.clone())
        .unwrap();
    // However many inventories list without it, however long it takes.
    for _ in 0..5 {
        assert_eq!(restarted.classify_vm(&name, true).unwrap(), VmClass::Absent);
    }

    // The create lands.
    let landed = model.seed_vm(&name);
    model.with_vm(&name, |vm| vm.running = false);
    assert_eq!(
        restarted.classify_vm(&name, true).unwrap(),
        VmClass::Owned {
            uuid: landed.clone(),
            running: false
        }
    );
    let (recorded, unrecorded) = restarted.recorded_vms().unwrap();
    assert_eq!(
        recorded
            .iter()
            .map(|vm| vm.name.as_str())
            .collect::<Vec<_>>(),
        [name.as_str()]
    );
    assert_eq!(unrecorded, ["marsh-k-other"]);

    let removed = restarted
        .remove_unused_kit_vm(
            &name,
            "kit-a",
            &BTreeSet::new(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    assert!(removed);
    assert_eq!(model.vm_names(), ["marsh-k-other"]);
    assert_eq!(model.vm("marsh-k-other").unwrap().id, stranger);
    assert!(matches!(
        restarted.remove_unused_kit_vm(
            "marsh-k-other",
            "other",
            &BTreeSet::new(),
            Instant::now() + Duration::from_secs(5),
        ),
        Err(SbxError::ForeignVm(_))
    ));
    assert_eq!(model.vm_names(), ["marsh-k-other"]);
}

/// Review of B-06: the VM that lands late is bare (the daemon that would have
/// written its worker marker is gone). It is ours by its recorded UUID, so the
/// Kit's next preparation must retire it and create afresh, not fail on it.
#[test]
fn a_bare_late_landing_vm_is_replaced_by_the_kits_next_preparation() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let kit = KitFixture::published("marsh-kit-fixture");
    write_map(
        &map,
        &serde_json::json!({
            "version": 2,
            "vms": {"marsh-kit-fixture": {"purpose": "kit", "key": "kit-a"}}
        }),
    );
    let model = StockModel::new();
    let restarted = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(map)
        .unwrap();
    // The restarted daemon's first inventory lacks it; then the create lands.
    assert_eq!(
        restarted.classify_vm("marsh-kit-fixture", true).unwrap(),
        VmClass::Absent
    );
    let bare = model.seed_vm("marsh-kit-fixture");

    let ready = restarted.ensure_kit_vm(&kit.spec).unwrap();
    assert!(ready.cold_started);
    let vm = model.vm("marsh-kit-fixture").unwrap();
    assert_ne!(vm.id, bare, "the bare VM was replaced");
    assert_eq!(
        vm.files["/var/lib/marsh/worker.json"],
        kit.published_marker()
    );
    assert_eq!(model.vm_names(), ["marsh-kit-fixture"]);
}

/// Review of B-06, for the shell VM: a shell VM with no marker at all is never
/// replaced (it may hold user state), so a bare late-landing one needs
/// `marsh reset`; the first open must say so, not fail "already exists" on a
/// stale listing, and the reset must remove it by its UUID.
#[test]
fn a_bare_late_landing_shell_vm_fails_closed_until_a_reset_removes_it_by_uuid() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let shell = ShellFixture::new();
    write_map(
        &map,
        &serde_json::json!({
            "version": 2,
            "vms": {shell.spec.name.clone(): {"purpose": "shell", "key": "selected"}}
        }),
    );
    let model = StockModel::new();
    let restarted = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(map)
        .unwrap();
    assert_eq!(
        restarted.classify_vm(&shell.spec.name, true).unwrap(),
        VmClass::Absent
    );
    let bare = model.seed_vm(&shell.spec.name);

    assert!(matches!(
        restarted.ensure_shell_vm(&shell.spec),
        Err(SbxError::IncompatibleVm { .. })
    ));
    assert_eq!(model.count("create"), 0);
    assert!(restarted.reset_shell_vm(&shell.spec).unwrap());
    assert!(model.vm(&shell.spec.name).is_none(), "{bare}");
    restarted.ensure_shell_vm(&shell.spec).unwrap();
}

/// Review of B-06: a reset that finds the name absent must not discard the
/// intent of a create that may still land, nor may a restart after it.
#[test]
fn a_reset_while_a_create_is_pending_keeps_its_intent_for_the_late_vm() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let kit = KitFixture::published("marsh-kit-fixture");
    write_map(
        &map,
        &serde_json::json!({
            "version": 2,
            "vms": {"marsh-kit-fixture": {"purpose": "kit", "key": "kit-a"}}
        }),
    );
    let model = StockModel::new();
    let runner = || Arc::clone(&model) as Arc<dyn CommandRunner>;
    let adapter = StockSbx::new("sbx", runner())
        .with_vm_ownership(map.clone())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    assert!(!adapter.reset_kit_vm_before(&kit.spec, deadline).unwrap());
    assert!(
        fs::read_to_string(&map)
            .unwrap()
            .contains("marsh-kit-fixture")
    );
    drop(adapter);

    let landed = model.seed_vm("marsh-kit-fixture");
    let restarted = StockSbx::new("sbx", runner())
        .with_vm_ownership(map)
        .unwrap();
    assert_eq!(
        restarted.classify_vm("marsh-kit-fixture", true).unwrap(),
        VmClass::Owned {
            uuid: landed,
            running: true
        }
    );
}

/// Audit B-11: `forget` and `record` changed memory first, so a failed write
/// left memory and disk apart until the next restart.
#[test]
fn a_failed_map_write_leaves_memory_as_it_was() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let ownership = VmOwnership::persisted(map.clone()).unwrap();
    let recorded = ownership.assign(VmPurpose::Kit, "kit-a").unwrap();
    ownership.record(&recorded, "uuid-a").unwrap();
    let intent = ownership.assign(VmPurpose::Kit, "kit-b").unwrap();
    let absent = ownership.assign(VmPurpose::Kit, "kit-c").unwrap();
    drop(ownership);
    let ownership = VmOwnership::persisted(map.clone()).unwrap();
    let on_disk = fs::read(&map).unwrap();
    let writable = |yes: bool| {
        let mode = if yes { 0o700 } else { 0o500 };
        fs::set_permissions(control.path(), fs::Permissions::from_mode(mode)).unwrap();
    };
    let view = || {
        StockInventory::decode(
            format!(
                r#"[{{"name":"{intent}","id":"11111111-1111-4111-8111-111111111111","status":"running","workspaces":[]}}]"#
            )
            .as_bytes(),
        )
    };

    writable(false);
    let forgotten = ownership.forget(&recorded);
    let adopted = ownership.record(&intent, "uuid-b");
    let reconciled = ownership.store_view(view().unwrap());
    writable(true);

    assert!(forgotten.is_err() && adopted.is_err() && reconciled.is_err());
    assert!(ownership.cached_view().is_none());
    assert_eq!(ownership.uuid(&recorded).as_deref(), Some("uuid-a"));
    assert_eq!(ownership.uuid(&intent), None);
    assert_eq!(
        ownership.lookup(VmPurpose::Kit, "kit-c").as_deref(),
        Some(absent.as_str())
    );
    assert_eq!(fs::read(&map).unwrap(), on_disk);
}

/// Audit B-11 review: the new map is published by the rename, so a failure
/// of the directory sync after it must not roll memory back to the old map.
#[test]
fn a_directory_sync_failure_after_the_rename_keeps_memory_equal_to_the_disk() {
    use crate::vm_ownership::{DIRECTORY_SYNCS, FailDirectorySync};
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let ownership = VmOwnership::persisted(map.clone()).unwrap();
    let before = DIRECTORY_SYNCS.with(std::cell::Cell::get);
    let recorded = ownership.assign(VmPurpose::Kit, "kit-a").unwrap();
    ownership.record(&recorded, "uuid-a").unwrap();
    // Every write syncs the directory after its rename.
    assert_eq!(DIRECTORY_SYNCS.with(std::cell::Cell::get), before + 2);
    let intent = ownership.assign(VmPurpose::Kit, "kit-b").unwrap();

    let fail = FailDirectorySync::in_dir(control.path());
    let forgotten = ownership.forget(&recorded);
    let adopted = ownership.record(&intent, "uuid-b");
    let fresh = ownership.assign(VmPurpose::Kit, "kit-c");
    let retired = ownership.mark_retired(&intent);
    drop(fail);

    assert!(forgotten.is_err() && adopted.is_err() && fresh.is_err() && retired.is_err());
    let reloaded = VmOwnership::persisted(map).unwrap();
    for name in [&recorded, &intent] {
        assert_eq!(ownership.uuid(name), reloaded.uuid(name), "{name}");
    }
    assert_eq!(ownership.uuid(&recorded), None);
    // After the first failure the map is not known durable, so the later
    // writes are refused before they change anything.
    assert_eq!(ownership.uuid(&intent), None);
    assert_eq!(ownership.host_names(), reloaded.host_names());
    assert_eq!(ownership.retired_names(), reloaded.retired_names());
}

/// Review of B-11: a bare relative file name has the empty parent directory.
#[test]
fn the_map_can_be_written_under_a_bare_relative_file_name() {
    let control = scratch();
    let previous = std::env::current_dir().unwrap();
    std::env::set_current_dir(control.path()).unwrap();
    let written = VmOwnership::persisted(PathBuf::from("vm-ownership.json"))
        .and_then(|ownership| ownership.assign(VmPurpose::Kit, "kit-a"));
    std::env::set_current_dir(previous).unwrap();
    written.unwrap();
    assert!(control.path().join("vm-ownership.json").is_file());
}

/// Review of B-11: a map write that was published but whose directory sync
/// failed is not durable; a retry that finds the answer in memory must not
/// hand out ownership (a name to create under) until a write succeeds.
#[test]
fn a_retry_after_a_failed_directory_sync_does_not_take_the_map_for_durable() {
    use crate::vm_ownership::FailDirectorySync;
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let ownership = VmOwnership::persisted(map.clone()).unwrap();
    let fail = FailDirectorySync::in_dir(control.path());
    assert!(ownership.assign(VmPurpose::Kit, "kit-a").is_err());
    // The intent is in memory and on disk, but not known durable: asking
    // again fails while the sync still fails, instead of answering from memory.
    assert!(ownership.assign(VmPurpose::Kit, "kit-a").is_err());
    let name = ownership.lookup(VmPurpose::Kit, "kit-a").unwrap();
    assert!(ownership.record(&name, "uuid-a").is_err());
    drop(fail);

    assert_eq!(ownership.assign(VmPurpose::Kit, "kit-a").unwrap(), name);
    ownership.record(&name, "uuid-a").unwrap();
    let reloaded = VmOwnership::persisted(map).unwrap();
    assert_eq!(reloaded.uuid(&name).as_deref(), Some("uuid-a"));
}

/// Review of B-11 (GPT's reproduction): a replacement whose restored intent
/// could not be made durable must not be created by the next preparation,
/// which finds the name absent in a listing that changes no entry.
#[test]
fn no_create_is_submitted_while_a_restored_intent_is_not_durable() {
    use crate::vm_ownership::{DIRECTORY_SYNCS, FAIL_SYNCS_FROM};
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let model = StockModel::new();
    let adapter = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(map.clone())
        .unwrap();
    let kit = KitFixture::published("marsh-kit-fixture");
    // A durably owned VM that was never set up (no marker): the next
    // preparation retires it, forgets it, restores its intent and recreates.
    adapter.ownership.assign(VmPurpose::Kit, "kit-a").unwrap();
    model.seed_vm("marsh-kit-fixture");
    adapter.ownership.invalidate();
    let owned = adapter.adopt_created("marsh-kit-fixture");
    assert!(owned.is_ok(), "{owned:?}");

    // The sync after the forget (the restore) fails, and every later one.
    let from = DIRECTORY_SYNCS.with(std::cell::Cell::get) + 1;
    FAIL_SYNCS_FROM.with(|fail| fail.set(Some(from)));
    let first = adapter.ensure_kit_vm(&kit.spec);
    let second = adapter.ensure_kit_vm(&kit.spec);
    FAIL_SYNCS_FROM.with(|fail| fail.set(None));

    assert!(first.is_err() && second.is_err(), "{first:?} {second:?}");
    assert_eq!(
        model.count("create"),
        0,
        "a create ran on an undurable intent"
    );
    // The failed attempt quarantined the name, or left it unrestored (no
    // entry: nothing is created under it); the sync recovered, still no create.
    assert!(matches!(
        adapter.ensure_kit_vm(&kit.spec),
        Err(SbxError::QuarantinedVm(_) | SbxError::StaleVmName(_))
    ));
    assert_eq!(model.count("create"), 0);
}

#[test]
fn a_marsh_vm_caught_in_a_transient_state_stays_owned_and_is_never_taken_for_stopped() {
    let ownership = VmOwnership::in_memory();
    let name = ownership.assign(VmPurpose::Kit, "kit-a").unwrap();
    let uuid = "0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9";
    ownership.record(&name, uuid).unwrap();
    let listing = |status: &str| {
        StockInventory::decode(
            format!(r#"[{{"name":"{name}","id":"{uuid}","status":"{status}"}}]"#).as_bytes(),
        )
        .unwrap()
    };
    for (status, running) in [("running", true), ("stopped", false), ("starting", true)] {
        assert_eq!(
            ownership.classify(&listing(status), &name),
            VmClass::Owned {
                uuid: uuid.into(),
                running
            },
            "{status}"
        );
    }
}

#[test]
fn ownership_mirror_holds_every_intent_before_create_and_tracks_removal() {
    let control = scratch();
    let registry = scratch();
    let map = control.path().join("vm-ownership.json");
    fs::set_permissions(registry.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mirror = registry.path().join("vm-ownership.json");
    let model = StockModel::new();
    let first = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(map.clone())
        .unwrap();
    let kept = first.vm_name(VmPurpose::Kit, "kit-a").unwrap();
    drop(first);
    // A restarted daemon given a mirror copies the existing map at once.
    let adapter = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(map.clone())
        .unwrap()
        .with_vm_ownership_mirror(mirror.clone())
        .unwrap();
    assert!(fs::read_to_string(&mirror).unwrap().contains(&kept));
    // A new intent reaches the mirror before any stock call.
    let name = adapter.vm_name(VmPurpose::Kit, "kit-b").unwrap();
    assert!(model.calls().is_empty());
    assert!(fs::read_to_string(&mirror).unwrap().contains(&name));
    let uuid = model.seed_vm(&name);
    adapter.adopt_created(&name).unwrap();
    assert!(fs::read_to_string(&mirror).unwrap().contains(&uuid));
    assert_eq!(fs::read(&mirror).unwrap(), fs::read(&map).unwrap());
    assert!(
        adapter
            .remove_owned_vm(&name, Instant::now() + Duration::from_secs(5))
            .unwrap()
    );
    assert!(!fs::read_to_string(&mirror).unwrap().contains(&name));
    assert_eq!(fs::read(&mirror).unwrap(), fs::read(&map).unwrap());
    let mode = fs::metadata(&mirror).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // A mirror in a group- or world-accessible directory is refused.
    let open = registry.path().join("open");
    fs::create_dir(&open).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
            .with_vm_ownership(map)
            .unwrap()
            .with_vm_ownership_mirror(open.join("vm-ownership.json")),
        Err(SbxError::HostGrantFence(_))
    ));
}

#[test]
fn a_malformed_inventory_row_never_makes_an_owned_vm_absent() {
    let model = StockModel::new();
    let home = tempfile::tempdir().unwrap();
    let adapter = model
        .adapter()
        .with_vm_ownership(home.path().join("vm-ownership.json"))
        .unwrap();
    let created = model.seed_vm("mine");
    adapter.adopt_created("mine").unwrap();
    model.drop_name_from_inventory("mine");
    adapter.ownership.invalidate();
    let deadline = Instant::now() + Duration::from_secs(5);
    assert!(adapter.remove_owned_vm("mine", deadline).is_err());
    assert!(adapter.classify_vm("mine", true).is_err());
    // Ownership is kept, and nothing was removed.
    assert_eq!(
        adapter.ownership.uuid("mine").as_deref(),
        Some(created.as_str())
    );
    assert_eq!(model.mutations(), 0);
}

/// Write `value` as an owner-only ownership map, as a daemon would.
fn write_map(path: &Path, value: &serde_json::Value) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(value).unwrap())
        .unwrap();
}

/// A grant as an older `marsh --dev` daemon persisted it.
fn legacy_grant(names: &serde_json::Value, uncertain: Option<bool>) -> serde_json::Value {
    let mut grant = serde_json::json!({
        "session": "session-1",
        "prefix": "marsh-xab12c-",
        "roots": ["/Users/example/marsh"],
        "scratch": "/Users/example/Library/Caches/marsh/dev/0123456789abcdef",
        "max_vms": 4,
        "revoked": true,
        "names": names,
    });
    if let Some(uncertain) = uncertain {
        grant["cleanup_uncertain"] = uncertain.into();
    }
    grant
}

/// The retired entries in the map file at `path`, and whether it still has
/// a `grants` section.
fn retired_on_disk(path: &Path) -> (Vec<String>, bool) {
    let written: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let retired = written["vms"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, entry)| entry["purpose"] == "retired")
        .map(|(name, _)| name.clone())
        .collect();
    (retired, written.get("grants").is_some())
}

/// `marsh --dev` was removed. A map an older daemon left with development
/// grants (every historical field, `cleanup_uncertain` present or not, and
/// one it never had) and a dev shell VM still loads. Loading alone, with no
/// mirror (as every installed daemon runs), rewrites the map at once with
/// what `--dev` left retired; a mirror added later gets the same. The
/// retired-VM pass removes it by recorded UUID. A child name now held by
/// another VM is forgotten and that VM is never named in any stock call; one
/// whose VM is gone is forgotten; the ordinary shell stays.
#[test]
fn an_older_maps_dev_grants_and_dev_shell_are_retired_and_removed_by_uuid() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let mirror_dir = control.path().join("mirror");
    fs::create_dir(&mirror_dir).unwrap();
    fs::set_permissions(&mirror_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let mirror = mirror_dir.join("vm-ownership.json");
    let model = StockModel::new();
    let shell = model.seed_vm("marsh-s-shell001");
    let dev_shell = model.seed_vm("marsh-s-devshl01");
    let child = model.seed_vm("marsh-xab12c-k-child001");
    model.seed_vm("marsh-xab12c-k-intent01");
    model.seed_vm("marsh-xab12c-s-replaced");
    let mut uncertain = legacy_grant(
        &serde_json::json!({
            "marsh-xab12c-s-replaced": FOREIGN,
            "marsh-xab12c-k-gone0001": "22222222-2222-4222-8222-222222222222",
        }),
        Some(true),
    );
    uncertain["depth"] = 2.into();
    write_map(
        &map,
        &serde_json::json!({
            "version": 2,
            "vms": {
                "marsh-s-shell001": {"purpose": "shell", "key": "shell", "uuid": shell},
                "marsh-s-devshl01": {"purpose": "shell", "key": "dev", "uuid": dev_shell},
            },
            "grants": {
                "grant-a": legacy_grant(
                    &serde_json::json!({
                        "marsh-xab12c-k-child001": child,
                        "marsh-xab12c-k-intent01": null,
                    }),
                    None,
                ),
                "grant-b": uncertain,
            },
        }),
    );

    let retired = [
        "marsh-s-devshl01",
        "marsh-xab12c-k-child001",
        "marsh-xab12c-k-gone0001",
        "marsh-xab12c-k-intent01",
        "marsh-xab12c-s-replaced",
    ];
    // The load itself saves, before anything else uses the map.
    drop(VmOwnership::persisted(map.clone()).unwrap());
    assert_eq!(
        retired_on_disk(&map),
        (retired.map(String::from).to_vec(), false)
    );

    let adapter = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(map.clone())
        .unwrap()
        .with_vm_ownership_mirror(mirror.clone())
        .unwrap();
    assert_eq!(
        retired_on_disk(&mirror),
        (retired.map(String::from).to_vec(), false)
    );
    assert_eq!(model.mutations(), 0, "loading touches no VM");

    let (removed, failed) = adapter.remove_retired_kit_vms();
    assert!(failed.is_empty(), "{failed:?}");
    assert_eq!(removed, retired);
    assert_eq!(
        model.vm_names(),
        ["marsh-s-shell001", "marsh-xab12c-s-replaced"]
    );
    let named: Vec<_> = model
        .calls()
        .into_iter()
        .filter(|call| {
            call.args
                .iter()
                .any(|arg| arg.contains("marsh-xab12c-s-replaced"))
        })
        .map(|call| call.args)
        .collect();
    assert!(named.is_empty(), "the other VM was named: {named:?}");
    let (removed, failed) = adapter.remove_retired_kit_vms();
    assert!(
        removed.is_empty() && failed.is_empty(),
        "{removed:?} {failed:?}"
    );
    let reloaded = VmOwnership::persisted(map).unwrap();
    assert_eq!(
        reloaded.host_names().into_iter().collect::<Vec<_>>(),
        ["marsh-s-shell001"]
    );
    assert_eq!(reloaded.uuid("marsh-s-shell001"), Some(shell));
}

/// A retired name held by another UUID is forgotten only when the same
/// listing has no VM with the recorded UUID. If the recorded UUID is still
/// listed (under another name), the record and the failure stay, and neither
/// VM is named in a stock call.
#[test]
fn a_retired_name_held_by_another_vm_keeps_a_recorded_uuid_that_is_still_listed() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let model = StockModel::new();
    let ours = model.seed_vm("marsh-k-renamed1");
    model.seed_vm("marsh-k-retired1");
    write_map(
        &map,
        &serde_json::json!({
            "version": 2,
            "vms": {"marsh-k-retired1": {"purpose": "retired", "key": "fixture", "uuid": ours}},
        }),
    );
    let adapter = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(map.clone())
        .unwrap();

    let (removed, failed) = adapter.remove_retired_kit_vms();
    assert!(removed.is_empty(), "{removed:?}");
    assert!(
        matches!(failed.as_slice(), [(name, SbxError::ForeignVm(_))] if name == "marsh-k-retired1"),
        "{failed:?}"
    );
    let named: Vec<_> = model
        .calls()
        .into_iter()
        .filter(|call| call.args.iter().any(|arg| arg.starts_with("marsh-k-re")))
        .map(|call| call.args)
        .collect();
    assert!(named.is_empty(), "a VM was named: {named:?}");
    assert_eq!(model.vm_names(), ["marsh-k-renamed1", "marsh-k-retired1"]);
    let reloaded = VmOwnership::persisted(map).unwrap();
    assert_eq!(reloaded.uuid("marsh-k-retired1"), Some(ours));
    assert!(reloaded.is_retired("marsh-k-retired1"));
}

/// A grant whose only names are already host entries still counts as
/// something `marsh --dev` left: the load drops `grants` from the map at
/// once, with no mirror, and the host entry keeps its purpose, key and UUID.
#[test]
fn a_grant_name_that_is_a_host_entry_keeps_the_host_entry() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    write_map(
        &map,
        &serde_json::json!({
            "version": 2,
            "vms": {
                "marsh-k-fixture1": {"purpose": "kit", "key": "fixture", "uuid": FOREIGN},
            },
            "grants": {
                "grant-a": legacy_grant(&serde_json::json!({"marsh-k-fixture1": null}), None),
            },
        }),
    );
    let loaded = VmOwnership::persisted(map.clone()).unwrap();
    assert_eq!(retired_on_disk(&map), (Vec::new(), false));
    assert!(!loaded.is_retired("marsh-k-fixture1"));
    assert_eq!(loaded.uuid("marsh-k-fixture1").as_deref(), Some(FOREIGN));
    assert_eq!(
        loaded.lookup(VmPurpose::Kit, "fixture").as_deref(),
        Some("marsh-k-fixture1")
    );
}

/// A map with nothing `marsh --dev` left loads without being rewritten.
#[test]
fn a_map_without_dev_grants_is_not_rewritten_at_load() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    write_map(
        &map,
        &serde_json::json!({
            "version": 2,
            "vms": {
                "marsh-s-shell001": {"purpose": "shell", "key": "shell", "uuid": FOREIGN},
                "marsh-k-intent01": {"purpose": "kit", "key": "fixture"},
            },
        }),
    );
    let before = (fs::read(&map).unwrap(), fs::metadata(&map).unwrap().ino());
    let loaded = VmOwnership::persisted(map.clone()).unwrap();
    // Every write replaces the file, so the same inode means none happened.
    assert_eq!(
        (fs::read(&map).unwrap(), fs::metadata(&map).unwrap().ino()),
        before
    );
    assert_eq!(loaded.uuid("marsh-s-shell001").as_deref(), Some(FOREIGN));
    assert!(!loaded.is_retired("marsh-k-intent01"));
}

fn install(attempt: &str, command: &str) -> crate::InstallRecord {
    crate::InstallRecord {
        attempt: attempt.into(),
        command: command.into(),
    }
}

/// `KitInstall.tla` rule 6 (`recordsInMemory`): install records are persisted with
/// the entry they name, so a restarted daemon still reaches a failed
/// install's VM by the install's name; the schema is 3 only while a record
/// exists, and a version 2 map still loads.
#[test]
fn install_records_are_persisted_with_their_entry_and_survive_a_restart() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let ownership = VmOwnership::persisted(map.clone()).unwrap();
    let name = ownership.assign(VmPurpose::Kit, "kit-a").unwrap();
    let version = || {
        serde_json::from_slice::<serde_json::Value>(&fs::read(&map).unwrap()).unwrap()["version"]
            .as_u64()
            .unwrap()
    };
    assert_eq!(version(), 2);
    ownership.begin_install(&name, install("a1", "hf")).unwrap();
    ownership.begin_install(&name, install("a2", "hf")).unwrap();
    assert_eq!(version(), 3);

    let restarted = VmOwnership::persisted(map.clone()).unwrap();
    assert_eq!(
        restarted.install_records(),
        [
            (name.clone(), "kit-a".into(), install("a1", "hf")),
            (name.clone(), "kit-a".into(), install("a2", "hf")),
        ]
    );
    // Ended by attempt id only: a2 stays.
    assert!(restarted.end_install("a1").unwrap());
    assert!(!restarted.end_install("a1").unwrap());
    assert_eq!(
        VmOwnership::persisted(map.clone())
            .unwrap()
            .install_records(),
        [(name.clone(), "kit-a".into(), install("a2", "hf"))]
    );
    restarted.end_install("a2").unwrap();
    assert_eq!(
        version(),
        2,
        "a map with no record is readable by an older marsh"
    );
}

/// `KitInstall.tla` rules 5 and 6: forgetting a removed VM's name ends the records
/// naming it in the same write; an intent (a create that may still land) is
/// never forgotten, and neither are its records. A record is only written
/// under a live entry.
#[test]
fn install_records_end_with_their_retired_name_and_stay_with_an_intent() {
    let control = scratch();
    let map = control.path().join("vm-ownership.json");
    let ownership = VmOwnership::persisted(map.clone()).unwrap();
    let intent = ownership.assign(VmPurpose::Kit, "kit-a").unwrap();
    let recorded = ownership.assign(VmPurpose::Kit, "kit-b").unwrap();
    ownership
        .begin_install(&intent, install("a1", "hf"))
        .unwrap();
    ownership
        .begin_install(&recorded, install("a2", "hf"))
        .unwrap();
    ownership.record(&recorded, FOREIGN).unwrap();

    ownership.forget(&intent).unwrap();
    ownership.forget(&recorded).unwrap();
    let restarted = VmOwnership::persisted(map).unwrap();
    assert_eq!(
        restarted.install_records(),
        [(intent.clone(), "kit-a".into(), install("a1", "hf"))]
    );
    assert!(restarted.is_live(&intent));
    assert!(matches!(
        ownership.begin_install(&recorded, install("a3", "hf")),
        Err(SbxError::StaleVmName(_))
    ));
}

/// `KitInstall.tla` rule 4 (create-time check): a create is never submitted under
/// a name that is not a live entry of the map: not under one forgotten after
/// it was chosen, and (persisted map) not under one the map never gave out.
#[test]
fn no_create_is_submitted_under_a_name_that_is_not_a_live_entry() {
    let control = scratch();
    let model = StockModel::new();
    let adapter = StockSbx::new("sbx", Arc::clone(&model) as Arc<dyn CommandRunner>)
        .with_vm_ownership(control.path().join("vm-ownership.json"))
        .unwrap();
    let mut kit = KitFixture::published("marsh-k-unknown1");
    assert!(matches!(
        adapter.ensure_kit_vm(&kit.spec),
        Err(SbxError::StaleVmName(name)) if name == "marsh-k-unknown1"
    ));
    kit.spec.name = adapter.vm_name(VmPurpose::Kit, "kit-a").unwrap();
    adapter.ownership.record(&kit.spec.name, FOREIGN).unwrap();
    adapter.ownership.forget(&kit.spec.name).unwrap();
    assert!(matches!(
        adapter.ensure_kit_vm(&kit.spec),
        Err(SbxError::StaleVmName(_))
    ));
    assert!(
        adapter.quarantined_vms().is_empty(),
        "nothing was submitted"
    );

    // The in-memory map refuses the name it forgot as well.
    let memory = model.adapter();
    let mut kit = KitFixture::published("marsh-k-memory01");
    kit.spec.name = memory.vm_name(VmPurpose::Kit, "kit-a").unwrap();
    memory.ownership.record(&kit.spec.name, FOREIGN).unwrap();
    memory.ownership.forget(&kit.spec.name).unwrap();
    assert!(matches!(
        memory.ensure_kit_vm(&kit.spec),
        Err(SbxError::StaleVmName(_))
    ));
    assert_eq!(model.count("create"), 0);
}
