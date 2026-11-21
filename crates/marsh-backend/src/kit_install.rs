//! `marsh kit install` records and `marsh workers reset NAME|all`: the design
//! `docs/model/KitInstall.tla` proves (issue #194).
//!
//! An install attempt persists a record (attempt id, command) for the Kit
//! VM name it chose (next to the ownership map, which stays schema 2), under
//! the Kit lock and before its create; the record ends when the command is
//! published, when the attempt is stopped before its create, or with the
//! name when its VM is retired. A failed create, however it failed, keeps its
//! intent and its record: the VM may still land, and the record is how
//! `workers reset NAME` reaches it, also after a restart.
//!
//! A reset finds its Kits without assigning a name, takes their Kit locks in
//! key order, plans again under the locks (and starts over when the plan
//! needs a lock it does not hold), then removes each target VM by its
//! recorded UUID. A target under which nothing is listed keeps its intent
//! and records: its create may still land.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

use marsh_daemon::{DaemonError, DaemonStore, LoadSelection};
use marsh_sbx::{InstallRecord, VmPurpose};

use super::{StockDaemonBackend, backend_error};

/// How many times a reset plans again because its Kits changed while it
/// waited for their locks.
const RESET_PLAN_ROUNDS: usize = 4;

/// One install attempt that has not published its command: running while
/// this guard lives. Dropping it settles the attempt (its persisted record
/// stays); [`InstallAttempt::published`] ends the record.
pub(super) struct InstallAttempt<'a> {
    backend: &'a StockDaemonBackend,
    record: InstallRecord,
}

impl InstallAttempt<'_> {
    pub(super) const fn record(&self) -> &InstallRecord {
        &self.record
    }

    /// The command is registered on the VM `vm`: the attempt's record ends,
    /// and so does every earlier record of the command under that name (the
    /// registry reaches that VM now: `KitInstall.tla` `InstPublish`).
    pub(super) fn published(self, vm: &str) -> Result<(), DaemonError> {
        self.backend
            .sbx
            .end_install_record(&self.record.attempt)
            .map_err(backend_error)?;
        self.backend
            .sbx
            .end_install_records_of(vm, &self.record.command)
            .map(drop)
            .map_err(backend_error)
    }

    /// The attempt was stopped before it submitted any create (`marsh stop
    /// --force`): it made nothing to reach, so its record ends
    /// (`KitInstall.tla` `InstAbort`). A create of an earlier attempt under
    /// the same name keeps that attempt's record.
    pub(super) fn abandoned(self) -> Result<(), DaemonError> {
        self.backend
            .sbx
            .end_install_record(&self.record.attempt)
            .map(drop)
            .map_err(backend_error)
    }
}

impl Drop for InstallAttempt<'_> {
    fn drop(&mut self) {
        self.backend
            .running_installs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.record.attempt);
    }
}

/// Every Kit lock of `locks` (in their key order) without waiting, or the
/// index of one held elsewhere (and none held).
fn try_lock_in_order(locks: &[Arc<Mutex<()>>]) -> Result<Vec<MutexGuard<'_, ()>>, usize> {
    let mut guards = Vec::with_capacity(locks.len());
    for (index, lock) in locks.iter().enumerate() {
        match lock.try_lock() {
            Ok(guard) => guards.push(guard),
            Err(std::sync::TryLockError::Poisoned(error)) => guards.push(error.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => return Err(index),
        }
    }
    Ok(guards)
}

/// How long a reset waits for Kit locks held elsewhere, in milliseconds (the
/// client's own wait for a busy daemon is as long).
pub(super) const RESET_LOCK_WAIT_MS: u64 = 30_000;

/// What a reset removes, planned under the Kit locks of `keys`.
#[derive(Debug, Default)]
struct ResetPlan {
    /// The ownership keys whose Kit locks the plan needs.
    keys: BTreeSet<String>,
    /// VM name -> ownership key.
    targets: BTreeMap<String, String>,
    /// What the reply names.
    selected: Vec<String>,
}

impl StockDaemonBackend {
    /// A new install attempt of `command` from the Kit of ownership key
    /// `owner`, running until the guard drops ([`InstallRecord::new_attempt`]:
    /// its id is never reused). It is running from before it takes its Kit
    /// lock, so a reset never waits behind it, record or not.
    pub(super) fn begin_install_attempt(&self, command: &str, owner: &str) -> InstallAttempt<'_> {
        let record = InstallRecord::new_attempt(command);
        self.running_installs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                record.attempt.clone(),
                (command.to_owned(), owner.to_owned()),
            );
        InstallAttempt {
            backend: self,
            record,
        }
    }

    /// The running install attempts as `(command, ownership key)`.
    fn running_attempts(&self) -> Vec<(String, String)> {
        self.running_installs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// The commands whose install records name `vm`, for `marsh status`.
    pub(super) fn install_names_for_vm(&self, vm: &str) -> Vec<String> {
        let mut names = self
            .sbx
            .install_records()
            .into_iter()
            .filter(|(name, _, _)| name == vm)
            .map(|(_, _, record)| record.command)
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        names
    }

    /// `marsh workers reset NAME|all` of local Kit VMs.
    pub(super) fn reset_kit_vms(
        &self,
        selection: &LoadSelection,
        store: &DaemonStore,
    ) -> Result<Vec<String>, DaemonError> {
        let wait = std::time::Duration::from_millis(
            self.reset_lock_wait
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        let deadline = std::time::Instant::now() + wait;
        for _ in 0..RESET_PLAN_ROUNDS {
            // The candidate Kits, found without assigning a name.
            let keys = self.plan_reset(selection)?.keys;
            #[cfg(test)]
            if let Some(hook) = self
                .reset_before_locks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                hook();
            }
            let locks = self.kit_locks_in_order(&keys)?;
            // Never wait blocked on a Kit lock: an install that started on
            // one of these Kits since the plan holds it for its whole create.
            // While a lock is held, plan again: that refuses (NAME) or skips
            // (all) such an install, and any other change starts over.
            // The wait is bounded: a lock held all along (a long job
            // preparation, a Kit change) refuses, naming its Kit.
            let guards = loop {
                let busy = match try_lock_in_order(&locks) {
                    Ok(guards) => break Some(guards),
                    Err(busy) => busy,
                };
                if self.plan_reset(selection)?.keys != keys {
                    break None;
                }
                if std::time::Instant::now() >= deadline {
                    let kit = keys.iter().nth(busy).cloned().unwrap_or_default();
                    return Err(DaemonError::InvalidState(format!(
                        "the reset waited {} s for Kit {kit}, which a job's preparation, a recovery, a Kit change or garbage collection kept busy; nothing was removed, try again",
                        wait.as_secs()
                    )));
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            let Some(_guards) = guards else {
                continue;
            };
            // Nothing planned before the locks is used after them.
            let plan = self.plan_reset(selection)?;
            if !plan.keys.is_subset(&keys) {
                continue;
            }
            // A name whose create was submitted (an install recorded it, or a
            // failed create quarantined it) and under which nothing is listed
            // is reported: its create may still land. A mere intent is not.
            let mut submitted = self
                .sbx
                .quarantined_vms()
                .into_keys()
                .collect::<BTreeSet<_>>();
            submitted.extend(
                self.sbx
                    .install_records()
                    .into_iter()
                    .map(|(name, _, _)| name),
            );
            let mut reply = plan.selected;
            let may_land = if matches!(selection, LoadSelection::All) {
                // One target at a time: a busy one is skipped and reported,
                // never retired, and the others still go.
                let mut may_land = Vec::new();
                for (name, owner) in &plan.targets {
                    // The claim itself refuses a VM with an unfinished job
                    // or one whose cleanup is not verified (in one step under
                    // the store lock), quarantined or not.
                    let retired = Self::claim_settled_retirement(store, vec![name.clone()])
                        .and_then(|claim| {
                            self.retire_claimed_named(
                                store,
                                &BTreeMap::from([(name.clone(), owner.clone())]),
                                &claim,
                            )
                        });
                    match retired {
                        Ok(names) => may_land.extend(names),
                        Err(error) => reply.push(format!("{name}: skipped: {error}")),
                    }
                }
                may_land
            } else {
                let claim = Self::claim_retirement(store, plan.targets.keys().cloned().collect())?;
                self.retire_claimed_named(store, &plan.targets, &claim)?
            };
            reply.extend(may_land.into_iter().filter(|vm| submitted.contains(vm)).map(|vm| {
                format!("{vm}: nothing is listed under it yet; its VM create may still land, and a later reset removes it")
            }));
            return Ok(reply);
        }
        Err(DaemonError::InvalidState(
            "the Kit VMs to reset kept changing while the reset waited for them; nothing was removed, try again".into(),
        ))
    }

    /// What a reset of `selection` removes now (`KitInstall.tla`, rule 7):
    /// - `NAME`: the VM the ownership map records for its registered Kit (a
    ///   lookup, never an assignment) and the VM of every install record of
    ///   `NAME`; a name with neither is not found, and a running install of it
    ///   refuses;
    /// - `all`: every live Kit entry of the map, every recorded install VM
    ///   and the registered Kits' VMs, skipping the Kits of running installs.
    fn plan_reset(&self, selection: &LoadSelection) -> Result<ResetPlan, DaemonError> {
        let records = self.sbx.install_records();
        let registered = self.command_names();
        let running = self.running_attempts();
        let mut plan = ResetPlan::default();
        let add_registered = |plan: &mut ResetPlan, command: &str| -> Result<(), DaemonError> {
            let workload = self
                .registered_kit(command)?
                .workload
                .capture_generation()
                .map_err(backend_error)?;
            let owner = workload.identity().to_owned();
            if let Some(name) = self.sbx.recorded_vm_name(VmPurpose::Kit, &owner) {
                plan.targets.insert(name, owner.clone());
            }
            plan.keys.insert(owner);
            Ok(())
        };
        match selection {
            LoadSelection::Kits(commands) => {
                let mut commands = commands.clone();
                commands.sort();
                commands.dedup();
                if commands.is_empty() {
                    return Err(DaemonError::InvalidState(
                        "worker reset selection cannot be empty".into(),
                    ));
                }
                for command in commands {
                    let mut found = false;
                    if registered.contains(&command) {
                        add_registered(&mut plan, &command)?;
                        found = true;
                    }
                    for (name, owner, record) in &records {
                        if record.command != command {
                            continue;
                        }
                        plan.targets.insert(name.clone(), owner.clone());
                        plan.keys.insert(owner.clone());
                        found = true;
                    }
                    if !found {
                        return Err(DaemonError::NotFound(command));
                    }
                    // With every Kit NAME's targets need (its registered Kit's
                    // and its records'): an install on any of them refuses.
                    if let Some((other, _)) = running
                        .iter()
                        .find(|(other, owner)| *other == command || plan.keys.contains(owner))
                    {
                        return Err(DaemonError::InvalidState(format!(
                            "`marsh kit install {other}` is still running{}; nothing was removed (`marsh stop --force` cancels it)",
                            if *other == command {
                                String::new()
                            } else {
                                format!(" on {command}'s Kit")
                            }
                        )));
                    }
                    plan.selected.push(command);
                }
            }
            LoadSelection::All => {
                for command in &registered {
                    add_registered(&mut plan, command)?;
                }
                plan.targets.extend(self.sbx.live_kit_entries());
                plan.targets.extend(
                    records
                        .iter()
                        .map(|(name, owner, _)| (name.clone(), owner.clone())),
                );
                // A running install holds its Kit lock until it publishes,
                // and a live ephemeral-home session's VMs are its own: their
                // Kits are skipped, not waited for.
                let mut busy = running
                    .iter()
                    .map(|(_, owner)| owner.clone())
                    .collect::<BTreeSet<_>>();
                busy.extend(self.live_ephemeral_keys());
                plan.targets.retain(|_, owner| !busy.contains(owner));
                plan.keys.retain(|owner| !busy.contains(owner));
                plan.keys.extend(plan.targets.values().cloned());
                if registered.is_empty() && plan.targets.is_empty() && running.is_empty() {
                    return Err(DaemonError::InvalidState(
                        "worker reset selection cannot be empty".into(),
                    ));
                }
                plan.selected = registered;
                plan.selected.extend(running.iter().map(|(command, _)| {
                    format!("{command}: its `marsh kit install` is still running; skipped")
                }));
            }
        }
        Ok(plan)
    }
}

/// Each test reproduces one race of a `KitInstall.tla` negative control with
/// a scripted stock SBX, and names the rule whose removal makes it fail.
#[cfg(test)]
mod tests {
    use crate::{
        RegisteredKit, StockDaemonBackend,
        tests::{backend_with_stock, test_stock},
    };
    use marsh_daemon::{DaemonBackend, DaemonError, DaemonStore, LoadSelection};
    use marsh_runtime::{Attachment, CommandOutput, CommandRunner, Invocation};
    use std::{
        collections::{BTreeMap, VecDeque},
        io,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::{Arc, Mutex, atomic::AtomicU64},
        time::Duration,
    };

    /// What one `sbx create` does.
    #[derive(Clone, Copy, Debug)]
    pub(super) enum Create {
        /// No reply in time; nothing lands.
        TimedOut,
        /// No reply in time; it lands when the test calls `land_pending`.
        TimedOutLandsLater,
        /// Reported failed with the VM listed.
        FailedListed,
        /// Reported failed with nothing listed, and nothing ever lands.
        FailedNone,
        /// Reported failed with nothing listed, but it lands later.
        FailedLandsLater,
        /// Hangs until creates are cancelled (`marsh stop --force`); the VM
        /// lands later anyway.
        HangsUntilCancelled,
    }

    type Hook = Box<dyn FnOnce() + Send>;

    /// Stock SBX as a name -> VM table: a create is atomic on its name, and
    /// a name that is taken or still being created is refused.
    #[derive(Default)]
    pub(super) struct Stock {
        vms: Mutex<BTreeMap<String, String>>,
        pending: Mutex<Vec<String>>,
        outcomes: Mutex<VecDeque<Create>>,
        created: Mutex<Vec<String>>,
        removed: Mutex<Vec<String>>,
        before_create: Mutex<Option<Hook>>,
        before_list: Mutex<Option<Hook>>,
        after_list_snapshot: Mutex<Option<Hook>>,
        next_id: AtomicU64,
        hanging: std::sync::atomic::AtomicBool,
        stopped: Mutex<std::collections::BTreeSet<String>>,
        review_registry_image: Mutex<Option<String>>,
    }

    #[allow(clippy::unnecessary_wraps)] // A stock call's reply.
    fn output(code: i32, stderr: &str) -> io::Result<CommandOutput> {
        Ok(CommandOutput {
            exit_code: Some(code),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    const NONE: [String; 0] = [];

    impl Stock {
        pub(super) fn script(&self, outcomes: &[Create]) {
            self.outcomes.lock().unwrap().extend(outcomes);
        }

        pub(super) fn before_create(&self, hook: impl FnOnce() + Send + 'static) {
            *self.before_create.lock().unwrap() = Some(Box::new(hook));
        }

        /// Run `hook` at the start of the next `sbx ls`.
        pub(super) fn before_list(&self, hook: impl FnOnce() + Send + 'static) {
            *self.before_list.lock().unwrap() = Some(Box::new(hook));
        }

        fn land(&self, name: &str) {
            let id = self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.vms.lock().unwrap().insert(
                name.to_owned(),
                format!("00000000-0000-4000-8000-{id:012x}"),
            );
        }

        /// Every create still in flight lands now.
        pub(super) fn land_pending(&self) {
            for name in std::mem::take(&mut *self.pending.lock().unwrap()) {
                self.land(&name);
            }
        }

        /// A VM appears under `name` (one the daemon's map names).
        pub(super) fn seed(&self, name: &str) {
            self.land(name);
        }

        /// Someone else's VM replaces the one listed under `name` (a new id).
        pub(super) fn replace(&self, name: &str) {
            self.land(name);
        }

        /// A stopped VM appears under `name`.
        pub(super) fn seed_stopped(&self, name: &str) {
            self.stopped.lock().unwrap().insert(name.to_owned());
            self.land(name);
        }

        pub(super) fn listed(&self) -> Vec<String> {
            self.vms.lock().unwrap().keys().cloned().collect()
        }

        pub(super) fn created(&self) -> Vec<String> {
            self.created.lock().unwrap().clone()
        }

        pub(super) fn removed(&self) -> Vec<String> {
            self.removed.lock().unwrap().clone()
        }
    }

    impl CommandRunner for Stock {
        fn run(&self, invocation: &Invocation) -> io::Result<CommandOutput> {
            self.run_bounded(invocation, Duration::from_secs(1))
        }

        #[allow(clippy::too_many_lines)] // One scripted stock CLI.
        fn run_bounded(&self, invocation: &Invocation, _: Duration) -> io::Result<CommandOutput> {
            let arguments = invocation
                .arguments
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            if let Some(image) = self.review_registry_image.lock().unwrap().as_ref() {
                let reply = if invocation.program == std::ffi::OsStr::new("docker") {
                    let day = if arguments.iter().any(|arg| arg == image) {
                        "02"
                    } else {
                        "01"
                    };
                    Some(format!(
                        r#"{{"config":{{"Labels":{{"org.marsh.kit.contract":"1"}}}},"created":"2026-01-{day}T00:00:00Z"}}"#
                    ))
                } else if arguments.first().is_some_and(|arg| arg == "kit") {
                    Some(format!(r#"{{"sandbox":{{"image":"{image}"}}}}"#))
                } else {
                    None
                };
                if let Some(reply) = reply {
                    return Ok(CommandOutput {
                        exit_code: Some(0),
                        stdout: reply.into_bytes(),
                        stderr: vec![],
                    });
                }
            }
            match arguments.first().map(String::as_str) {
                Some("ls") => {
                    let hook = self.before_list.lock().unwrap().take();
                    if let Some(hook) = hook {
                        hook();
                    }
                    let rows = self
                        .vms
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|(name, id)| {
                            let status = if self.stopped.lock().unwrap().contains(name) {
                                "stopped"
                            } else {
                                "running"
                            };
                            format!(r#"{{"name":"{name}","id":"{id}","status":"{status}"}}"#)
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    let after = self.after_list_snapshot.lock().unwrap().take();
                    if let Some(hook) = after {
                        hook();
                    }
                    Ok(CommandOutput {
                        exit_code: Some(0),
                        stdout: format!(r#"{{"sandboxes":[{rows}]}}"#).into_bytes(),
                        stderr: Vec::new(),
                    })
                }
                Some("create") => {
                    let hook = self.before_create.lock().unwrap().take();
                    if let Some(hook) = hook {
                        hook();
                    }
                    let name = arguments
                        .iter()
                        .position(|argument| argument == "--name")
                        .map(|index| arguments[index + 1].clone())
                        .unwrap();
                    if self.vms.lock().unwrap().contains_key(&name)
                        || self.pending.lock().unwrap().contains(&name)
                    {
                        return output(1, "sandbox name already in use");
                    }
                    self.created.lock().unwrap().push(name.clone());
                    let outcome = self
                        .outcomes
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or(Create::TimedOut);
                    match outcome {
                        Create::TimedOut => Err(io::Error::new(io::ErrorKind::TimedOut, "hung")),
                        Create::TimedOutLandsLater => {
                            self.pending.lock().unwrap().push(name);
                            Err(io::Error::new(io::ErrorKind::TimedOut, "hung"))
                        }
                        Create::FailedListed => {
                            self.land(&name);
                            output(1, "create failed")
                        }
                        Create::FailedNone => output(1, "create failed"),
                        Create::FailedLandsLater => {
                            self.pending.lock().unwrap().push(name);
                            output(1, "create failed")
                        }
                        Create::HangsUntilCancelled => {
                            panic!("a hanging create must run cancellable")
                        }
                    }
                }
                Some("rm") => {
                    let name = arguments.last().unwrap().clone();
                    self.vms.lock().unwrap().remove(&name);
                    self.removed.lock().unwrap().push(name);
                    output(0, "")
                }
                Some("stop") => output(0, ""),
                Some("exec") if arguments.iter().any(|argument| argument == "ps") => output(0, ""),
                _ => Err(io::Error::other(format!(
                    "unexpected stock call {arguments:?}"
                ))),
            }
        }

        fn run_bounded_cancellable(
            &self,
            invocation: &Invocation,
            timeout: Duration,
            cancel: &marsh_runtime::Cancellation,
        ) -> io::Result<CommandOutput> {
            let hangs = matches!(
                self.outcomes.lock().unwrap().front(),
                Some(Create::HangsUntilCancelled)
            ) && invocation
                .arguments
                .first()
                .is_some_and(|verb| verb == "create");
            if !hangs {
                return self.run_bounded(invocation, timeout);
            }
            self.outcomes.lock().unwrap().pop_front();
            let arguments = invocation
                .arguments
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            let name = arguments
                .iter()
                .position(|argument| argument == "--name")
                .map(|index| arguments[index + 1].clone())
                .unwrap();
            self.created.lock().unwrap().push(name.clone());
            self.hanging
                .store(true, std::sync::atomic::Ordering::Release);
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while !cancel.is_cancelled() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the create was never cancelled"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            self.pending.lock().unwrap().push(name);
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "owned I/O cancelled",
            ))
        }

        fn spawn_attached(&self, _: &Invocation) -> io::Result<Attachment> {
            Err(io::Error::other("unexpected attachment"))
        }
    }

    pub(super) fn reference(digit: char) -> String {
        format!("example/hf@sha256:{}", digit.to_string().repeat(64))
    }

    /// A daemon over [`Stock`], with a persisted ownership map.
    pub(super) struct Lab {
        pub(super) home: tempfile::TempDir,
        pub(super) stock: Arc<Stock>,
        pub(super) backend: Arc<StockDaemonBackend>,
        store: Option<DaemonStore>,
    }

    impl Lab {
        pub(super) fn new() -> Self {
            let home =
                tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
            for artifact in [
                "worker",
                "relay",
                "shell",
                "marsh-byte-exec-linux-arm64",
                "marsh-local-linux-arm64",
            ] {
                let path = home.path().join(artifact);
                std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let control = home.path().join("control");
            std::fs::create_dir(&control).unwrap();
            std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700)).unwrap();
            let stock = Arc::new(Stock::default());
            let backend = Self::daemon(home.path(), &stock);
            let store = Some(DaemonStore::new(home.path()));
            Self {
                home,
                stock,
                backend,
                store,
            }
        }

        pub(super) fn store(&self) -> &DaemonStore {
            self.store.as_ref().unwrap()
        }

        fn daemon(home: &std::path::Path, stock: &Arc<Stock>) -> Arc<StockDaemonBackend> {
            let map: PathBuf = home.join("control/vm-ownership.json");
            Arc::new(backend_with_stock(
                home,
                BTreeMap::new(),
                test_stock(stock.clone())
                    .with_vm_ownership(map)
                    .unwrap()
                    .with_ephemeral_root_for_test(home.join("ephemeral-pool")),
            ))
        }

        /// A daemon restart: memory (quarantines, running attempts, the
        /// forgotten names) is lost; the ownership map and its install
        /// records are read again. Creates already submitted go on.
        pub(super) fn restart(&mut self) {
            self.backend = Self::daemon(self.home.path(), &self.stock);
            // The store's journal lock is the daemon's: the old one goes first.
            self.store = None;
            self.store = Some(DaemonStore::new(self.home.path()));
        }

        pub(super) fn install(
            &self,
            command: &str,
            reference: &str,
        ) -> Result<String, DaemonError> {
            self.backend
                .install_command(command.into(), reference.into(), Some(self.store()))
        }

        pub(super) fn reset(&self, names: &[&str]) -> Result<Vec<String>, DaemonError> {
            let selection = if names.is_empty() {
                LoadSelection::All
            } else {
                LoadSelection::Kits(names.iter().map(|name| (*name).to_owned()).collect())
            };
            self.backend.reset_workers(&selection, self.store().clone())
        }

        pub(super) fn register(&self, command: &str, reference: &str) {
            self.backend.installed_commands.lock().unwrap().insert(
                command.into(),
                RegisteredKit {
                    workload: marsh_sbx::NativeKitRef::immutable_oci(reference).unwrap(),
                },
            );
        }

        /// `EveryDaemonVMOwned`: every listed VM is a live entry of the map.
        pub(super) fn assert_every_vm_owned(&self) {
            for vm in self.stock.listed() {
                assert!(
                    self.backend.sbx.is_live_vm_name(&vm),
                    "{vm} is listed but the ownership map does not own it: foreign forever"
                );
            }
        }

        pub(super) fn records(&self) -> Vec<String> {
            self.backend
                .sbx
                .install_records()
                .into_iter()
                .map(|(name, _, record)| format!("{name} {}", record.command))
                .collect()
        }
    }

    #[test]
    fn review_v2b_reset_all_skips_unverified_job_cleanup_and_makes_progress() {
        reset_with_a_quarantined_job(true, false);
    }

    #[test]
    fn review_v2b_reset_all_skips_running_job_and_makes_progress() {
        reset_with_a_quarantined_job(false, false);
    }

    #[test]
    fn review_v2c_reset_name_must_not_retire_a_quarantined_running_job() {
        reset_with_a_quarantined_job(false, true);
    }

    #[test]
    fn review_v2c_reset_name_releases_terminal_uncertain_cleanup_by_design() {
        reset_with_a_quarantined_job(true, true);
    }

    #[test]
    fn review_v2c_real_auto_update_pass_cancellation_keeps_late_vm_resettable() {
        let mut lab = Lab::new();
        lab.register("hf", &reference('c'));
        *lab.stock.review_registry_image.lock().unwrap() = Some(reference('d'));
        crate::kit_lifecycle::write_sources(
            &lab.backend.config.control_home,
            &BTreeMap::from([(
                "hf".to_owned(),
                marsh_contracts::kit_source::KitTag::parse("example/hf:stable").unwrap(),
            )]),
        )
        .unwrap();
        lab.backend = Arc::new(
            Arc::try_unwrap(lab.backend)
                .unwrap_or_else(|_| panic!("backend was shared"))
                .with_auto_update(None, lab.home.path().to_owned()),
        );
        lab.stock.script(&[Create::HangsUntilCancelled]);
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let pass = std::thread::spawn(move || backend.auto_update_kits(&store));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !lab.stock.hanging.load(std::sync::atomic::Ordering::Acquire) {
            assert!(
                std::time::Instant::now() < deadline,
                "the actual updater never created a VM"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        lab.backend.cancel_background_creates();
        pass.join().unwrap();
        let vm = lab.stock.created()[0].clone();
        assert!(lab.backend.sbx.quarantined_vms()[&vm].create_pending);
        assert!(lab.backend.sbx.is_live_vm_name(&vm));
        assert!(
            lab.records().is_empty(),
            "automatic update has no install-name record"
        );
        lab.reset(&[]).unwrap();
        assert!(lab.backend.sbx.is_live_vm_name(&vm));
        lab.restart();
        lab.stock.land_pending();
        lab.assert_every_vm_owned();
        lab.reset(&[]).unwrap();
        assert_eq!(lab.stock.listed(), NONE);
        assert!(lab.stock.removed().contains(&vm));
    }

    #[test]
    fn review_v2c_reset_all_skips_install_started_after_plan_and_removes_idle() {
        let lab = Lab::new();
        lab.register("g", &reference('c'));
        let idle = lab
            .backend
            .sbx
            .vm_name(marsh_sbx::VmPurpose::Kit, &reference('d'))
            .unwrap();
        lab.stock.seed(&idle);
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        lab.stock.script(&[Create::FailedListed]);
        lab.stock.before_create(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        let install = Arc::new(Mutex::new(None));
        let (slot, backend, store) = (install.clone(), lab.backend.clone(), lab.store().clone());
        *lab.backend.reset_before_locks.lock().unwrap() = Some(Box::new(move || {
            *slot.lock().unwrap() = Some(std::thread::spawn(move || {
                backend.install_command("hf".into(), reference('c'), Some(&store))
            }));
            entered.recv_timeout(Duration::from_secs(5)).unwrap();
        }));
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let (done_tx, done) = std::sync::mpsc::channel();
        let reset = std::thread::spawn(move || {
            let reply = backend.reset_workers(&LoadSelection::All, store);
            done_tx.send(()).unwrap();
            reply
        });
        let prompt = done.recv_timeout(Duration::from_millis(500));
        release.send(()).unwrap();
        let reply = reset.join().unwrap().unwrap();
        install
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .join()
            .unwrap()
            .unwrap_err();
        assert!(prompt.is_ok(), "reset all waited for the install");
        assert!(lab.stock.removed().contains(&idle));
        assert!(
            reply
                .iter()
                .any(|line| line.contains("still running") && line.contains("skipped")),
            "{reply:?}"
        );
    }

    #[test]
    fn review_v2c_stable_lock_contention_releases_prefix_but_is_not_round_bounded() {
        let lab = Lab::new();
        for digit in ['c', 'd'] {
            let vm = lab
                .backend
                .sbx
                .vm_name(marsh_sbx::VmPurpose::Kit, &reference(digit))
                .unwrap();
            lab.stock.seed(&vm);
        }
        let first = lab.backend.kit_lock_for_key(&reference('c')).unwrap();
        let last = lab.backend.kit_lock_for_key(&reference('d')).unwrap();
        let held = last.lock().unwrap();
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let (done_tx, done) = std::sync::mpsc::channel();
        let reset = std::thread::spawn(move || {
            let result = backend.reset_workers(&LoadSelection::All, store);
            done_tx.send(()).unwrap();
            result
        });
        let early = done.recv_timeout(Duration::from_millis(300));
        let deadline = std::time::Instant::now() + Duration::from_millis(300);
        let prefix_free = loop {
            if first.try_lock().is_ok() {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        drop(held);
        reset.join().unwrap().unwrap();
        assert!(
            early.is_err(),
            "stable contention unexpectedly consumed the four planning rounds"
        );
        assert!(
            prefix_free,
            "the reset kept an earlier lock while waiting on a later lock"
        );
        assert_eq!(lab.stock.listed(), NONE);
    }

    #[allow(clippy::too_many_lines)] // One store scenario: worker, jobs, quarantine, reset.
    fn reset_with_a_quarantined_job(complete: bool, named: bool) {
        use marsh_daemon::{
            CleanupState, ExitStatus, NewJob, SessionAuthority, TimingReport, WorkerHealth,
            WorkerStatus,
        };
        let lab = Lab::new();
        if named {
            lab.register("hf", &reference('c'));
        }
        let vm = lab
            .backend
            .sbx
            .vm_name(marsh_sbx::VmPurpose::Kit, &reference('c'))
            .unwrap();
        let idle = lab
            .backend
            .sbx
            .vm_name(marsh_sbx::VmPurpose::Kit, &reference('d'))
            .unwrap();
        lab.stock.seed(&vm);
        lab.stock.seed(&idle);
        lab.backend.sbx.stock_inventory(true).unwrap();
        let store = lab.store();
        store
            .register_worker(WorkerStatus {
                worker_id: vm.clone(),
                vm_id: vm.clone(),
                scope_id: store.status(None).scope_id,
                kit_ref: reference('c'),
                kits: vec!["hf".into()],
                warm: true,
                health: WorkerHealth::Ready,
                container_capacity: 8,
                active_container_ids: vec![],
                quarantine: None,
            })
            .unwrap();
        let session = store.attach_shell(
            1,
            SessionAuthority {
                username: "alice".into(),
                uid: 501,
                gid: 20,
                launch_directory: lab.home.path().into(),
                guest_home: "/Users/alice".into(),
                home_backing: lab.home.path().into(),
                ephemeral_home: false,
            },
        );
        let (job, _) = store
            .begin_job(NewJob {
                label: None,
                session_id: session.clone(),
                command: "hf".into(),
                kit_ref: reference('c'),
                workload_image: reference('c'),
                mounts: vec![],
            })
            .unwrap();
        store.reserve_worker(&job, &vm, &vm).unwrap();
        store.mark_running(&job, &vm, &vm, &"a".repeat(64)).unwrap();
        if named && !complete {
            // One concurrent job fails cleanup and quarantines the whole VM;
            // the first job is still running on it.
            let (sibling, _) = store
                .begin_job(NewJob {
                    label: None,
                    session_id: session,
                    command: "hf".into(),
                    kit_ref: reference('c'),
                    workload_image: reference('c'),
                    mounts: vec![],
                })
                .unwrap();
            store.reserve_worker(&sibling, &vm, &vm).unwrap();
            store
                .mark_running(&sibling, &vm, &vm, &"b".repeat(64))
                .unwrap();
            store
                .finish_job(
                    &sibling,
                    ExitStatus {
                        code: Some(125),
                        cause: "cleanup_failed".into(),
                    },
                    false,
                    CleanupState::Uncertain,
                    TimingReport::default(),
                )
                .unwrap();
        }
        if complete {
            store
                .finish_job(
                    &job,
                    ExitStatus {
                        code: Some(125),
                        cause: "worker_start_ambiguous".into(),
                    },
                    false,
                    CleanupState::Uncertain,
                    TimingReport::default(),
                )
                .unwrap();
        }
        store
            .quarantine_worker(&vm, "container may still run")
            .unwrap();
        assert!(store.vm_jobs_unsettled(&vm));
        if named {
            let reply = lab.reset(&["hf"]);
            if complete {
                reply.unwrap();
                assert!(lab.stock.removed().contains(&vm));
            } else {
                assert!(
                    lab.stock.listed().contains(&vm),
                    "reset NAME removed a quarantined VM with a RUNNING job: reply={reply:?}, removed={:?}",
                    lab.stock.removed()
                );
                assert!(reply.is_err());
            }
            return;
        }
        let reply = lab.reset(&[]).unwrap();
        assert!(
            lab.stock.removed().contains(&idle),
            "idle target was not removed: {reply:?}"
        );
        assert!(
            lab.stock.listed().contains(&vm),
            "reset all removed a VM with unsettled jobs (complete={complete}): reply={reply:?}, removed={:?}",
            lab.stock.removed()
        );
        assert!(
            reply
                .iter()
                .any(|line| line.contains(&vm) && line.contains("skipped")),
            "{reply:?}"
        );
    }

    #[test]
    fn review_v2b_reset_failed_name_does_not_wait_for_an_alias_install() {
        let mut lab = Lab::new();
        lab.stock.script(&[Create::FailedNone]);
        lab.install("hf", &reference('c')).unwrap_err();
        lab.restart();
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        lab.stock.script(&[Create::FailedListed]);
        lab.stock.before_create(move || {
            entered_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let install = std::thread::spawn(move || {
            backend.install_command("alias".into(), reference('c'), Some(&store))
        });
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let (done_tx, done) = std::sync::mpsc::channel();
        let reset = std::thread::spawn(move || {
            let result = backend.reset_workers(&LoadSelection::Kits(vec!["hf".into()]), store);
            done_tx.send(()).unwrap();
            result
        });
        let prompt = done.recv_timeout(Duration::from_millis(500));
        release.send(()).unwrap();
        let reset_result = reset.join().unwrap();
        install.join().unwrap().unwrap_err();
        assert!(
            prompt.is_ok(),
            "reset of a failed install waited for an alias's whole create: {reset_result:?}"
        );
        assert!(
            reset_result
                .unwrap_err()
                .to_string()
                .contains("still running")
        );
    }

    #[test]
    fn claude_v2c_probe_reset_name_keeps_a_quarantined_vm_with_a_running_job() {
        use marsh_daemon::{
            CleanupState, ExitStatus, NewJob, SessionAuthority, TimingReport, WorkerHealth,
            WorkerStatus,
        };
        let lab = Lab::new();
        lab.register("hf", &reference('c'));
        let vm = lab
            .backend
            .sbx
            .vm_name(marsh_sbx::VmPurpose::Kit, &reference('c'))
            .unwrap();
        lab.stock.seed(&vm);
        lab.backend.sbx.stock_inventory(true).unwrap();
        let store = lab.store();
        store
            .register_worker(WorkerStatus {
                worker_id: vm.clone(),
                vm_id: vm.clone(),
                scope_id: store.status(None).scope_id,
                kit_ref: reference('c'),
                kits: vec!["hf".into()],
                warm: true,
                health: WorkerHealth::Ready,
                container_capacity: 8,
                active_container_ids: vec![],
                quarantine: None,
            })
            .unwrap();
        let session = store.attach_shell(
            1,
            SessionAuthority {
                username: "alice".into(),
                uid: 501,
                gid: 20,
                launch_directory: lab.home.path().into(),
                guest_home: "/Users/alice".into(),
                home_backing: lab.home.path().into(),
                ephemeral_home: false,
            },
        );
        let mut jobs = Vec::new();
        for digit in ['a', 'b'] {
            let (job, _) = store
                .begin_job(NewJob {
                    label: None,
                    session_id: session.clone(),
                    command: "hf".into(),
                    kit_ref: reference('c'),
                    workload_image: reference('c'),
                    mounts: vec![],
                })
                .unwrap();
            store.reserve_worker(&job, &vm, &vm).unwrap();
            store
                .mark_running(&job, &vm, &vm, &digit.to_string().repeat(64))
                .unwrap();
            jobs.push(job);
        }
        // Job a ends with uncertain cleanup: the worker is quarantined while
        // job b still runs on it.
        store
            .finish_job(
                &jobs[0],
                ExitStatus {
                    code: Some(125),
                    cause: "worker_start_ambiguous".into(),
                },
                false,
                CleanupState::Uncertain,
                TimingReport::default(),
            )
            .unwrap();
        assert!(store.worker_quarantine(&vm).is_some());
        let reply = lab.reset(&["hf"]);
        assert!(
            lab.stock.listed().contains(&vm),
            "reset NAME removed a VM with a running job: {reply:?}"
        );
    }

    /// `resetIgnoresRecords` (#194 itself): `workers reset NAME` of a
    /// `kit install` that never registered its command reaches the VM its
    /// create left. Fails when reset targets only registered commands.
    #[test]
    fn reset_by_install_name_removes_a_failed_installs_vm() {
        let lab = Lab::new();
        lab.stock.script(&[Create::FailedListed]);
        lab.install("hf", &reference('c')).unwrap_err();
        let vm = lab.stock.created()[0].clone();
        assert_eq!(lab.stock.listed(), std::slice::from_ref(&vm));
        assert_eq!(lab.records(), [format!("{vm} hf")]);
        let mut workers = Vec::new();
        lab.backend.annotate_quarantines(&mut workers, "scope");
        assert_eq!(workers[0].kits, ["hf"], "status names the install");

        assert_eq!(lab.reset(&["hf"]).unwrap(), ["hf"]);
        assert_eq!(lab.stock.listed(), NONE);
        assert_eq!(lab.stock.removed(), [vm]);
        assert_eq!(lab.records(), NONE);
        assert!(matches!(lab.reset(&["hf"]), Err(DaemonError::NotFound(_))));
        assert!(matches!(
            lab.reset(&["nope"]),
            Err(DaemonError::NotFound(_))
        ));
    }

    /// `lateLandingLost`: a reset that finds a timed-out create's name
    /// empty keeps its intent and record (the create may still land) and
    /// says so; the VM lands; the next reset by the install's name removes
    /// it. Fails when a reset ends the record (or forgets the intent) of a
    /// name nothing is listed under.
    #[test]
    fn a_vm_landing_after_a_reset_is_still_reached_by_the_install_name() {
        let lab = Lab::new();
        lab.stock.script(&[Create::TimedOutLandsLater]);
        assert!(
            lab.install("hf", &reference('c'))
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        let vm = lab.stock.created()[0].clone();
        let reply = lab.reset(&["hf"]).unwrap();
        assert!(
            reply
                .iter()
                .any(|line| line.contains(&vm) && line.contains("may still land")),
            "{reply:?}"
        );
        assert!(
            lab.backend.sbx.quarantined_vms().is_empty(),
            "the quarantine is lifted"
        );
        lab.stock.land_pending();
        lab.assert_every_vm_owned();
        lab.reset(&["hf"]).unwrap();
        assert_eq!(lab.stock.listed(), NONE);
        assert_eq!(lab.records(), NONE);
    }

    /// `forgetFailedIntent`: a create stock reported failed with nothing
    /// listed may still land. Its intent and record stay, so the late VM is
    /// adopted, owned, and reached by `reset NAME`. Fails when a definite
    /// failure (or a reset of the empty name) forgets the intent.
    #[test]
    fn a_reported_failure_that_lands_later_stays_owned_and_reachable() {
        let lab = Lab::new();
        lab.stock.script(&[Create::FailedLandsLater]);
        lab.install("hf", &reference('c')).unwrap_err();
        let vm = lab.stock.created()[0].clone();
        assert!(lab.backend.sbx.is_live_vm_name(&vm), "the intent is kept");
        lab.reset(&["hf"]).unwrap();
        lab.stock.land_pending();
        lab.assert_every_vm_owned();
        lab.reset(&["hf"]).unwrap();
        assert_eq!(lab.stock.removed(), [vm]);
    }

    /// `recordsInMemory` and `restartLosesUncertainty`: create A times out
    /// and the daemon restarts (the quarantine and the uncertainty are
    /// lost; the persisted record and intent are not). The retry's create
    /// under the same name is refused as busy (a definite failure); A lands;
    /// `reset NAME` of the restarted daemon still removes it. Fails with the
    /// records kept in memory, or when the busy refusal forgets the intent.
    #[test]
    fn a_failed_install_is_reached_by_name_after_a_restart() {
        let mut lab = Lab::new();
        lab.stock.script(&[Create::TimedOutLandsLater]);
        lab.install("hf", &reference('c')).unwrap_err();
        let vm = lab.stock.created()[0].clone();
        lab.restart();
        assert_eq!(lab.records(), [format!("{vm} hf")]);
        assert_eq!(lab.backend.sbx.quarantined_vms().len(), 0);
        // The retry reuses the Kit's name; stock refuses it while A is pending.
        let retry = lab.install("hf", &reference('c')).unwrap_err();
        assert!(retry.to_string().contains("already in use"), "{retry}");
        assert!(lab.backend.sbx.is_live_vm_name(&vm));
        lab.stock.land_pending();
        lab.assert_every_vm_owned();
        lab.restart();
        lab.reset(&["hf"]).unwrap();
        assert_eq!(lab.stock.listed(), NONE);
        assert_eq!(lab.records(), NONE);
    }

    /// Run `reset` with `between` interleaved after its first plan and
    /// before its Kit locks.
    fn reset_with(
        lab: &Lab,
        names: &[&str],
        between: impl FnOnce() + Send + 'static,
    ) -> Result<Vec<String>, DaemonError> {
        *lab.backend.reset_before_locks.lock().unwrap() = Some(Box::new(between));
        lab.reset(names)
    }

    /// `oldAttemptErasesNew` and `noReplan` (review kh, GPT's repro):
    /// attempt 1 (Kit c) fails with VM1 listed; the reset of `hf` plans
    /// {VM1}; before it locks, a retry from another reference (Kit d)
    /// records VM2 and fails. The reset must plan again under its locks and
    /// remove both: nothing planned before the locks is used after them.
    /// Fails when the reset acts on its first plan.
    #[test]
    fn a_retry_between_a_resets_plan_and_its_locks_is_reset_too() {
        let lab = Lab::new();
        lab.stock
            .script(&[Create::FailedListed, Create::FailedListed]);
        lab.install("hf", &reference('c')).unwrap_err();
        let backend = lab.backend.clone();
        let store = lab.store().clone();
        reset_with(&lab, &["hf"], move || {
            backend
                .install_command("hf".into(), reference('d'), Some(&store))
                .unwrap_err();
        })
        .unwrap();
        assert_eq!(lab.stock.created().len(), 2);
        assert_eq!(lab.stock.listed(), NONE);
        assert_eq!(lab.records(), NONE);
    }

    /// `resetAllSnapshotRace` (review kh3): the install fails with its VM
    /// listed; `reset all` plans; before it locks, the retry recovers that
    /// VM, chooses the Kit's name again and fails with a new VM. The reset
    /// plans again under its locks: every VM is owned and none is left.
    /// Fails when the reset acts on its first plan (the retry's VM stays),
    /// or with the retry's name chosen before its recovery and no
    /// create-time check (the retry's VM is foreign).
    #[test]
    fn reset_all_against_a_retry_that_recovered_leaves_nothing_foreign() {
        let lab = Lab::new();
        lab.stock
            .script(&[Create::FailedListed, Create::FailedListed]);
        lab.install("hf", &reference('c')).unwrap_err();
        let first = lab.stock.created()[0].clone();
        let backend = lab.backend.clone();
        let store = lab.store().clone();
        reset_with(&lab, &[], move || {
            backend
                .install_command("hf".into(), reference('c'), Some(&store))
                .unwrap_err();
        })
        .unwrap();
        let created = lab.stock.created();
        assert_eq!(created.len(), 2);
        assert_ne!(created[1], first, "the retired name is never created under");
        lab.assert_every_vm_owned();
        assert_eq!(lab.stock.listed(), NONE);
    }

    /// `nameBeforeRecovery`: a retry whose Kit VM is quarantined recovers it
    /// first and only then chooses the name, so it never creates under the
    /// name its own recovery retired. Fails with the name chosen before the
    /// recovery and the create-time check removed (either one alone keeps
    /// it safe, as `lockOnly_pass`/`revalidateOnly_pass` show).
    #[test]
    fn a_retry_chooses_its_name_after_recovering_the_quarantined_vm() {
        let lab = Lab::new();
        lab.stock
            .script(&[Create::FailedListed, Create::FailedListed]);
        lab.install("hf", &reference('c')).unwrap_err();
        lab.install("hf", &reference('c')).unwrap_err();
        let created = lab.stock.created();
        assert_ne!(created[0], created[1]);
        assert_eq!(lab.stock.removed(), [created[0].clone()], "recovered first");
        lab.assert_every_vm_owned();
        assert_eq!(lab.records(), [format!("{} hf", created[1])]);
    }

    /// `jobPathStaleName`: a job's preparation is handed the name chosen
    /// before its Kit lock; that VM was quarantined and is recovered under
    /// the lock, and the job creates under the name the map gives now.
    /// Fails when the job path creates under the caller's name with the
    /// create-time check removed.
    #[test]
    fn a_job_creates_under_the_name_chosen_after_recovery() {
        let lab = Lab::new();
        lab.register("c", &reference('c'));
        lab.stock
            .script(&[Create::FailedListed, Create::FailedListed]);
        let stale = lab.backend.kit_spec("c").unwrap();
        lab.backend
            .prepare_one_with_progress(&stale, lab.store(), |_| Ok(()))
            .unwrap_err();
        assert_eq!(lab.stock.listed(), std::slice::from_ref(&stale.name));
        lab.backend
            .prepare_one_with_progress(&stale, lab.store(), |_| Ok(()))
            .unwrap_err();
        let created = lab.stock.created();
        assert_ne!(created[1], stale.name);
        lab.assert_every_vm_owned();
        lab.reset(&["c"]).unwrap();
        assert_eq!(lab.stock.listed(), NONE);
    }

    /// `recoveryNoLock`: background recovery of a quarantined VM no command
    /// names (a failed install's) takes the Kit lock of its ownership key,
    /// so it cannot run inside an install's window between choosing a name
    /// and creating. Fails when recovery locks only for a named VM.
    #[test]
    fn background_recovery_of_an_unnamed_vm_waits_for_its_kit_lock() {
        let lab = Lab::new();
        lab.stock.script(&[Create::FailedListed]);
        lab.install("hf", &reference('c')).unwrap_err();
        let vm = lab.stock.created()[0].clone();
        let owner = lab.backend.sbx.vm_ownership_key(&vm).unwrap();
        let lock = lab.backend.kit_lock_for_key(&owner).unwrap();
        let held = lock.lock().unwrap();
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let recovery = std::thread::spawn(move || backend.recover_quarantined(&store));
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            lab.stock.listed(),
            std::slice::from_ref(&vm),
            "recovered under a held Kit lock"
        );
        drop(held);
        recovery.join().unwrap();
        assert_eq!(lab.stock.removed(), [vm]);
        assert_eq!(lab.records(), NONE);
    }

    /// `switchAbba`: a Kit switch takes the old and the new Kit's locks
    /// together, in key order. With a key-ordered reset holding the new
    /// (lower) key and asking for the old one, the switch waits holding
    /// nothing. Fails when the switch holds the old Kit's lock and then
    /// takes the new one in its preparation.
    #[test]
    fn a_kit_switch_and_a_key_ordered_reset_do_not_deadlock() {
        let lab = Lab::new();
        let (old, new) = (reference('b'), reference('a'));
        lab.register("c", &old);
        let current = lab.backend.registered_kit("c").unwrap();
        let low = lab.backend.kit_lock_for_key(&new).unwrap();
        let high = lab.backend.kit_lock_for_key(&old).unwrap();
        assert!(lab.backend.kit_lock_key(&new).unwrap() < lab.backend.kit_lock_key(&old).unwrap());
        let held_low = low.lock().unwrap();
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let switch = std::thread::spawn(move || {
            let image = marsh_contracts::OciImage::parse(new).unwrap();
            let _ = backend.apply_upgrade("c", &current, &image, &store);
        });
        std::thread::sleep(Duration::from_millis(200));
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let held_high = loop {
            if let Ok(guard) = high.try_lock() {
                break guard;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the switch holds the old Kit's lock while it waits for the new one: ABBA with reset"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        drop(held_high);
        drop(held_low);
        switch.join().unwrap();
    }

    /// `narrowResetAll`: `reset all` targets every live Kit entry of the map,
    /// not only the commands', the records' and the quarantined VMs: a VM
    /// that landed for an entry nothing else names (a Kit switch's create,
    /// after a restart lost its quarantine) is removed. Fails with the
    /// narrower set.
    #[test]
    fn reset_all_removes_a_vm_only_the_ownership_map_names() {
        let mut lab = Lab::new();
        let orphan = lab
            .backend
            .sbx
            .vm_name(marsh_sbx::VmPurpose::Kit, &reference('e'))
            .unwrap();
        lab.stock.seed(&orphan);
        lab.restart();
        lab.reset(&[]).unwrap();
        assert_eq!(lab.stock.listed(), NONE);
    }

    /// `resetNoLock` (the running-record safeguard): while an install's
    /// create is in flight, `reset NAME` refuses at once ("still running")
    /// and `reset all` skips its Kit; neither touches its VM. Fails when the
    /// running record is not looked at (the reset waits on the Kit lock).
    #[test]
    fn a_reset_during_an_install_refuses_or_skips_it() {
        let lab = Lab::new();
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        lab.stock.script(&[Create::FailedListed]);
        lab.stock.before_create(move || {
            entered_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let install = std::thread::spawn(move || {
            backend
                .install_command("hf".into(), reference('c'), Some(&store))
                .unwrap_err()
        });
        entered.recv().unwrap();
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let (done_tx, done) = std::sync::mpsc::channel();
        let named = std::thread::spawn(move || {
            let named =
                backend.reset_workers(&LoadSelection::Kits(vec!["hf".into()]), store.clone());
            let all = backend.reset_workers(&LoadSelection::All, store);
            done_tx.send(()).unwrap();
            (named, all)
        });
        let finished = done.recv_timeout(Duration::from_secs(5));
        release.send(()).unwrap();
        let (named, all) = named.join().unwrap();
        install.join().unwrap();
        assert!(finished.is_ok(), "a reset waited for the install's create");
        let named = named.unwrap_err().to_string();
        assert!(named.contains("still running"), "{named}");
        let all = all.unwrap();
        assert!(
            all.iter()
                .any(|line| line.contains("still running; skipped")),
            "{all:?}"
        );
        assert_eq!(lab.stock.removed(), NONE);
        // Settled now: the next reset reaches it.
        lab.reset(&["hf"]).unwrap();
        assert_eq!(lab.stock.listed(), NONE);
    }

    /// `recoveryKeepsRecord` (review kh2): automatic recovery removes a
    /// failed install's VM; the record ends with the name, so the next
    /// reset is not refused by a stale record, and a failed retry is reset
    /// by name again.
    #[test]
    fn recovery_ends_the_record_and_a_failed_retry_is_reset_by_name() {
        let lab = Lab::new();
        lab.stock
            .script(&[Create::FailedListed, Create::FailedListed]);
        lab.install("hf", &reference('c')).unwrap_err();
        lab.backend.recover_quarantined(lab.store());
        assert_eq!(lab.stock.listed(), NONE);
        assert_eq!(lab.records(), NONE);
        assert!(matches!(lab.reset(&["hf"]), Err(DaemonError::NotFound(_))));
        lab.install("hf", &reference('c')).unwrap_err();
        lab.reset(&["hf"]).unwrap();
        assert_eq!(lab.stock.listed(), NONE);
    }

    /// `forceStopForgetsIntents`, for the teardown both `marsh reset`/`marsh
    /// stop` and `marsh stop --force` end with: it keeps the intent and the
    /// record of a create that may still land, so the late VM is owned and
    /// reached by name. Fails when teardown forgets an absent intent.
    #[test]
    fn teardown_keeps_the_intent_of_a_create_that_may_still_land() {
        let lab = Lab::new();
        lab.stock.script(&[Create::TimedOutLandsLater]);
        lab.install("hf", &reference('c')).unwrap_err();
        let vm = lab.stock.created()[0].clone();
        let report = lab.backend.teardown_scope(
            marsh_daemon::ScopeLifecycleAction::Reset,
            lab.store().clone(),
            std::time::Instant::now() + Duration::from_secs(30),
        );
        assert!(report.cleanup_complete || !report.components.is_empty());
        lab.stock.land_pending();
        lab.assert_every_vm_owned();
        assert_eq!(lab.records(), [format!("{vm} hf")]);
        lab.reset(&["hf"]).unwrap();
        assert_eq!(lab.stock.listed(), NONE);
    }

    /// Rule 5 (`failedCreateKeepsRecord` is the design now): a create stock
    /// reported failed with nothing listed keeps its intent and its record
    /// for as long as the intent lives; a reset says it may still land.
    #[test]
    fn a_reported_failure_with_nothing_listed_keeps_its_intent_and_record() {
        let lab = Lab::new();
        lab.stock.script(&[Create::FailedNone]);
        lab.install("hf", &reference('c')).unwrap_err();
        let vm = lab.stock.created()[0].clone();
        let reply = lab.reset(&["hf"]).unwrap();
        assert!(
            reply.iter().any(|line| line.contains("may still land")),
            "{reply:?}"
        );
        assert!(lab.backend.sbx.is_live_vm_name(&vm));
        assert_eq!(lab.records(), [format!("{vm} hf")]);
    }

    /// `marsh stop --force` through the real backend: the install's create
    /// hangs; cancelling creates ends it (the install fails, keeping its
    /// intent and record); the forced stop's teardown keeps them; the record
    /// survives the restart; the VM landing afterwards is owned and removed
    /// by `reset NAME` of the next daemon.
    #[test]
    fn a_forced_stop_cancels_a_hung_install_whose_late_vm_the_next_daemon_resets() {
        let mut lab = Lab::new();
        lab.stock.script(&[Create::HangsUntilCancelled]);
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let install = std::thread::spawn(move || {
            backend.install_command("hf".into(), reference('c'), Some(&store))
        });
        while !lab.stock.hanging.load(std::sync::atomic::Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(10));
        }
        lab.backend.cancel_creates();
        install.join().unwrap().unwrap_err();
        let vm = lab.stock.created()[0].clone();
        lab.backend.teardown_scope(
            marsh_daemon::ScopeLifecycleAction::Stop,
            lab.store().clone(),
            std::time::Instant::now() + Duration::from_secs(30),
        );
        lab.restart();
        assert_eq!(lab.records(), [format!("{vm} hf")]);
        lab.stock.land_pending();
        lab.assert_every_vm_owned();
        lab.reset(&["hf"]).unwrap();
        assert_eq!(lab.stock.listed(), NONE);
        assert_eq!(lab.records(), NONE);
    }

    /// Rule 2 (`InstPublish`): an install holds its Kit lock from its
    /// decision until its command is registered, so no recovery, GC or reset
    /// of the Kit acts between the VM's preparation and the registry write;
    /// then its record ends. (The VM here is a validation flight that
    /// completed while the install waited for the lock, whose Ready VM it
    /// shares.) Fails when the lock is released before the registration.
    #[test]
    fn an_install_holds_its_kit_lock_until_its_command_is_registered() {
        let lab = Lab::new();
        let owner = reference('c');
        let name = lab
            .backend
            .sbx
            .vm_name(marsh_sbx::VmPurpose::Kit, &owner)
            .unwrap();
        let key = lab.backend.kit_lock_key(&owner).unwrap();
        let lock = lab.backend.kit_lock_for_key(&owner).unwrap();
        let held = lock.lock().unwrap();
        let (observed_tx, observed) = std::sync::mpsc::channel();
        let observed_tx = Mutex::new(observed_tx);
        let locked_at_publish = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (seen, publish_lock) = (Arc::clone(&locked_at_publish), Arc::clone(&lock));
        *lab.backend.install_hook.lock().unwrap() = Some(Box::new(move |point| match point {
            "observed" => observed_tx.lock().unwrap().send(()).unwrap(),
            "publish" => seen.store(
                publish_lock.try_lock().is_err(),
                std::sync::atomic::Ordering::SeqCst,
            ),
            _ => {}
        }));
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let install = std::thread::spawn(move || {
            backend.install_command("hf".into(), reference('c'), Some(&store))
        });
        observed.recv().unwrap();
        let spec = lab
            .backend
            .kit_spec_for_workload_named(
                marsh_sbx::NativeKitRef::immutable_oci(owner.clone()).unwrap(),
                name.clone(),
            )
            .unwrap();
        lab.backend.ready_kits.lock().unwrap().insert(
            key.clone(),
            marsh_sbx::ReadyKitVm {
                name: name.clone(),
                kit_ref: owner.clone(),
                lifecycle_workspace: spec.lifecycle_workspace.clone(),
                cold_started: false,
                job_image: spec.workload_kit.workload_image().unwrap().clone(),
                worker_binary: spec.worker_binary.clone(),
            },
        );
        lab.backend.kit_validation_flights.lock().unwrap().insert(
            key,
            crate::KitFlightCompletion {
                epoch: 1,
                error: None,
            },
        );
        drop(held);
        install.join().unwrap().unwrap();
        assert!(
            locked_at_publish.load(std::sync::atomic::Ordering::SeqCst),
            "the Kit lock was free before the command was registered"
        );
        assert_eq!(lab.records(), NONE, "the published attempt's record ended");
        assert!(lab.backend.command_names().contains(&"hf".to_owned()));
        assert_eq!(lab.stock.created(), NONE);
    }

    /// `Gc` under the lock: VM garbage collection takes the Kit lock of the
    /// VM's ownership key whether or not a command names its Kit (here a
    /// superseded Kit's stopped VM), so it cannot act inside a preparation's
    /// window. Fails when GC locks only a current Kit's VM.
    #[test]
    fn garbage_collection_of_a_superseded_kit_vm_waits_for_its_kit_lock() {
        let lab = Lab::new();
        let owner = reference('e');
        let vm = lab
            .backend
            .sbx
            .vm_name(marsh_sbx::VmPurpose::Kit, &owner)
            .unwrap();
        lab.stock.seed_stopped(&vm);
        let lock = lab.backend.kit_lock_for_key(&owner).unwrap();
        let held = lock.lock().unwrap();
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let gc = std::thread::spawn(move || backend.gc_vms(false, &store));
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            lab.stock.listed(),
            std::slice::from_ref(&vm),
            "collected under a held Kit lock"
        );
        drop(held);
        let report = gc.join().unwrap().unwrap();
        assert_eq!(lab.stock.removed(), [vm], "{report:?}");
    }

    /// Rule 4 (the create-time check, with `revalidateOnly_pass`'s unlocked
    /// retirement): the Kit's VM is retired by a path that does not take the
    /// Kit lock between the install's choice of its name and its create. The
    /// create is refused under the retired name; the install chooses again,
    /// re-points its record and creates under the new name, which stays
    /// owned and reachable. Fails without the check (the VM is foreign) or
    /// without the second choice (the install fails, creating nothing).
    #[test]
    fn a_name_retired_before_the_create_is_chosen_again_and_the_record_follows() {
        let lab = Lab::new();
        let owner = reference('c');
        let old = lab
            .backend
            .sbx
            .vm_name(marsh_sbx::VmPurpose::Kit, &owner)
            .unwrap();
        lab.stock.seed(&old);
        lab.stock.script(&[Create::FailedListed]);
        let (sbx, retired, key) = (lab.backend.sbx.clone(), old.clone(), owner.clone());
        lab.stock.before_list(move || {
            sbx.retire_kit_vm_named_before(
                &retired,
                &key,
                std::time::Instant::now() + Duration::from_secs(30),
                None,
            )
            .unwrap();
        });
        let error = lab.install("hf", &owner).unwrap_err();
        let created = lab.stock.created();
        assert_eq!(created.len(), 1, "{created:?} {error}");
        assert_ne!(created[0], old);
        lab.assert_every_vm_owned();
        assert_eq!(lab.records(), [format!("{} hf", created[0])]);
        lab.reset(&["hf"]).unwrap();
        assert_eq!(lab.stock.listed(), NONE);
    }

    // Reviewer ports of the kh/kh2/kh3 interleavings, through real callers.
    #[test]
    fn review_record_is_on_disk_before_stock_create_is_submitted() {
        let lab = Lab::new();
        let (home, stock) = (lab.home.path().to_owned(), lab.stock.clone());
        lab.stock.before_create(move || {
            assert_eq!(stock.created().len(), 0);
            let fresh = Lab::daemon(&home, &stock);
            let records = fresh.sbx.install_records();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].2.command, "hf");
            assert_eq!(
                fresh
                    .sbx
                    .recorded_vm_name(marsh_sbx::VmPurpose::Kit, &reference('c'))
                    .as_deref(),
                Some(records[0].0.as_str())
            );
        });
        lab.install("hf", &reference('c')).unwrap_err();
    }

    #[test]
    fn review_attempt_ids_do_not_replace_a_different_kits_record_after_restart() {
        let mut lab = Lab::new();
        lab.stock
            .script(&[Create::TimedOutLandsLater, Create::FailedListed]);
        lab.install("hf", &reference('c')).unwrap_err();
        let first = lab.backend.sbx.install_records()[0].2.attempt.clone();
        lab.restart();
        lab.install("hf", &reference('d')).unwrap_err();
        let records = lab.backend.sbx.install_records();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|(_, _, r)| r.attempt == first));
        assert_ne!(records[0].2.attempt, records[1].2.attempt);
        lab.stock.land_pending();
        lab.reset(&["hf"]).unwrap();
        assert_eq!(lab.stock.listed().len(), 0);
    }

    #[test]
    fn review_ephemeral_recovery_remembers_the_actual_name_for_session_cleanup() {
        let mut lab = Lab::new();
        let lease = lab.backend.sbx.allocate_ephemeral_home().unwrap();
        let token = lease.token();
        lab.store = None;
        let server = marsh_daemon::Server::bind(lab.home.path())
            .unwrap()
            .with_backend(lab.backend.clone());
        lab.store = Some(server.store());
        let task = std::thread::spawn(move || server.serve_one().unwrap());
        let authority = marsh_daemon::SessionAuthority {
            username: "review".into(),
            uid: nix::unistd::Uid::current().as_raw(),
            gid: nix::unistd::Gid::current().as_raw(),
            launch_directory: lab.home.path().to_owned(),
            guest_home: lease.path().to_owned(),
            home_backing: lease.path().to_owned(),
            ephemeral_home: true,
        };
        let reply = marsh_daemon::Client::connect(lab.home.path())
            .unwrap()
            .request(marsh_daemon::PublicRequest::AttachEphemeralShell {
                pid: std::process::id(),
                session: authority.clone(),
                expected_project_identity: None,
                token: token.clone(),
            })
            .unwrap();
        task.join().unwrap();
        let marsh_daemon::PublicReply::ShellAttached { session_id } = reply else {
            panic!("{reply:?}");
        };
        let session = marsh_daemon::SessionSpec {
            session_id: session_id.clone(),
            username: authority.username,
            uid: authority.uid,
            gid: authority.gid,
            launch_directory: authority.launch_directory,
            guest_home: authority.guest_home,
            home_backing: authority.home_backing,
            ephemeral_home: true,
            terminal: false,
            terminal_size: None,
        };
        lab.register("c", &reference('c'));
        let spec = lab
            .backend
            .kit_spec_for_session("c", &session, lab.store())
            .unwrap();
        lab.stock
            .script(&[Create::FailedListed, Create::FailedListed]);
        lab.backend
            .prepare_one_authorized(&spec, lab.store(), Some(&token), |_| Ok(()))
            .unwrap_err();
        lab.backend
            .prepare_one_authorized(&spec, lab.store(), Some(&token), |_| Ok(()))
            .unwrap_err();
        let created = lab.stock.created();
        assert_eq!(created.len(), 2);
        assert_ne!(created[0], created[1]);
        let remembered = lab
            .backend
            .remembered_ephemeral_kits()
            .into_iter()
            .map(|s| s.name)
            .collect::<Vec<_>>();
        lease.close_admission().unwrap();
        let closed = lab.backend.close_ephemeral_kits(&session_id, lab.store());
        assert!(
            closed.is_ok() && lab.stock.listed().is_empty(),
            "close={closed:?}, session cleanup knew {remembered:?}, actual VM left={:?}",
            lab.stock.listed()
        );
    }

    #[test]
    fn review_v2b_ephemeral_close_deduplicates_and_takes_kit_keys_in_order() {
        let mut lab = Lab::new();
        let lease = lab.backend.sbx.allocate_ephemeral_home().unwrap();
        let token = lease.token();
        lab.store = None;
        let server = marsh_daemon::Server::bind(lab.home.path())
            .unwrap()
            .with_backend(lab.backend.clone());
        lab.store = Some(server.store());
        let task = std::thread::spawn(move || server.serve_one().unwrap());
        let authority = marsh_daemon::SessionAuthority {
            username: "review".into(),
            uid: nix::unistd::Uid::current().as_raw(),
            gid: nix::unistd::Gid::current().as_raw(),
            launch_directory: lab.home.path().into(),
            guest_home: lease.path().into(),
            home_backing: lease.path().into(),
            ephemeral_home: true,
        };
        let reply = marsh_daemon::Client::connect(lab.home.path())
            .unwrap()
            .request(marsh_daemon::PublicRequest::AttachEphemeralShell {
                pid: std::process::id(),
                session: authority.clone(),
                expected_project_identity: None,
                token,
            })
            .unwrap();
        task.join().unwrap();
        let marsh_daemon::PublicReply::ShellAttached { session_id } = reply else {
            panic!("{reply:?}")
        };
        let session = marsh_daemon::SessionSpec {
            session_id: session_id.clone(),
            username: authority.username,
            uid: authority.uid,
            gid: authority.gid,
            launch_directory: authority.launch_directory,
            guest_home: authority.guest_home,
            home_backing: authority.home_backing,
            ephemeral_home: true,
            terminal: false,
            terminal_size: None,
        };
        for digit in ['c', 'd'] {
            lab.register(&digit.to_string(), &reference(digit));
            let spec = lab
                .backend
                .kit_spec_for_session(&digit.to_string(), &session, lab.store())
                .unwrap();
            lab.stock.seed(&spec.name);
            if digit == 'c' {
                let mut duplicate = spec;
                duplicate.name = "marsh-k-oldname1".into();
                lab.backend
                    .ephemeral_kits
                    .lock()
                    .unwrap()
                    .get_mut(&session_id)
                    .unwrap()
                    .insert(duplicate.name.clone(), duplicate);
            }
        }
        lease.close_admission().unwrap();
        let first = lab
            .backend
            .kit_lock_for_key(&format!("{}:ephemeral:{session_id}", reference('c')))
            .unwrap();
        let last = lab
            .backend
            .kit_lock_for_key(&format!("{}:ephemeral:{session_id}", reference('d')))
            .unwrap();
        let held = last.lock().unwrap();
        let (backend, store, session) =
            (lab.backend.clone(), lab.store().clone(), session_id.clone());
        let close = std::thread::spawn(move || backend.close_ephemeral_kits(&session, &store));
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        let mut took_first = false;
        while std::time::Instant::now() < deadline {
            if first.try_lock().is_err() {
                took_first = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(held);
        let result = close.join().unwrap();
        assert!(
            took_first,
            "close waited for a later Kit key before taking the earlier one"
        );
        result.unwrap();
        assert_eq!(lab.stock.listed(), NONE);
        assert!(lab.store().ephemeral_home_token(&session_id).is_none());
    }

    #[test]
    fn review_late_adoption_during_an_absent_reset_must_not_forget_the_vm() {
        let mut lab = Lab::new();
        lab.stock.script(&[Create::TimedOutLandsLater]);
        lab.install("hf", &reference('c')).unwrap_err();
        let stock = lab.stock.clone();
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        *lab.stock.after_list_snapshot.lock().unwrap() = Some(Box::new(move || {
            // Reset's stock listing already observed absence. Before that
            // response reaches the adapter, GC's inventory lists the late VM.
            stock.land_pending();
            let report = backend.gc_vms(true, &store).unwrap();
            assert!(
                report
                    .entries
                    .iter()
                    .any(|entry| entry.vm == stock.created()[0])
            );
        }));
        lab.reset(&["hf"]).unwrap();
        lab.restart();
        lab.register("fixture", &reference('d'));
        let named = lab.reset(&["hf"]);
        let all = lab.reset(&[]);
        assert!(
            named.is_ok() && all.is_ok() && lab.stock.listed().is_empty(),
            "named={named:?}, all={all:?}, surviving={:?}, owned={:?}, records={:?}",
            lab.stock.listed(),
            lab.backend.sbx.live_kit_entries(),
            lab.records()
        );
    }

    #[test]
    fn review_kh_landing_after_absent_reset_keeps_both_cleanup_paths() {
        for all in [false, true] {
            let lab = Lab::new();
            lab.register("fixture", &reference('d'));
            lab.stock.script(&[Create::TimedOutLandsLater]);
            lab.install("hf", &reference('c')).unwrap_err();
            lab.reset(if all { &[] } else { &["hf"] }).unwrap();
            lab.stock.land_pending();
            lab.reset(if all { &[] } else { &["hf"] }).unwrap();
            assert_eq!(lab.stock.listed().len(), 0);
            assert_eq!(lab.records().len(), 0);
        }
    }

    #[test]
    fn review_kh_new_attempt_during_old_retirement_keeps_its_record() {
        let lab = Lab::new();
        lab.stock
            .script(&[Create::FailedListed, Create::FailedListed]);
        lab.install("hf", &reference('c')).unwrap_err();
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        lab.stock.before_list(move || {
            backend
                .install_command("hf".into(), reference('d'), Some(&store))
                .unwrap_err();
        });
        lab.reset(&["hf"]).unwrap();
        assert_eq!(lab.stock.listed().len(), 1);
        assert_eq!(lab.records().len(), 1, "old retirement erased new attempt");
        lab.reset(&["hf"]).unwrap();
        assert_eq!(lab.stock.listed().len(), 0);
        assert_eq!(lab.records().len(), 0);
    }

    #[test]
    fn review_kh2_automatic_retirement_retry_and_both_resets() {
        for all in [false, true] {
            let lab = Lab::new();
            lab.stock
                .script(&[Create::FailedListed, Create::FailedListed]);
            lab.install("hf", &reference('c')).unwrap_err();
            let vm = lab.stock.created()[0].clone();
            lab.backend
                .recover_quarantined_vm(lab.store(), &vm)
                .unwrap();
            assert_eq!(lab.records().len(), 0);
            lab.install("hf", &reference('c')).unwrap_err();
            lab.reset(if all { &[] } else { &["hf"] }).unwrap();
            assert_eq!(lab.stock.listed().len(), 0);
            assert_eq!(lab.records().len(), 0);
        }
    }

    #[test]
    fn review_kh3_retry_entering_during_locked_reset_uses_a_fresh_name() {
        let lab = Lab::new();
        lab.stock
            .script(&[Create::TimedOutLandsLater, Create::TimedOutLandsLater]);
        lab.install("hf", &reference('c')).unwrap_err();
        lab.reset(&["hf"]).unwrap();
        lab.stock.land_pending();
        let old = lab.stock.created()[0].clone();
        let (observed_tx, observed) = std::sync::mpsc::channel();
        let observed_tx = Mutex::new(observed_tx);
        *lab.backend.install_hook.lock().unwrap() = Some(Box::new(move |point| {
            if point == "observed" {
                observed_tx.lock().unwrap().send(()).unwrap();
            }
        }));
        let retry = Arc::new(Mutex::new(None));
        let handle = retry.clone();
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        lab.stock.before_list(move || {
            *handle.lock().unwrap() = Some(std::thread::spawn(move || {
                backend.install_command("hf".into(), reference('c'), Some(&store))
            }));
            observed.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        lab.reset(&[]).unwrap();
        retry
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .join()
            .unwrap()
            .unwrap_err();
        let created = lab.stock.created();
        assert_eq!(created.len(), 2, "retry did not submit create");
        assert_ne!(created[1], old, "retry submitted under retired name");
        lab.stock.land_pending();
        lab.assert_every_vm_owned();
        lab.reset(&["hf"]).unwrap();
        lab.reset(&[]).unwrap_err(); // No commands or live entries remain.
        assert_eq!(lab.stock.listed().len(), 0);
        assert_eq!(lab.records().len(), 0);
    }

    /// `removeUnowned` (`NoForeignRemoval`): a VM listed under an install's
    /// recorded name that is not the VM the map recorded (another UUID) is
    /// never removed. `reset NAME` refuses; `reset all` skips it, says so,
    /// and still removes the other targets (Claude's review: one target it
    /// cannot remove made the whole reset refuse after earlier ones were
    /// removed). Fails when a reset removes a recorded name's VM without the
    /// UUID check, or when `reset all` stops at the first target it skips.
    #[test]
    fn a_reset_never_removes_a_vm_the_map_did_not_record() {
        let lab = Lab::new();
        lab.stock.script(&[Create::FailedListed]);
        lab.install("hf", &reference('c')).unwrap_err();
        let vm = lab.stock.created()[0].clone();
        // A fresh listing adopts the VM's UUID; then another VM takes the name.
        lab.backend.sbx.stock_inventory(true).unwrap();
        lab.stock.replace(&vm);
        // Another Kit's VM, owned and idle, sorted after it.
        let other = lab
            .backend
            .sbx
            .vm_name(marsh_sbx::VmPurpose::Kit, &reference('e'))
            .unwrap();
        lab.stock.seed(&other);
        let named = lab.reset(&["hf"]).unwrap_err().to_string();
        assert!(named.contains("not an owned"), "{named}");
        let all = lab.reset(&[]).unwrap();
        assert!(
            all.iter()
                .any(|line| line.starts_with(&format!("{vm}: skipped"))
                    && line.contains("not an owned")),
            "{all:?}"
        );
        assert_eq!(lab.stock.removed(), [other]);
        assert_eq!(lab.stock.listed(), [vm]);
    }

    /// Claude's review: `reset all` leaves a live ephemeral-home session's
    /// Kit VM alone (closing the session removes it). Fails when `reset all`
    /// targets it.
    #[test]
    fn reset_all_skips_a_live_ephemeral_sessions_kit_vm() {
        let lab = Lab::new();
        let key = format!("{}:ephemeral:session-1", reference('c'));
        let vm = lab
            .backend
            .sbx
            .vm_name(marsh_sbx::VmPurpose::Kit, &key)
            .unwrap();
        lab.stock.seed(&vm);
        let spec = lab
            .backend
            .kit_spec_for_workload_named(
                marsh_sbx::NativeKitRef::immutable_oci(reference('c')).unwrap(),
                vm.clone(),
            )
            .unwrap();
        lab.backend
            .ephemeral_kits
            .lock()
            .unwrap()
            .entry("session-1".into())
            .or_default()
            .insert(vm.clone(), spec);
        lab.register("fixture", &reference('d'));
        lab.reset(&[]).unwrap();
        assert_eq!(lab.stock.listed(), [vm]);
        // Once the session is gone, `reset all` removes it.
        lab.backend.ephemeral_kits.lock().unwrap().clear();
        lab.reset(&[]).unwrap();
        assert_eq!(lab.stock.listed(), NONE);
    }

    /// The retry of a failed install succeeds, through a validation flight
    /// that completed while it waited: its Ready VM is `name`.
    fn complete_next_install(lab: &Lab, owner: &str, name: &str) {
        let key = lab.backend.kit_lock_key(owner).unwrap();
        let spec = lab
            .backend
            .kit_spec_for_workload_named(
                marsh_sbx::NativeKitRef::immutable_oci(owner.to_owned()).unwrap(),
                name.to_owned(),
            )
            .unwrap();
        let backend = Arc::downgrade(&lab.backend);
        let owner = owner.to_owned();
        *lab.backend.install_hook.lock().unwrap() = Some(Box::new(move |point| {
            let Some(backend) = backend.upgrade() else {
                return;
            };
            if point != "observed" {
                return;
            }
            backend.ready_kits.lock().unwrap().insert(
                key.clone(),
                marsh_sbx::ReadyKitVm {
                    name: spec.name.clone(),
                    kit_ref: owner.clone(),
                    lifecycle_workspace: spec.lifecycle_workspace.clone(),
                    cold_started: false,
                    job_image: spec.workload_kit.workload_image().unwrap().clone(),
                    worker_binary: spec.worker_binary.clone(),
                },
            );
            let mut flights = backend.kit_validation_flights.lock().unwrap();
            let epoch = flights.get(&key).map_or(0, |flight| flight.epoch) + 1;
            flights.insert(
                key.clone(),
                crate::KitFlightCompletion { epoch, error: None },
            );
        }));
    }

    /// Claude's review (the downgrade trap) and `KitInstall.tla`
    /// `InstPublish`: publishing a command ends every earlier record of it
    /// on the VM it was published on (the registry reaches that VM now), not
    /// only the publishing attempt's. Fails when publication ends its own
    /// record only.
    #[test]
    fn publishing_ends_the_commands_earlier_records_on_that_vm() {
        let mut lab = Lab::new();
        lab.stock.script(&[Create::FailedNone]);
        lab.install("hf", &reference('c')).unwrap_err();
        let vm = lab.stock.created()[0].clone();
        // A restart: the record stays, the quarantine goes.
        lab.restart();
        assert_eq!(lab.records(), [format!("{vm} hf")]);
        complete_next_install(&lab, &reference('c'), &vm);
        lab.install("hf", &reference('c')).unwrap();
        assert_eq!(lab.records(), NONE);
        assert!(lab.backend.command_names().contains(&"hf".to_owned()));
    }

    /// Claude's review (`may still land` for a create never submitted) and
    /// `KitInstall.tla` `InstAbort`: an install refused by `marsh stop
    /// --force` before its create made nothing: its record ends and its name
    /// is not quarantined, so no reset says a create may still land. Fails
    /// when the record is kept (the record outlives every reset).
    #[test]
    fn an_install_stopped_before_its_create_leaves_no_record() {
        let lab = Lab::new();
        lab.backend.cancel_creates();
        let error = lab.install("hf", &reference('c')).unwrap_err().to_string();
        assert!(error.contains("marsh stop --force"), "{error}");
        assert_eq!(lab.stock.created(), NONE);
        assert_eq!(lab.records(), NONE);
        assert_eq!(lab.backend.sbx.quarantined_vms().len(), 0);
    }

    /// Claude's review: `reset NAME` of a command whose Kit an install of
    /// another command is preparing refuses at once instead of waiting out
    /// the install's create (it would wait on the Kit lock), and so does a
    /// reset of the installing command before its record is written (it is
    /// running from before its Kit lock). Fails when only records count as
    /// running.
    #[test]
    fn a_reset_of_a_kit_an_install_is_preparing_refuses_at_once() {
        let lab = Lab::new();
        lab.register("g", &reference('c'));
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        lab.stock.script(&[Create::FailedListed]);
        lab.stock.before_create(move || {
            entered_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let install = std::thread::spawn(move || {
            backend
                .install_command("hf".into(), reference('c'), Some(&store))
                .unwrap_err()
        });
        entered.recv().unwrap();
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let (done_tx, done) = std::sync::mpsc::channel();
        let reset = std::thread::spawn(move || {
            let reset = backend.reset_workers(&LoadSelection::Kits(vec!["g".into()]), store);
            done_tx.send(()).unwrap();
            reset
        });
        let finished = done.recv_timeout(Duration::from_secs(5));
        release.send(()).unwrap();
        let reset = reset.join().unwrap();
        install.join().unwrap();
        assert!(
            finished.is_ok(),
            "the reset waited for the install's create"
        );
        let refused = reset.unwrap_err().to_string();
        assert!(refused.contains("still running on g's Kit"), "{refused}");
    }

    /// Claude's review: `marsh workers stop` reads (or chooses) its Kit VM's
    /// name under the Kit lock, as every other path does, not before it.
    /// Fails when the name is chosen before the lock (a stop waiting on a
    /// held lock has already put an intent in the map).
    #[test]
    fn workers_stop_reads_its_vm_name_under_the_kit_lock() {
        let lab = Lab::new();
        lab.register("c", &reference('c'));
        let lock = lab.backend.kit_lock_for_key(&reference('c')).unwrap();
        let held = lock.lock().unwrap();
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let stop = std::thread::spawn(move || {
            backend.stop_workers(&LoadSelection::Kits(vec!["c".into()]), &store)
        });
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(lab.backend.sbx.live_kit_entries(), Vec::new());
        drop(held);
        stop.join().unwrap().unwrap();
    }

    /// GPT's round 2 (the lock acquisition): an install that starts on the
    /// Kit after a reset's plan and before its locks holds that Kit lock for
    /// its whole create. The reset does not wait for it blocked: it plans
    /// again while the lock is held, and refuses. Fails with a blocking lock
    /// acquisition.
    #[test]
    fn a_reset_does_not_wait_on_an_install_that_started_after_its_plan() {
        let lab = Lab::new();
        lab.register("g", &reference('c'));
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        lab.stock.script(&[Create::FailedListed]);
        lab.stock.before_create(move || {
            entered_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        let install = Arc::new(Mutex::new(None));
        let (slot, backend, store) = (install.clone(), lab.backend.clone(), lab.store().clone());
        *lab.backend.reset_before_locks.lock().unwrap() = Some(Box::new(move || {
            *slot.lock().unwrap() = Some(std::thread::spawn(move || {
                backend.install_command("hf".into(), reference('c'), Some(&store))
            }));
            entered.recv_timeout(Duration::from_secs(5)).unwrap();
        }));
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let (done_tx, done) = std::sync::mpsc::channel();
        let reset = std::thread::spawn(move || {
            let reset = backend.reset_workers(&LoadSelection::Kits(vec!["g".into()]), store);
            done_tx.send(()).unwrap();
            reset
        });
        let finished = done.recv_timeout(Duration::from_secs(5));
        release.send(()).unwrap();
        let reset = reset.join().unwrap();
        install
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .join()
            .unwrap()
            .unwrap_err();
        assert!(
            finished.is_ok(),
            "the reset waited blocked on the install's Kit lock"
        );
        let refused = reset.unwrap_err().to_string();
        assert!(refused.contains("still running on g's Kit"), "{refused}");
    }

    /// Claude's round 2 (N2), `staleAbsence` for the scope reset (`marsh
    /// reset`/`stop`): it reads the recorded UUIDs before its listing, so a VM
    /// that lands and is adopted by another listing after that listing was
    /// taken is not forgotten as gone. Fails when the UUIDs are read after
    /// the listing.
    #[test]
    fn the_scope_reset_never_forgets_a_vm_adopted_after_its_listing() {
        let lab = Lab::new();
        lab.stock.script(&[Create::TimedOutLandsLater]);
        lab.install("hf", &reference('c')).unwrap_err();
        let vm = lab.stock.created()[0].clone();
        let (stock, sbx) = (lab.stock.clone(), lab.backend.sbx.clone());
        *lab.stock.after_list_snapshot.lock().unwrap() = Some(Box::new(move || {
            // The scope reset's listing found nothing; the VM lands and a
            // newer listing adopts it before that reply is acted on.
            stock.land_pending();
            sbx.stock_inventory(true).unwrap();
        }));
        lab.backend.sbx.reset_stale_scope_kit_vms().unwrap();
        assert_eq!(lab.stock.listed(), std::slice::from_ref(&vm));
        lab.assert_every_vm_owned();
        assert_eq!(lab.records(), [format!("{vm} hf")]);
        lab.reset(&["hf"]).unwrap();
        assert_eq!(lab.stock.listed(), NONE);
    }

    /// GPT's round 3 (the bound): a reset waiting on a Kit lock that stays
    /// held (stable contention) gives up at its deadline and names the Kit,
    /// removing nothing. Fails with the deadline removed (it waits as long as
    /// the lock is held).
    #[test]
    fn a_reset_under_stable_contention_gives_up_at_its_deadline() {
        let lab = Lab::new();
        lab.register("g", &reference('c'));
        let vm = lab
            .backend
            .sbx
            .vm_name(marsh_sbx::VmPurpose::Kit, &reference('c'))
            .unwrap();
        lab.stock.seed(&vm);
        lab.backend
            .reset_lock_wait
            .store(300, std::sync::atomic::Ordering::Relaxed);
        let lock = lab.backend.kit_lock_for_key(&reference('c')).unwrap();
        let held = lock.lock().unwrap();
        let (backend, store) = (lab.backend.clone(), lab.store().clone());
        let (done_tx, done) = std::sync::mpsc::channel();
        let reset = std::thread::spawn(move || {
            let reset = backend.reset_workers(&LoadSelection::Kits(vec!["g".into()]), store);
            done_tx.send(()).unwrap();
            reset
        });
        let finished = done.recv_timeout(Duration::from_secs(5));
        drop(held);
        let refused = reset.join().unwrap();
        assert!(finished.is_ok(), "the reset outwaited its deadline");
        let refused = refused.unwrap_err().to_string();
        assert!(
            refused.contains(&reference('c')) && refused.contains("nothing was removed"),
            "{refused}"
        );
        assert_eq!(lab.stock.listed(), std::slice::from_ref(&vm));
    }
}
