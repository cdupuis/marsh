//! `marsh kit install`, its Kit VM and `marsh workers reset`: the design
//! `docs/model/KitInstall.tla` proves (issue #194).

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
        /// Reported failed with the VM listed.
        FailedListed,
    }

    /// Stock SBX as a name -> VM table: a create is atomic on its name, and
    /// a name that is taken or still being created is refused.
    #[derive(Default)]
    pub(super) struct Stock {
        vms: Mutex<BTreeMap<String, String>>,
        outcomes: Mutex<VecDeque<Create>>,
        created: Mutex<Vec<String>>,
        removed: Mutex<Vec<String>>,
        next_id: AtomicU64,
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

        fn land(&self, name: &str) {
            let id = self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.vms.lock().unwrap().insert(
                name.to_owned(),
                format!("00000000-0000-4000-8000-{id:012x}"),
            );
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

        fn run_bounded(&self, invocation: &Invocation, _: Duration) -> io::Result<CommandOutput> {
            let arguments = invocation
                .arguments
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            match arguments.first().map(String::as_str) {
                Some("ls") => {
                    let rows = self
                        .vms
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|(name, id)| {
                            format!(r#"{{"name":"{name}","id":"{id}","status":"running"}}"#)
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    Ok(CommandOutput {
                        exit_code: Some(0),
                        stdout: format!(r#"{{"sandboxes":[{rows}]}}"#).into_bytes(),
                        stderr: Vec::new(),
                    })
                }
                Some("create") => {
                    let name = arguments
                        .iter()
                        .position(|argument| argument == "--name")
                        .map(|index| arguments[index + 1].clone())
                        .unwrap();
                    if self.vms.lock().unwrap().contains_key(&name) {
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
                        Create::FailedListed => {
                            self.land(&name);
                            output(1, "create failed")
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

        fn spawn_attached(&self, _: &Invocation) -> io::Result<Attachment> {
            Err(io::Error::other("unexpected attachment"))
        }
    }

    pub(super) fn reference(digit: char) -> String {
        format!("example/hf@sha256:{}", digit.to_string().repeat(64))
    }

    /// A daemon over [`Stock`], with a persisted ownership map.
    pub(super) struct Lab {
        _home: tempfile::TempDir,
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
                _home: home,
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
                test_stock(stock.clone()).with_vm_ownership(map).unwrap(),
            ))
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
}
