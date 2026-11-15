//! A stuck services engine for tests: a generation whose worker is inside one
//! admitted `sbx` call that never returns until released, so a stop path can
//! be driven against the one state it must refuse. Test code only (`cfg(test)`
//! or the `test-support` feature); nothing here runs a real `sbx`.
/// Provenance marker. Every binary that links this harness keeps these bytes;
/// packaging refuses them (`scripts/check-no-test-breaks.sh`), so an artifact
/// carrying the harness is refused even when no feature metadata says so (a
/// hand-passed `--cfg`).
#[used]
pub static MARSH_FEATURE_TEST_SUPPORT: [u8; 26] = *b"marsh-feature:test-support";

use crate::services_engine::{
    EngineArtifacts, EngineHandle, EnginePin, EngineSettings, PIN_SCHEMA, ServicesEngine,
    ServicesVmRef,
};
use crate::services_relay::ServicesRelays;
use crate::{StockSbx, VmPurpose};
use marsh_runtime::{CommandOutput, CommandRunner, Invocation};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Answers `sbx` by verb and holds the first `sbx cp` until released.
#[derive(Default)]
pub(crate) struct HeldCopy {
    /// Hold the first `sha256sum` instead of the first `sbx cp`.
    pub(crate) hold_hash: bool,
    calls: Mutex<Vec<String>>,
    /// What `sbx ls --json` answers (empty: an unparseable listing).
    listing: Mutex<Vec<u8>>,
    held: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl HeldCopy {
    pub(crate) fn wait_held(&self) {
        let held = self.held.lock().unwrap();
        let (held, timeout) = self
            .changed
            .wait_timeout_while(held, Duration::from_secs(30), |held| !held.0)
            .unwrap();
        assert!(!timeout.timed_out() && held.0, "no copy reached the hold");
    }

    pub(crate) fn release(&self) {
        self.held.lock().unwrap().1 = true;
        self.changed.notify_all();
    }

    /// Answer `sbx ls --json` with a listing of these `(name, status)` VMs.
    pub fn list(&self, vms: &[(&str, &str)]) {
        let rows: Vec<String> = vms
            .iter()
            .enumerate()
            .map(|(index, (name, status))| {
                format!(
                    r#"{{"name":"{name}","id":"{index:08x}-4b5a-4978-8695-a4b3c2d1e0f9","status":"{status}"}}"#
                )
            })
            .collect();
        *self.listing.lock().unwrap() = format!("[{}]", rows.join(",")).into_bytes();
    }

    /// Every `sbx` call so far, as its words.
    pub(crate) fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl CommandRunner for HeldCopy {
    fn run(&self, _: &Invocation) -> std::io::Result<CommandOutput> {
        Err(std::io::Error::other("unbounded call"))
    }

    fn run_bounded(&self, invocation: &Invocation, _: Duration) -> std::io::Result<CommandOutput> {
        let words: Vec<String> = invocation
            .arguments
            .iter()
            .map(|word| word.to_string_lossy().into_owned())
            .collect();
        self.calls.lock().unwrap().push(words.join(" "));
        let mut stdout = Vec::new();
        let held = if self.hold_hash {
            words.iter().any(|word| word == "sha256sum")
        } else {
            words.first().map(String::as_str) == Some("cp")
        };
        match words.first().map(String::as_str) {
            _ if held && !self.held.lock().unwrap().0 => {
                let mut held = self.held.lock().unwrap();
                held.0 = true;
                self.changed.notify_all();
                while !held.1 {
                    held = self.changed.wait(held).unwrap();
                }
            }
            Some("exec") if words.iter().any(|word| word == "cat") => {
                stdout = b"boot-1\n".to_vec();
            }
            Some("ls") => stdout.clone_from(&self.listing.lock().unwrap()),
            _ => {}
        }
        Ok(CommandOutput {
            exit_code: Some(0),
            stdout,
            stderr: Vec::new(),
        })
    }

    fn spawn_attached(&self, _: &Invocation) -> std::io::Result<marsh_runtime::Attachment> {
        Err(std::io::Error::other("no attached process"))
    }
}

/// Engine artifacts for a generation that is never really installed.
pub(crate) fn test_artifacts() -> EngineArtifacts {
    EngineArtifacts {
        pin: EnginePin {
            schema: PIN_SCHEMA.into(),
            platform: "linux/arm64".into(),
            image_id: format!("sha256:{}", "1".repeat(64)),
            config_id: format!("sha256:{}", "2".repeat(64)),
            archive: "engine.tar".into(),
            archive_sha256: "a".repeat(64),
            archive_bytes: 1,
        },
        archive: PathBuf::from("/nonexistent/engine.tar"),
        marsh: PathBuf::from("/nonexistent/marsh"),
        marsh_sha256: "b".repeat(64),
    }
}

pub(crate) fn test_vm() -> ServicesVmRef {
    ServicesVmRef {
        name: "marsh-v-test".into(),
        project_root: PathBuf::from("/Users/alice/project"),
    }
}

/// A generation whose worker is inside one held stock call.
pub(crate) fn start_held(hold_hash: bool) -> (Arc<HeldCopy>, Arc<EngineHandle>) {
    let runner = Arc::new(HeldCopy {
        hold_hash,
        ..HeldCopy::default()
    });
    let engine = ServicesEngine::new(PathBuf::from("sbx"), runner.clone());
    let handle = Arc::new(engine.start(test_vm(), test_artifacts(), EngineSettings::default()));
    runner.wait_held();
    (runner, handle)
}

/// A services engine generation stuck inside a call, and the runner that
/// holds the call (and answers everything else `sbx` is asked).
pub struct StuckEngine {
    runner: Arc<HeldCopy>,
    handle: Arc<EngineHandle>,
}

impl StuckEngine {
    /// A generation whose worker is held inside its first `sbx cp`.
    #[must_use]
    pub fn start() -> Self {
        let (runner, handle) = start_held(false);
        Self { runner, handle }
    }

    /// The runner to give the stock adapter, so its calls are answered and
    /// recorded together with the engine's.
    #[must_use]
    pub fn runner(&self) -> Arc<dyn CommandRunner> {
        self.runner.clone()
    }

    /// Answer `sbx ls --json` with these `(name, status)` VMs.
    pub fn list(&self, vms: &[(&str, &str)]) {
        self.runner.list(vms);
    }

    /// Let the held call return.
    pub fn release(&self) {
        self.runner.release();
    }

    /// Every `sbx` verb the adapter or engine has run so far.
    #[must_use]
    pub fn verbs(&self) -> Vec<String> {
        self.runner
            .calls()
            .iter()
            .filter_map(|call| call.split_whitespace().next().map(str::to_owned))
            .collect()
    }

    /// Hand the generation to `relays` as a failed or replaced start would:
    /// still inside its call, owned until the worker is gone.
    pub fn stick_in(&self, relays: &ServicesRelays, root: &Path) -> bool {
        relays.detach_owned(root, &self.handle)
    }
}

impl StockSbx {
    /// Record a services VM of `root` as owned, with a UUID, as a created one is.
    ///
    /// # Panics
    /// If the name or record cannot be made.
    pub fn own_services_vm_for_test(&self, root: &Path) -> String {
        let name = self
            .vm_name(VmPurpose::Services, root.to_str().unwrap())
            .unwrap();
        self.ownership
            .record(&name, "5f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9")
            .unwrap();
        name
    }
}
