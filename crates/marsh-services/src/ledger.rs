//! The workspace ledger (A4, DECISIONS 14): which scope owns which object.
//!
//! Persisted on the pool, inside the engine, so it survives engine restarts
//! (the engine's containers do too). It is the only authority for scope; labels
//! are display text. Compose labels never exempt anything.
// Pedantic lints this module trades for readability: the HTTP and policy code is
// long, table-like and full of one-letter names for a request, a head and a
// connection.
#![allow(
    clippy::missing_errors_doc,
    clippy::many_single_char_names,
    clippy::too_many_lines,
    clippy::format_push_string,
    clippy::collapsible_if,
    clippy::collapsible_else_if
)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use crate::policy::{Lookup, VolumeScope};

#[derive(Debug, Clone)]
pub struct Paths {
    pub ledger: PathBuf,
    pub bind_root: PathBuf,
    pub socket_root: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            ledger: PathBuf::from("/pool/marsh/ledger.json"),
            bind_root: PathBuf::from("/var/lib/marsh/binds"),
            socket_root: PathBuf::from("/run/marsh/sockets"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerRec {
    pub scope: String,
    pub attempt: String,
    pub name: Option<String>,
    pub pins: Vec<String>,
    pub created: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetRec {
    pub scope: String,
    pub attempt: String,
    pub name: String,
    #[serde(default)]
    pub created: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolRec {
    pub scope: String,
    pub attempt: String,
    #[serde(default)]
    pub created: u64,
}

/// Who created an image tag (`repo:tag`, canonical spelling).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagRec {
    pub scope: String,
    pub created: u64,
    /// How many times the engine refused to untag it when its scope was dropped.
    #[serde(default)]
    pub untag_refused: u32,
}

/// Most tag records kept. At the cap, records whose image is gone are dropped
/// first (`Ledger::retain_tags`); a request that still would not fit is refused.
pub const MAX_TAGS: usize = 8192;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinRec {
    pub scope: String,
    /// The project root as the authority gave it (re-opened on restore).
    pub project_root: String,
    /// Canonical, root-relative path resolved at admission.
    pub rel: String,
    pub read_only: bool,
    pub is_dir: bool,
    /// Protected top-level names mounted read-only inside this pin.
    pub subs: Vec<String>,
    pub dev: u64,
    pub ino: u64,
    pub created: u64,
    /// Restore could not recreate this pin. Containers that hold it must not
    /// start (A3: a failed resolve fails `start` closed).
    #[serde(default)]
    pub failed: bool,
}

/// What a protected name (`.git`, `.marsh`) of a project root resolved to the
/// first time the agent saw it. The identity outlives the name: a job that
/// renames `.git` and pins the new name still pins the recorded identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedId {
    pub name: String,
    pub dev: u64,
    pub ino: u64,
}

/// Execs remembered per container; a new one past this forgets the oldest.
pub const MAX_EXECS_PER_CONTAINER: usize = 256;

/// At most this many identities are kept per project root. The earliest are the
/// most trustworthy, so a full list stops growing rather than evicting.
pub const MAX_PROTECTED_IDS: usize = 64;

/// A substituted Docker socket (A3.1) to serve again after an engine restart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SockRec {
    pub scope: String,
    pub attempt: String,
    pub project_root: String,
    pub upstream: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    sockets: BTreeMap<String, SockRec>,
    /// Passes in a row in which the engine did not list a container. Not
    /// persisted: an engine that is still starting must not cost us pins.
    #[serde(skip)]
    missing: BTreeMap<String, u32>,
    /// What the file looked like when this state was last read or written. A
    /// different file means another process wrote: reload before changing.
    #[serde(skip)]
    seen: Option<FileSig>,
    containers: BTreeMap<String, ContainerRec>,
    networks: BTreeMap<String, NetRec>,
    volumes: BTreeMap<String, VolRec>,
    /// Older ledgers have none.
    #[serde(default)]
    tags: BTreeMap<String, TagRec>,
    /// Exec ID -> (sequence, container). Not persisted: an exec outlives
    /// neither its container nor the agent's connections, and a ledger that
    /// kept every `docker exec` would grow and slow every write without bound.
    #[serde(skip)]
    execs: BTreeMap<String, (u64, String)>,
    #[serde(skip)]
    exec_seq: u64,
    pins: BTreeMap<String, PinRec>,
    scope_networks: BTreeMap<String, String>,
    /// Per project root (as the authority gave it): the `(dev, ino)` of every
    /// `.git`/`.marsh` seen there. Older ledgers have none.
    #[serde(default)]
    protected: BTreeMap<String, Vec<ProtectedId>>,
}

/// Identity of the ledger file as of one read or write.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSig {
    ino: u64,
    mtime_ns: i128,
    len: u64,
}

fn file_sig(path: &Path) -> Option<FileSig> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some(FileSig {
        ino: m.ino(),
        mtime_ns: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
        len: m.len(),
    })
}

/// The ledger could not make a change durable. Nothing changed in memory
/// either: callers refuse the request, or undo the engine object they made.
#[derive(Debug)]
pub struct LedgerError(pub String);

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ownership records cannot be saved: {}", self.0)
    }
}

impl std::error::Error for LedgerError {}

pub type LedgerResult<T> = Result<T, LedgerError>;

/// Who holds a volume name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeClaim {
    /// Unowned until this call: the caller now owns it.
    New,
    Own,
    Foreign,
}

/// What the engine says about an image tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagImage {
    /// No image has the name.
    Absent,
    /// The image was pulled (it has registry digests): shared, nobody's to move.
    Pulled,
    /// Built, committed or tagged here.
    Local,
}

/// What a scope may do with an image tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClaim {
    /// The caller created it already.
    Own,
    /// Free to take: nobody holds it, or its holder's image is gone.
    New,
    /// Another scope created it and its image is there.
    Foreign,
    /// A pulled image: not the caller's to move.
    Unowned,
}

/// The rule for moving a tag, given the ledger's record and what the engine
/// has under that name. A record whose image is gone holds nothing (so a
/// `docker rmi` frees the name at once); an image built here that no record
/// covers (its scope was dropped, or it predates the ledger) is adopted.
#[must_use]
pub fn tag_claim(rec: Option<&TagRec>, scope: &str, image: TagImage) -> TagClaim {
    match (rec, image) {
        (Some(r), _) if r.scope == scope => TagClaim::Own,
        (Some(_), TagImage::Local | TagImage::Pulled) => TagClaim::Foreign,
        (None, TagImage::Pulled) => TagClaim::Unowned,
        (Some(_) | None, TagImage::Absent) | (None, TagImage::Local) => TagClaim::New,
    }
}

pub struct Ledger {
    path: Option<PathBuf>,
    state: Mutex<State>,
    /// The last write failed: durable authority is not established.
    degraded: AtomicBool,
    /// Held for this ledger's lifetime by an agent that serves requests from
    /// it (`open_exclusive`): no other serving agent can hold stale authority.
    #[allow(dead_code)] // held, never read: dropping it releases the lock
    serve_lock: Option<std::fs::File>,
}

#[must_use]
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Ledger {
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            state: Mutex::new(State::default()),
            degraded: AtomicBool::new(false),
            serve_lock: None,
        }
    }

    /// Open (or create) the ledger at `path`. A file that does not parse is
    /// set aside as `<name>.corrupt-*`, never deleted, and the ledger starts
    /// from what could be read of it (nothing, if no state survives).
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let _lock = lock_file(path)?;
        sweep_temp_files(path);
        let mut state = match std::fs::read(path) {
            Ok(b) => match parse_state(&b) {
                Ok(state) => state,
                Err(first) => {
                    let kept = set_aside(path, &b)?;
                    write_quarantine(path, &kept)?;
                    eprintln!(
                        "marsh-services: ledger {} did not parse ({first}); kept as {}; \
                         protected paths are unknown until {} is removed",
                        path.display(),
                        kept.display(),
                        path.with_extension("quarantine").display()
                    );
                    parse_first_value(&b).unwrap_or_default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e),
        };
        state.seen = file_sig(path);
        Ok(Self {
            path: Some(path.to_path_buf()),
            state: Mutex::new(state),
            degraded: AtomicBool::new(false),
            serve_lock: None,
        })
    }

    /// As [`Self::open`], for the agent that serves requests from the ledger:
    /// it also holds an exclusive lock for its lifetime, so a second serving
    /// agent (a replacement that started before the old one exited) waits up
    /// to `wait` and then fails. Reads answer from memory, so two servers
    /// could authorize an operation on an object the other has since given to
    /// another workspace; one server at a time cannot.
    pub fn open_exclusive(path: &Path, wait: std::time::Duration) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let serving = lock_exclusive(&path.with_extension("serve"), wait).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "another agent is serving {} ({e}); it must exit first",
                    path.display()
                ),
            )
        })?;
        let mut ledger = Self::open(path)?;
        ledger.serve_lock = Some(serving);
        Ok(ledger)
    }

    /// The ledger was found corrupt and set aside, so the recorded protected
    /// identities (`.git`, `.marsh`) cannot be trusted. Until an operator
    /// verifies them and removes `ledger.quarantine`, nothing that depends on
    /// them (binding a project folder) is admitted.
    #[must_use]
    pub fn quarantined(&self) -> bool {
        self.path
            .as_ref()
            .is_some_and(|path| path.with_extension("quarantine").exists())
    }

    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        let mut g = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut g)
    }

    /// Apply `f` to a copy of the state, write that copy, and only then adopt
    /// it. `f` returns its result and whether it changed anything.
    fn mutate<R>(&self, f: impl FnOnce(&mut State) -> (R, bool)) -> LedgerResult<R> {
        let mut g = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Another agent process may share the file: serialize on a lock file
        // and start from whatever it last published.
        let _lock = match &self.path {
            Some(path) => match lock_file(path) {
                Ok(lock) => Some(lock),
                Err(e) => {
                    self.degraded.store(true, Ordering::SeqCst);
                    return Err(LedgerError(format!("ledger lock: {e}")));
                }
            },
            None => None,
        };
        let mut next = match self.path.as_deref().map(|path| fresh(path, &g)) {
            Some(Err(e)) => {
                self.degraded.store(true, Ordering::SeqCst);
                return Err(LedgerError(e.to_string()));
            }
            Some(Ok(state)) => state,
            None => g.clone(),
        };
        let (r, changed) = f(&mut next);
        if !changed {
            *g = next;
            return Ok(r);
        }
        if let Some(path) = &self.path {
            if crate::breaks::break_mode("ledger-persist-ignore") {
                // Defect: a failed write is logged and acknowledged.
                if let Err(e) = persist(path, &next) {
                    eprintln!("marsh-services: ledger write failed: {e}");
                }
            } else if let Err(e) = persist(path, &next) {
                self.degraded.store(true, Ordering::SeqCst);
                return Err(LedgerError(e.to_string()));
            }
            next.seen = file_sig(path);
        }
        self.degraded.store(false, Ordering::SeqCst);
        *g = next;
        Ok(r)
    }

    /// Try to make the state durable again after a failed write. `true` when
    /// the ledger is writable (and admissions may resume).
    pub fn probe(&self) -> bool {
        if !self.degraded() {
            return true;
        }
        self.mutate(|_| ((), true)).is_ok()
    }

    /// The last write failed, so no new object may be admitted until one
    /// succeeds.
    #[must_use]
    pub fn degraded(&self) -> bool {
        self.degraded.load(Ordering::SeqCst)
    }

    // --- containers ---------------------------------------------------------

    /// Resolve a name, ID or ID prefix inside one scope. Objects of other
    /// scopes are indistinguishable from missing ones.
    #[must_use]
    pub fn find_container(&self, scope: &str, r: &str) -> Lookup {
        self.with(|s| {
            let own: Vec<(&String, &ContainerRec)> = s
                .containers
                .iter()
                .filter(|(_, c)| c.scope == scope)
                .collect();
            if let Some((id, _)) = own.iter().find(|(id, _)| id.as_str() == r) {
                return Lookup::Own((*id).clone());
            }
            let bare = r.trim_start_matches('/');
            if let Some((id, _)) = own.iter().find(|(_, c)| c.name.as_deref() == Some(bare)) {
                return Lookup::Own((*id).clone());
            }
            if r.len() >= 4 && r.bytes().all(|b| b.is_ascii_hexdigit()) {
                let hits: Vec<_> = own.iter().filter(|(id, _)| id.starts_with(r)).collect();
                return match hits.len() {
                    0 => Lookup::Missing,
                    1 => Lookup::Own(hits[0].0.clone()),
                    _ => Lookup::Ambiguous,
                };
            }
            Lookup::Missing
        })
    }

    #[must_use]
    pub fn container(&self, id: &str) -> Option<ContainerRec> {
        self.with(|s| s.containers.get(id).cloned())
    }

    #[must_use]
    pub fn container_ids(&self, scope: &str) -> Vec<String> {
        self.with(|s| {
            s.containers
                .iter()
                .filter(|(_, c)| c.scope == scope)
                .map(|(i, _)| i.clone())
                .collect()
        })
    }

    /// The pins a container holds (its own and those it inherited).
    #[must_use]
    pub fn container_pins(&self, id: &str) -> Vec<String> {
        self.with(|s| {
            s.containers
                .get(id)
                .map(|c| c.pins.clone())
                .unwrap_or_default()
        })
    }

    /// Containers that hold `pin`.
    #[must_use]
    pub fn containers_holding(&self, pin: &str) -> Vec<String> {
        self.with(|s| {
            s.containers
                .iter()
                .filter(|(_, c)| c.pins.iter().any(|p| p == pin))
                .map(|(id, _)| id.clone())
                .collect()
        })
    }

    /// Does the container hold a pin that restore could not recreate?
    #[must_use]
    pub fn container_has_failed_pin(&self, id: &str) -> bool {
        self.with(|s| {
            s.containers.get(id).is_some_and(|c| {
                c.pins
                    .iter()
                    .any(|p| s.pins.get(p).is_some_and(|r| r.failed))
            })
        })
    }

    pub fn add_container(&self, id: &str, rec: ContainerRec) -> LedgerResult<()> {
        self.mutate(|s| {
            s.containers.insert(id.to_string(), rec);
            ((), true)
        })
    }

    /// Returns the pins that no container references any more, with their
    /// records (the mountpoint's type is needed to remove it).
    pub fn remove_container(&self, id: &str) -> LedgerResult<Vec<(String, PinRec)>> {
        self.mutate(|s| {
            let Some(rec) = s.containers.remove(id) else {
                return (Vec::new(), false);
            };
            s.execs.retain(|_, (_, c)| c != id);
            (release_unreferenced(s, &rec.pins), true)
        })
    }

    pub fn rename_container(&self, id: &str, name: &str) -> LedgerResult<()> {
        self.mutate(|s| {
            if let Some(c) = s.containers.get_mut(id) {
                c.name = Some(name.to_string());
            }
            ((), true)
        })
    }

    // --- substituted sockets --------------------------------------------------

    /// A dropped workspace's records that exist for the scope itself: its
    /// substituted sockets and its default network entry. Objects are removed
    /// through the engine (and leave the ledger by their own removal). Image
    /// tag records stay: they go one by one, once the engine confirmed the
    /// untag (`release_tag`), so a tag that is still there keeps its owner.
    pub fn forget_scope(&self, scope: &str) -> LedgerResult<()> {
        self.mutate(|s| {
            let before = (s.sockets.len(), s.scope_networks.len());
            s.sockets.retain(|_, rec| rec.scope != scope);
            s.scope_networks.remove(scope);
            let changed = before != (s.sockets.len(), s.scope_networks.len());
            ((), changed)
        })
    }

    pub fn add_socket(&self, rec: SockRec) -> LedgerResult<()> {
        self.mutate(|s| {
            s.sockets
                .insert(format!("{}/{}", rec.scope, rec.attempt), rec);
            ((), true)
        })
    }

    #[must_use]
    pub fn sockets(&self) -> Vec<SockRec> {
        self.with(|s| s.sockets.values().cloned().collect())
    }

    // --- pins ---------------------------------------------------------------

    pub fn add_pin(&self, id: &str, rec: PinRec) -> LedgerResult<()> {
        self.mutate(|s| {
            s.pins.insert(id.to_string(), rec);
            ((), true)
        })
    }

    /// Record whether restore recreated a pin. Persisted: the service that
    /// admits `start` is not the process that ran restore.
    pub fn set_pin_failed(&self, id: &str, failed: bool) -> LedgerResult<()> {
        self.mutate(|s| match s.pins.get_mut(id) {
            Some(p) if p.failed != failed => {
                p.failed = failed;
                ((), true)
            }
            _ => ((), false),
        })
    }

    #[must_use]
    pub fn pin(&self, id: &str) -> Option<PinRec> {
        self.with(|s| s.pins.get(id).cloned())
    }

    #[must_use]
    pub fn pins(&self) -> Vec<(String, PinRec)> {
        self.with(|s| s.pins.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    /// Forget pins of a request that failed. Returns those actually dropped.
    pub fn drop_pins(&self, ids: &[String]) -> LedgerResult<Vec<(String, PinRec)>> {
        self.mutate(|s| {
            let freed = release_unreferenced(s, ids);
            let changed = !freed.is_empty();
            (freed, changed)
        })
    }

    // --- protected identities -----------------------------------------------

    /// The identities recorded for a project root.
    #[must_use]
    pub fn protected(&self, project_root: &str) -> Vec<ProtectedId> {
        self.with(|s| s.protected.get(project_root).cloned().unwrap_or_default())
    }

    /// Remember identities not yet recorded for a project root (up to
    /// [`MAX_PROTECTED_IDS`]); known ones change nothing.
    pub fn note_protected(&self, project_root: &str, seen: &[ProtectedId]) -> LedgerResult<()> {
        self.mutate(|s| {
            let list = s.protected.entry(project_root.to_string()).or_default();
            let mut changed = false;
            for id in seen {
                if list.len() < MAX_PROTECTED_IDS
                    && !list.iter().any(|k| k.dev == id.dev && k.ino == id.ino)
                {
                    list.push(id.clone());
                    changed = true;
                }
            }
            if list.is_empty() {
                s.protected.remove(project_root);
            }
            ((), changed)
        })
    }

    // --- networks, volumes, execs ---------------------------------------------

    #[must_use]
    pub fn find_network(&self, scope: &str, r: &str) -> Lookup {
        self.with(|s| {
            let own: Vec<_> = s
                .networks
                .iter()
                .filter(|(_, n)| n.scope == scope)
                .collect();
            if let Some((id, _)) = own.iter().find(|(id, n)| id.as_str() == r || n.name == r) {
                return Lookup::Own((*id).clone());
            }
            if r.len() >= 4 && r.bytes().all(|b| b.is_ascii_hexdigit()) {
                let hits: Vec<_> = own.iter().filter(|(id, _)| id.starts_with(r)).collect();
                return match hits.len() {
                    0 => Lookup::Missing,
                    1 => Lookup::Own(hits[0].0.clone()),
                    _ => Lookup::Ambiguous,
                };
            }
            Lookup::Missing
        })
    }

    pub fn add_network(&self, id: &str, rec: NetRec) -> LedgerResult<()> {
        self.mutate(|s| {
            s.networks.insert(id.to_string(), rec);
            ((), true)
        })
    }

    pub fn remove_network(&self, id: &str) -> LedgerResult<()> {
        self.mutate(|s| {
            let name = s.networks.get(id).map(|n| n.name.clone());
            s.networks.remove(id);
            s.scope_networks
                .retain(|_, n| n.as_str() != id && Some(n.as_str()) != name.as_deref());
            ((), true)
        })
    }

    #[must_use]
    pub fn scope_network(&self, scope: &str) -> Option<String> {
        self.with(|s| s.scope_networks.get(scope).cloned())
    }

    pub fn set_scope_network(&self, scope: &str, name: &str) -> LedgerResult<()> {
        self.mutate(|s| {
            s.scope_networks.insert(scope.to_string(), name.to_string());
            ((), true)
        })
    }

    #[must_use]
    pub fn volume(&self, scope: &str, name: &str) -> VolumeScope {
        self.with(|s| match s.volumes.get(name) {
            Some(v) if v.scope == scope => VolumeScope::Own,
            Some(_) => VolumeScope::Foreign,
            None => VolumeScope::Unknown,
        })
    }

    /// Atomically reserve a volume name for `scope`. Never replaces another
    /// scope's ownership: the loser of a race is told `Foreign`.
    pub fn claim_volume(
        &self,
        scope: &str,
        attempt: &str,
        name: &str,
    ) -> LedgerResult<VolumeClaim> {
        self.mutate(|s| match s.volumes.get(name) {
            Some(v) if v.scope == scope => (VolumeClaim::Own, false),
            Some(_) if !crate::breaks::break_mode("volume-claim-racy") => {
                (VolumeClaim::Foreign, false)
            }
            _ => {
                s.volumes.insert(
                    name.to_string(),
                    VolRec {
                        scope: scope.to_string(),
                        attempt: attempt.to_string(),
                        created: now(),
                    },
                );
                (VolumeClaim::New, true)
            }
        })
    }

    /// Give back a claim made by this call when the engine object was not
    /// created. Only the owner can release.
    pub fn unclaim_volume(&self, scope: &str, name: &str) -> LedgerResult<()> {
        self.mutate(|s| match s.volumes.get(name) {
            Some(v) if v.scope == scope => {
                s.volumes.remove(name);
                ((), true)
            }
            _ => ((), false),
        })
    }

    /// Forget a volume the engine has deleted. Only the owner can.
    pub fn remove_volume(&self, scope: &str, name: &str) -> LedgerResult<()> {
        self.unclaim_volume(scope, name)
    }

    #[must_use]
    pub fn has_volume(&self, scope: &str, name: &str) -> bool {
        self.volume(scope, name) == VolumeScope::Own
    }

    #[must_use]
    pub fn tag_owner(&self, name: &str) -> Option<TagRec> {
        self.with(|s| s.tags.get(name).cloned())
    }

    #[must_use]
    pub fn tag_count(&self) -> usize {
        self.with(|s| s.tags.len())
    }

    /// The tags `scope` is recorded as the creator of, in name order.
    #[must_use]
    pub fn scope_tags(&self, scope: &str) -> Vec<String> {
        self.with(|s| {
            let mut names: Vec<String> = s
                .tags
                .iter()
                .filter(|(_, rec)| rec.scope == scope)
                .map(|(name, _)| name.clone())
                .collect();
            names.sort();
            names
        })
    }

    /// Forget `scope`'s record of a tag; a record another scope has taken over
    /// since stays. Returns whether a record went.
    pub fn release_tag(&self, scope: &str, name: &str) -> LedgerResult<bool> {
        self.mutate(|s| {
            let mine = s.tags.get(name).is_some_and(|rec| rec.scope == scope);
            if mine {
                s.tags.remove(name);
            }
            (mine, mine)
        })
    }

    /// Count one refusal by the engine to untag `scope`'s record of a tag;
    /// returns the count (0 when the record is not the scope's).
    pub fn note_untag_refused(&self, scope: &str, name: &str) -> LedgerResult<u32> {
        self.mutate(|s| match s.tags.get_mut(name) {
            Some(rec) if rec.scope == scope => {
                rec.untag_refused += 1;
                (rec.untag_refused, true)
            }
            _ => (0, false),
        })
    }

    /// Keep only the tag records `keep` accepts; returns how many went.
    pub fn retain_tags(&self, keep: impl Fn(&str, &TagRec) -> bool) -> LedgerResult<usize> {
        self.mutate(|s| {
            let before = s.tags.len();
            s.tags.retain(|name, rec| keep(name, rec));
            let gone = before - s.tags.len();
            (gone, gone > 0)
        })
    }

    /// Record `scope` as the creator of a tag (taking over a stale record).
    /// `Ok(false)`: the ledger holds too many tags and kept the record out.
    pub fn set_tag(&self, scope: &str, name: &str) -> LedgerResult<bool> {
        self.mutate(|s| {
            if s.tags.len() >= MAX_TAGS && !s.tags.contains_key(name) {
                return (false, false);
            }
            s.tags.insert(
                name.to_string(),
                TagRec {
                    scope: scope.to_string(),
                    created: now(),
                    untag_refused: 0,
                },
            );
            (true, true)
        })
    }

    /// Remember that `exec` belongs to `container`, in memory only and at most
    /// [`MAX_EXECS_PER_CONTAINER`] per container.
    pub fn add_exec(&self, exec: &str, container: &str) {
        self.with(|s| {
            s.exec_seq += 1;
            s.execs
                .insert(exec.to_string(), (s.exec_seq, container.to_string()));
            let mine = s.execs.values().filter(|(_, c)| c == container).count();
            if mine > MAX_EXECS_PER_CONTAINER {
                let oldest = s
                    .execs
                    .iter()
                    .filter(|(_, (_, c))| c == container)
                    .min_by_key(|(_, (seq, _))| *seq)
                    .map(|(id, _)| id.clone());
                if let Some(id) = oldest {
                    s.execs.remove(&id);
                }
            }
        });
    }

    #[must_use]
    pub fn exec_container(&self, scope: &str, exec: &str) -> Lookup {
        self.with(|s| {
            match s
                .execs
                .get(exec)
                .and_then(|(_, c)| s.containers.get(c).map(|r| (c, r)))
            {
                Some((c, r)) if r.scope == scope => Lookup::Own(c.clone()),
                _ => Lookup::Missing,
            }
        })
    }

    /// Does `id` (full network ID) or name belong to `scope`?
    #[must_use]
    pub fn owns_network(&self, scope: &str, id: &str, name: &str) -> bool {
        self.with(|s| {
            s.networks.get(id).is_some_and(|n| n.scope == scope)
                || s.networks
                    .values()
                    .any(|n| n.scope == scope && n.name == name && !name.is_empty())
        })
    }

    #[must_use]
    pub fn owns_volume(&self, scope: &str, name: &str) -> bool {
        self.has_volume(scope, name)
    }

    // --- reconcile ----------------------------------------------------------

    /// Drop records of objects the engine no longer has (auto-removed
    /// containers, prunes, a wiped pool) and return pins nothing references.
    /// `pending_volumes` are names the engine may still create (a create of
    /// unknown outcome): their records are kept.
    pub fn reconcile(
        &self,
        containers: &[String],
        networks: &[String],
        volumes: &[String],
        pending_volumes: &[String],
        now_secs: u64,
    ) -> LedgerResult<Vec<(String, PinRec)>> {
        self.mutate(|s| {
            let mut freed = Vec::new();
            let mut changed = false;
            let gone: Vec<String> = s
                .containers
                .keys()
                .filter(|id| !containers.contains(id))
                .cloned()
                .collect();
            s.missing.retain(|id, _| gone.contains(id));
            for id in gone {
                // An engine that is still starting may list nothing: only a
                // container missing from two passes in a row is gone.
                let streak = s.missing.entry(id.clone()).or_default();
                *streak += 1;
                if *streak < 2 {
                    continue;
                }
                // A container created a moment ago may not be listed yet.
                if s.containers
                    .get(&id)
                    .is_some_and(|c| now_secs.saturating_sub(c.created) < 30)
                {
                    continue;
                }
                if let Some(rec) = s.containers.remove(&id) {
                    freed.extend(release_unreferenced(s, &rec.pins));
                    changed = true;
                }
                s.execs.retain(|_, (_, c)| *c != id);
            }
            let (n0, v0) = (s.networks.len(), s.volumes.len());
            s.networks
                .retain(|id, n| networks.contains(id) || now_secs.saturating_sub(n.created) < 30);
            // A volume the engine does not list yet may be one whose create is
            // still pending: its record stays (`pending_volumes`) whatever its age.
            s.volumes.retain(|name, v| {
                volumes.contains(name)
                    || pending_volumes.contains(name)
                    || now_secs.saturating_sub(v.created) < 30
            });
            changed |= n0 != s.networks.len() || v0 != s.volumes.len();
            let live: Vec<String> = s.containers.values().flat_map(|c| c.pins.clone()).collect();
            let orphans: Vec<String> = s
                .pins
                .iter()
                .filter(|(id, p)| !live.contains(id) && now_secs.saturating_sub(p.created) > 120)
                .map(|(id, _)| id.clone())
                .collect();
            for id in orphans {
                if let Some(p) = s.pins.remove(&id) {
                    freed.push((id, p));
                    changed = true;
                }
            }
            (freed, changed)
        })
    }
}

fn release_unreferenced(s: &mut State, ids: &[String]) -> Vec<(String, PinRec)> {
    let live: Vec<String> = s
        .containers
        .values()
        .flat_map(|c| c.pins.iter().cloned())
        .collect();
    let mut freed = Vec::new();
    for id in ids {
        if live.contains(id) {
            continue;
        }
        if let Some(rec) = s.pins.remove(id) {
            freed.push((id.clone(), rec));
        }
    }
    freed
}

/// Take the exclusive lock that serializes every writer of the ledger at
/// `path`, across processes. The kernel drops it when the holder dies.
fn lock_file(path: &Path) -> std::io::Result<std::fs::File> {
    lock_exclusive(
        &path.with_extension("lock"),
        std::time::Duration::from_secs(10),
    )
}

fn lock_exclusive(lock: &Path, wait: std::time::Duration) -> std::io::Result<std::fs::File> {
    use rustix::fs::{FlockOperation, flock};
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock)?;
    let deadline = std::time::Instant::now() + wait;
    loop {
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(file),
            Err(rustix::io::Errno::WOULDBLOCK) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// `held` if the file is the one it last saw; otherwise what another process
/// published since. Call with the lock held.
fn fresh(path: &Path, held: &State) -> std::io::Result<State> {
    let sig = file_sig(path);
    if sig == held.seen || sig.is_none() {
        return Ok(held.clone());
    }
    let mut state = parse_state(&std::fs::read(path)?).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("ledger {}: {e}", path.display()),
        )
    })?;
    state.missing.clone_from(&held.missing);
    state.execs.clone_from(&held.execs);
    state.exec_seq = held.exec_seq;
    state.seen = sig;
    Ok(state)
}

fn parse_state(bytes: &[u8]) -> Result<State, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// The first complete state in a file with bytes after it: the shape a torn
/// write by two processes leaves behind.
fn parse_first_value(bytes: &[u8]) -> Option<State> {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<State>()
        .next()?
        .ok()
}

/// Keep a copy of a ledger that did not parse, under a name nothing else uses.
fn set_aside(path: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let name = path
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    for attempt in 0..1000 {
        let kept = path.with_file_name(format!("{name}.corrupt-{}-{attempt}", now()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&kept)
        {
            Ok(mut f) => {
                f.write_all(bytes)?;
                f.sync_all()?;
                return Ok(kept);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other(
        "no free name to keep the corrupt ledger",
    ))
}

/// Temporary files of writers that died before the rename. Called under the
/// lock, when no live writer can own one.
fn sweep_temp_files(path: &Path) {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let prefix = format!("{}.", name.to_string_lossy());
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let n = entry.file_name().to_string_lossy().into_owned();
        if n.starts_with(&prefix) && n.rsplit_once('.').is_some_and(|(_, ext)| ext == "tmp") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Record a step of `persist` (tests assert their order).
#[cfg(test)]
fn step(what: &'static str) {
    STEPS.with(|steps| steps.borrow_mut().push(what));
}

#[cfg(not(test))]
fn step(_what: &'static str) {}

#[cfg(test)]
thread_local! {
    /// Make the named sync fail (tests of what a failed sync acknowledges).
    static FAIL_AT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
    static STEPS: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Keep a note of the corrupt copy and refuse protected-path work until an
/// operator removes the note.
fn write_quarantine(path: &Path, kept: &Path) -> std::io::Result<()> {
    let note = path.with_extension("quarantine");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&note)?;
    writeln!(file, "corrupt ledger kept as {}", kept.display())?;
    file.sync_all()?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Write `bytes` to `file` and make them durable.
fn write_durably(mut file: std::fs::File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    sync("sync-file", &file)
}

/// `fsync`, noted for the tests of the publishing order.
fn sync(what: &'static str, file: &std::fs::File) -> std::io::Result<()> {
    step(what);
    #[cfg(test)]
    if FAIL_AT.with(std::cell::Cell::get) == Some(what) {
        return Err(std::io::Error::other("injected sync failure"));
    }
    file.sync_all()
}

/// Publish `state`: a private temporary file, fsynced, renamed over the
/// ledger, then the directory fsynced. Call with the lock held.
fn persist(path: &Path, state: &State) -> std::io::Result<()> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let name = path
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let tmp = path.with_file_name(format!(
        "{name}.{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let published = write_durably(file, &serde_json::to_vec(state)?).and_then(|()| {
        step("rename");
        std::fs::rename(&tmp, path)
    });
    if let Err(e) = published {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Some(dir) = path.parent() {
        sync("sync-dir", &std::fs::File::open(dir)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(scope: &str, name: &str) -> ContainerRec {
        ContainerRec {
            scope: scope.into(),
            attempt: "a1".into(),
            name: Some(name.into()),
            pins: vec![],
            created: 0,
        }
    }

    fn pin(scope: &str) -> PinRec {
        PinRec {
            scope: scope.into(),
            project_root: "/p".into(),
            rel: "d".into(),
            read_only: false,
            is_dir: true,
            subs: vec![],
            dev: 0,
            ino: 0,
            created: 0,
            failed: false,
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("e3-ledger-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn scope_lookup_table() {
        let l = Ledger::in_memory();
        let a = "a".repeat(64);
        let b = "ab".repeat(32);
        l.add_container(&a, rec("base", "db")).unwrap();
        l.add_container(&b, rec("lane", "db2")).unwrap();
        assert_eq!(l.find_container("base", "db"), Lookup::Own(a.clone()));
        assert_eq!(l.find_container("base", &a), Lookup::Own(a.clone()));
        assert_eq!(l.find_container("base", "aaaa"), Lookup::Own(a.clone()));
        // Other scope's objects look exactly like missing ones, by every form.
        assert_eq!(l.find_container("lane", "db"), Lookup::Missing);
        assert_eq!(l.find_container("lane", &a), Lookup::Missing);
        assert_eq!(l.find_container("lane", "aaaa"), Lookup::Missing);
        assert_eq!(l.find_container("base", "ab"), Lookup::Missing);
    }

    #[test]
    fn pins_are_released_with_the_last_container() {
        let l = Ledger::in_memory();
        l.add_pin("p1", pin("base")).unwrap();
        let mut c1 = rec("base", "c1");
        c1.pins = vec!["p1".into()];
        let mut c2 = rec("base", "c2");
        c2.pins = vec!["p1".into()];
        l.add_container("c1", c1).unwrap();
        l.add_container("c2", c2).unwrap();
        assert_eq!(l.remove_container("c1").unwrap().len(), 0);
        let freed = l.remove_container("c2").unwrap();
        // The record comes back: the caller needs the mountpoint's type.
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].0, "p1");
        assert!(freed[0].1.is_dir);
        assert!(l.pin("p1").is_none());
    }

    #[test]
    fn a_failed_pin_blocks_every_container_that_holds_it() {
        let l = Ledger::in_memory();
        l.add_pin("p1", pin("base")).unwrap();
        let mut c = rec("base", "c1");
        c.pins = vec!["p1".into()];
        l.add_container("c1", c).unwrap();
        assert!(!l.container_has_failed_pin("c1"));
        l.set_pin_failed("p1", true).unwrap();
        assert!(l.container_has_failed_pin("c1"));
        l.set_pin_failed("p1", false).unwrap();
        assert!(!l.container_has_failed_pin("c1"));
    }

    #[test]
    fn volume_claims_never_transfer_ownership() {
        let l = Ledger::in_memory();
        assert_eq!(l.claim_volume("a", "t1", "data").unwrap(), VolumeClaim::New);
        assert_eq!(l.claim_volume("a", "t2", "data").unwrap(), VolumeClaim::Own);
        assert_eq!(
            l.claim_volume("b", "t1", "data").unwrap(),
            VolumeClaim::Foreign
        );
        assert_eq!(l.volume("a", "data"), VolumeScope::Own);
        assert_eq!(l.volume("b", "data"), VolumeScope::Foreign);
        // Only the owner can give a claim back.
        l.unclaim_volume("b", "data").unwrap();
        assert_eq!(l.volume("a", "data"), VolumeScope::Own);
        l.unclaim_volume("a", "data").unwrap();
        assert_eq!(l.volume("a", "data"), VolumeScope::Unknown);
    }

    #[test]
    fn concurrent_claims_have_exactly_one_winner() {
        let l = std::sync::Arc::new(Ledger::in_memory());
        for round in 0..200 {
            let name = format!("v{round}");
            let handles: Vec<_> = ["a", "b", "c", "d"]
                .into_iter()
                .map(|scope| {
                    let (l, name) = (l.clone(), name.clone());
                    std::thread::spawn(move || l.claim_volume(scope, "t", &name).unwrap())
                })
                .collect();
            let wins = handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|c| *c == VolumeClaim::New)
                .count();
            assert_eq!(wins, 1, "round {round}");
        }
    }

    /// A tag is the creator's; pulled images are nobody's to move; a record
    /// for an image that is gone holds nothing.
    #[test]
    fn a_tag_belongs_to_the_scope_that_created_it() {
        let rec = |scope: &str| TagRec {
            scope: scope.into(),
            created: 0,
            untag_refused: 0,
        };
        for (what, held, image, want) in [
            ("nobody, no image", None, TagImage::Absent, TagClaim::New),
            (
                "nobody, pulled image",
                None,
                TagImage::Pulled,
                TagClaim::Unowned,
            ),
            ("nobody, built here", None, TagImage::Local, TagClaim::New),
            (
                "own, image there",
                Some(rec("a")),
                TagImage::Local,
                TagClaim::Own,
            ),
            (
                "own, image gone",
                Some(rec("a")),
                TagImage::Absent,
                TagClaim::Own,
            ),
            (
                "other's, image there",
                Some(rec("b")),
                TagImage::Local,
                TagClaim::Foreign,
            ),
            (
                "other's, pulled",
                Some(rec("b")),
                TagImage::Pulled,
                TagClaim::Foreign,
            ),
            (
                "other's, image gone",
                Some(rec("b")),
                TagImage::Absent,
                TagClaim::New,
            ),
        ] {
            assert_eq!(tag_claim(held.as_ref(), "a", image), want, "{what}");
        }
    }

    #[test]
    fn released_and_stale_records_free_the_tag_table() {
        let l = Ledger::in_memory();
        for n in 0..MAX_TAGS {
            assert!(l.set_tag("dead", &format!("dead:{n}")).unwrap());
        }
        assert!(!l.set_tag("live", "new:1").unwrap(), "full");
        // Forgetting the scope keeps its tag records: they go one by one, once
        // the engine confirmed the untag, and only while still the scope's.
        l.forget_scope("dead").unwrap();
        assert_eq!(l.tag_count(), MAX_TAGS);
        assert_eq!(l.scope_tags("dead").len(), MAX_TAGS);
        assert!(!l.release_tag("live", "dead:0").unwrap(), "not its record");
        assert_eq!(l.tag_count(), MAX_TAGS);
        for name in l.scope_tags("dead") {
            assert!(l.release_tag("dead", &name).unwrap());
        }
        assert_eq!(l.tag_count(), 0);
        assert!(l.set_tag("live", "keep:1").unwrap());
        assert!(l.set_tag("live", "gone:1").unwrap());
        assert!(l.set_tag("other", "keep:2").unwrap());
        // Records of images the engine no longer has go; the others stay.
        let gone = l.retain_tags(|name, _| name.starts_with("keep:")).unwrap();
        assert_eq!(gone, 1);
        assert!(l.tag_owner("gone:1").is_none());
        assert_eq!(l.tag_owner("keep:1").map(|r| r.scope), Some("live".into()));
        assert_eq!(l.tag_owner("keep:2").map(|r| r.scope), Some("other".into()));
    }

    /// Ledgers written before the refusal count was added still load.
    #[test]
    fn a_tag_record_without_a_refusal_count_loads() {
        let rec: TagRec = serde_json::from_str(r#"{"scope":"a","created":7}"#).unwrap();
        assert_eq!((rec.scope.as_str(), rec.untag_refused), ("a", 0));
        let l = Ledger::in_memory();
        l.set_tag("a", "app:1").unwrap();
        assert_eq!(l.note_untag_refused("a", "app:1").unwrap(), 1);
        assert_eq!(l.note_untag_refused("a", "app:1").unwrap(), 2);
        assert_eq!(
            l.note_untag_refused("b", "app:1").unwrap(),
            0,
            "not its record"
        );
        l.set_tag("a", "app:1").unwrap();
        assert_eq!(
            l.note_untag_refused("a", "app:1").unwrap(),
            1,
            "a new claim restarts it"
        );
    }

    #[test]
    fn tag_records_persist_and_are_bounded() {
        let dir = scratch("tags");
        let path = dir.join("ledger.json");
        let l = Ledger::open(&path).unwrap();
        assert!(l.set_tag("a", "app:1").unwrap());
        assert_eq!(l.tag_owner("app:1").map(|r| r.scope), Some("a".into()));
        assert_eq!(
            Ledger::open(&path)
                .unwrap()
                .tag_owner("app:1")
                .map(|r| r.scope),
            Some("a".into())
        );
        let l = Ledger::in_memory();
        assert!(l.set_tag("a", "app:1").unwrap());
        for n in 1..MAX_TAGS {
            assert!(l.set_tag("a", &format!("t:{n}")).unwrap());
        }
        assert!(!l.set_tag("a", "one-too-many:1").unwrap());
        assert!(l.tag_owner("one-too-many:1").is_none());
        // A known name can still be taken over when it is stale.
        assert!(l.set_tag("b", "app:1").unwrap());
        assert_eq!(l.tag_owner("app:1").map(|r| r.scope), Some("b".into()));
    }

    /// A write that fails is reported, changes nothing in memory, stops further
    /// admissions (`degraded`) and leaves the file as it was.
    #[test]
    fn a_failed_write_is_an_error_and_changes_nothing() {
        let dir = scratch("fail");
        let path = dir.join("ledger.json");
        let l = Ledger::open(&path).unwrap();
        l.add_container("c1", rec("base", "one")).unwrap();
        assert!(!l.degraded());
        // The lock file cannot be opened: a directory is in its place.
        let lock = path.with_extension("lock");
        std::fs::remove_file(&lock).unwrap();
        std::fs::create_dir(&lock).unwrap();
        let err = l.add_container("c2", rec("base", "two")).unwrap_err();
        assert!(err.to_string().contains("cannot be saved"), "{err}");
        assert!(l.degraded());
        assert_eq!(l.find_container("base", "two"), Lookup::Missing);
        assert!(l.claim_volume("base", "t", "v").is_err());
        assert_eq!(l.volume("base", "v"), VolumeScope::Unknown);
        // Once the fault clears, reopening sees exactly what was acknowledged,
        // the next write succeeds and admission resumes.
        std::fs::remove_dir(&lock).unwrap();
        let again = Ledger::open(&path).unwrap();
        assert!(matches!(
            again.find_container("base", "one"),
            Lookup::Own(_)
        ));
        assert_eq!(again.find_container("base", "two"), Lookup::Missing);
        l.add_container("c2", rec("base", "two")).unwrap();
        assert!(!l.degraded());
        let again = Ledger::open(&path).unwrap();
        assert!(matches!(
            again.find_container("base", "two"),
            Lookup::Own(_)
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The rename that publishes the new file fails (a directory stands at the
    /// ledger's path): the same refusal, and the old state is what reopens.
    #[test]
    fn a_failed_rename_is_an_error_too() {
        let dir = scratch("rename");
        let path = dir.join("ledger.json");
        let l = Ledger::open(&path).unwrap();
        l.add_container("c1", rec("base", "one")).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let err = l.add_container("c2", rec("base", "two")).unwrap_err();
        assert!(err.to_string().contains("cannot be saved"), "{err}");
        assert!(l.degraded());
        assert_eq!(l.find_container("base", "two"), Lookup::Missing);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The write itself fails (the target is `/dev/full`): ENOSPC, the
    /// pool-full case, is an error rather than a silent short file.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_full_disk_fails_the_durable_write() {
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let err = write_durably(full, b"{}").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(28), "{err}");
    }

    /// Two agent processes (two `Ledger`s on one file) lose nothing: each
    /// change starts from what the other published.
    #[test]
    fn two_ledgers_on_one_file_keep_each_others_records() {
        let dir = scratch("two");
        let path = dir.join("ledger.json");
        let a = Ledger::open(&path).unwrap();
        let b = Ledger::open(&path).unwrap();
        a.add_container("c1", rec("base", "one")).unwrap();
        b.add_container("c2", rec("base", "two")).unwrap();
        a.add_container("c3", rec("base", "three")).unwrap();
        let again = Ledger::open(&path).unwrap();
        for id in ["c1", "c2", "c3"] {
            assert!(again.container(id).is_some(), "{id} was lost");
        }
        // The one that wrote first now sees the other's record too.
        assert!(a.container("c2").is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Writers racing on one file never tear it and never lose a record.
    #[test]
    fn racing_writers_never_tear_or_lose_the_ledger() {
        let dir = scratch("race");
        let path = dir.join("ledger.json");
        let handles: Vec<_> = (0..4)
            .map(|w| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let l = Ledger::open(&path).unwrap();
                    for i in 0..40 {
                        l.add_container(&format!("w{w}-{i}"), rec("base", &format!("n{w}-{i}")))
                            .unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let again = Ledger::open(&path).unwrap();
        assert_eq!(again.container_ids("base").len(), 160);
        let aside = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("corrupt"))
            .count();
        assert_eq!(aside, 0, "the ledger was torn");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A ledger that does not parse is kept, byte for byte, and the engine
    /// still boots on an empty one.
    #[test]
    fn an_unparseable_ledger_is_set_aside_not_deleted() {
        let dir = scratch("corrupt");
        let path = dir.join("ledger.json");
        std::fs::write(&path, b"{\"containers\": {\"c1\": {\"sco").unwrap();
        let l = Ledger::open(&path).unwrap();
        assert_eq!(l.container_ids("base").len(), 0);
        let kept: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains("ledger.json.corrupt-")
            })
            .collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(
            std::fs::read(kept[0].path()).unwrap(),
            b"{\"containers\": {\"c1\": {\"sco"
        );
        l.add_container("c2", rec("base", "two")).unwrap();
        assert!(Ledger::open(&path).unwrap().container("c2").is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The tear two writers sharing a temporary file leave behind (one whole
    /// state, then the tail of a longer one) keeps the whole state.
    #[test]
    fn a_ledger_with_a_stale_tail_keeps_its_first_state() {
        let dir = scratch("tail");
        let path = dir.join("ledger.json");
        {
            let l = Ledger::open(&path).unwrap();
            l.add_container("c1", rec("base", "one")).unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(b"\"stale\":{\"tail\":1}}");
        std::fs::write(&path, &bytes).unwrap();
        let l = Ledger::open(&path).unwrap();
        assert!(l.container("c1").is_some());
        let kept = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .find(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .expect("the torn file is kept");
        assert_eq!(std::fs::read(kept.path()).unwrap(), bytes);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A temporary file left by a writer that died is not published and does
    /// not pile up.
    #[test]
    fn a_dead_writers_temporary_file_is_swept() {
        let dir = scratch("sweep");
        let path = dir.join("ledger.json");
        std::fs::write(dir.join("ledger.json.99999.0.tmp"), b"{ half").unwrap();
        let l = Ledger::open(&path).unwrap();
        assert!(!dir.join("ledger.json.99999.0.tmp").exists());
        l.add_container("c1", rec("base", "one")).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The order that makes a published ledger durable: the temporary file's
    /// bytes, then the rename, then the directory entry. Dropping either sync,
    /// or syncing after the rename, changes this list.
    #[test]
    fn a_change_is_published_in_the_durable_order() {
        let dir = scratch("order");
        let l = Ledger::open(&dir.join("ledger.json")).unwrap();
        STEPS.with(|steps| steps.borrow_mut().clear());
        l.add_container("c1", rec("base", "one")).unwrap();
        let steps = STEPS.with(|steps| steps.borrow().clone());
        assert_eq!(steps, ["sync-file", "rename", "sync-dir"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A ledger that did not parse loses the recorded protected identities, so
    /// the agent notes that it must not trust them: `quarantined` stays true,
    /// across restarts, until an operator removes the note.
    #[test]
    fn a_corrupt_ledger_quarantines_until_an_operator_clears_it() {
        let dir = scratch("quarantine");
        let path = dir.join("ledger.json");
        {
            let l = Ledger::open(&path).unwrap();
            assert!(!l.quarantined());
            l.note_protected(
                "/p",
                &[ProtectedId {
                    name: ".git".into(),
                    dev: 1,
                    ino: 2,
                }],
            )
            .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        let l = Ledger::open(&path).unwrap();
        assert!(l.quarantined());
        assert_eq!(l.protected("/p").len(), 0, "the identities are gone");
        l.add_container("c1", rec("base", "one")).unwrap();
        drop(l);
        // The next start reads a clean file, and is still quarantined.
        assert!(Ledger::open(&path).unwrap().quarantined());
        // A salvaged older value is no better: its later records are unknown.
        let mut with_tail = std::fs::read(&path).unwrap();
        with_tail.extend_from_slice(b"garbage");
        std::fs::write(&path, with_tail).unwrap();
        let salvaged = Ledger::open(&path).unwrap();
        assert!(salvaged.quarantined());
        salvaged.add_container("c2", rec("base", "two")).unwrap();
        drop(salvaged);
        std::fs::remove_file(path.with_extension("quarantine")).unwrap();
        assert!(!Ledger::open(&path).unwrap().quarantined());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One serving agent at a time: a second waits, then fails; it opens once
    /// the first is gone.
    #[test]
    fn only_one_agent_serves_a_ledger_at_a_time() {
        let dir = scratch("exclusive");
        let path = dir.join("ledger.json");
        let wait = std::time::Duration::from_millis(100);
        let first = Ledger::open_exclusive(&path, wait).unwrap();
        let error = Ledger::open_exclusive(&path, wait).err().expect("refused");
        assert!(error.to_string().contains("another agent"), "{error}");
        // A short-lived opener (engine-up's restore) is not blocked.
        assert!(Ledger::open(&path).is_ok());
        drop(first);
        assert!(Ledger::open_exclusive(&path, wait).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A sync that fails is an error, never an acknowledged change: nothing is
    /// adopted in memory and the ledger is degraded. (This checks that sync
    /// errors are honored; there is no test that the real `fsync` is issued.)
    #[test]
    fn a_failed_sync_is_not_acknowledged() {
        for failing in ["sync-file", "sync-dir"] {
            let dir = scratch(failing);
            let l = Ledger::open(&dir.join("ledger.json")).unwrap();
            FAIL_AT.with(|f| f.set(Some(failing)));
            let result = l.add_container("c1", rec("base", "one"));
            FAIL_AT.with(|f| f.set(None));
            assert!(result.is_err(), "{failing}");
            assert!(l.degraded(), "{failing}");
            assert_eq!(
                l.find_container("base", "one"),
                Lookup::Missing,
                "{failing}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// A job that runs `docker exec` forever does not grow the ledger: execs
    /// are bounded per container, and never written to the file.
    #[test]
    fn execs_are_bounded_and_not_persisted() {
        let dir = scratch("execs");
        let path = dir.join("ledger.json");
        let l = Ledger::open(&path).unwrap();
        l.add_container("db", rec("base", "db")).unwrap();
        l.add_container("web", rec("base", "web")).unwrap();
        l.add_exec("web-exec", "web");
        let before = std::fs::metadata(&path).unwrap().len();
        for i in 0..(MAX_EXECS_PER_CONTAINER * 4) {
            l.add_exec(&format!("exec-{i}"), "db");
        }
        l.add_container("late", rec("base", "late")).unwrap();
        let after = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&after).contains("exec-"));
        assert!(
            after.len() as u64 - before < 400,
            "the file grew with execs"
        );
        let last = MAX_EXECS_PER_CONTAINER * 4 - 1;
        assert_eq!(
            l.exec_container("base", &format!("exec-{last}")),
            Lookup::Own("db".into())
        );
        assert_eq!(l.exec_container("base", "exec-0"), Lookup::Missing);
        let kept = (0..=last)
            .filter(|i| l.exec_container("base", &format!("exec-{i}")) != Lookup::Missing)
            .count();
        assert_eq!(kept, MAX_EXECS_PER_CONTAINER);
        // Another container's exec is not evicted by this one's churn, and is
        // still scoped.
        assert_eq!(
            l.exec_container("base", "web-exec"),
            Lookup::Own("web".into())
        );
        assert_eq!(l.exec_container("lane", "web-exec"), Lookup::Missing);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Execs live only in memory, so a reload of what another process
    /// published must keep this process's own.
    #[test]
    fn a_reload_keeps_this_agents_execs() {
        let dir = scratch("exec-reload");
        let path = dir.join("ledger.json");
        let a = Ledger::open(&path).unwrap();
        let b = Ledger::open(&path).unwrap();
        a.add_container("db", rec("base", "db")).unwrap();
        a.add_exec("exec-1", "db");
        b.add_container("web", rec("base", "web")).unwrap();
        // A's next change starts from B's file.
        a.add_container("late", rec("base", "late")).unwrap();
        assert!(a.container("web").is_some(), "the reload happened");
        assert_eq!(
            a.exec_container("base", "exec-1"),
            Lookup::Own("db".into()),
            "the reload dropped the exec"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
