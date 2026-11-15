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
    containers: BTreeMap<String, ContainerRec>,
    networks: BTreeMap<String, NetRec>,
    volumes: BTreeMap<String, VolRec>,
    /// Older ledgers have none.
    #[serde(default)]
    tags: BTreeMap<String, TagRec>,
    execs: BTreeMap<String, String>,
    pins: BTreeMap<String, PinRec>,
    scope_networks: BTreeMap<String, String>,
    /// Per project root (as the authority gave it): the `(dev, ino)` of every
    /// `.git`/`.marsh` seen there. Older ledgers have none.
    #[serde(default)]
    protected: BTreeMap<String, Vec<ProtectedId>>,
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
        }
    }

    pub fn open(path: &Path) -> std::io::Result<Self> {
        let state = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("ledger {}: {e}", path.display()),
                )
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e),
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        Ok(Self {
            path: Some(path.to_path_buf()),
            state: Mutex::new(state),
            degraded: AtomicBool::new(false),
        })
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
        let mut next = g.clone();
        let (r, changed) = f(&mut next);
        if !changed {
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
            s.execs.retain(|_, c| c != id);
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
    /// through the engine (and leave the ledger by their own removal).
    pub fn forget_scope(&self, scope: &str) -> LedgerResult<()> {
        self.mutate(|s| {
            let before = (s.sockets.len(), s.scope_networks.len());
            s.sockets.retain(|_, rec| rec.scope != scope);
            s.scope_networks.remove(scope);
            let tags = s.tags.len();
            s.tags.retain(|_, rec| rec.scope != scope);
            let changed =
                before != (s.sockets.len(), s.scope_networks.len()) || tags != s.tags.len();
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
                },
            );
            (true, true)
        })
    }

    pub fn add_exec(&self, exec: &str, container: &str) -> LedgerResult<()> {
        self.mutate(|s| {
            s.execs.insert(exec.to_string(), container.to_string());
            ((), true)
        })
    }

    #[must_use]
    pub fn exec_container(&self, scope: &str, exec: &str) -> Lookup {
        self.with(|s| {
            match s
                .execs
                .get(exec)
                .and_then(|c| s.containers.get(c).map(|r| (c, r)))
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
    pub fn reconcile(
        &self,
        containers: &[String],
        networks: &[String],
        volumes: &[String],
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
                s.execs.retain(|_, c| *c != id);
            }
            let (n0, v0) = (s.networks.len(), s.volumes.len());
            s.networks
                .retain(|id, n| networks.contains(id) || now_secs.saturating_sub(n.created) < 30);
            s.volumes.retain(|name, v| {
                volumes.contains(name) || now_secs.saturating_sub(v.created) < 30
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

fn persist(path: &Path, state: &State) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&serde_json::to_vec(state)?)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
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
    fn a_dropped_scope_and_stale_records_free_the_tag_table() {
        let l = Ledger::in_memory();
        for n in 0..MAX_TAGS {
            assert!(l.set_tag("dead", &format!("dead:{n}")).unwrap());
        }
        assert!(!l.set_tag("live", "new:1").unwrap(), "full");
        l.forget_scope("dead").unwrap();
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
        // The temporary file cannot be created: a directory is in its place.
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
        let err = l.add_container("c2", rec("base", "two")).unwrap_err();
        assert!(err.to_string().contains("cannot be saved"), "{err}");
        assert!(l.degraded());
        assert_eq!(l.find_container("base", "two"), Lookup::Missing);
        assert!(l.claim_volume("base", "t", "v").is_err());
        assert_eq!(l.volume("base", "v"), VolumeScope::Unknown);
        assert!(l.set_pin_failed("nope", true).is_ok()); // no change: no write
        // Reopening sees exactly what was acknowledged.
        let again = Ledger::open(&path).unwrap();
        assert!(matches!(
            again.find_container("base", "one"),
            Lookup::Own(_)
        ));
        assert_eq!(again.find_container("base", "two"), Lookup::Missing);
        // Once the fault clears, the next write succeeds and admission resumes.
        std::fs::remove_dir(path.with_extension("json.tmp")).unwrap();
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

    /// The write itself fails (the temporary file is `/dev/full`): ENOSPC, the
    /// pool-full case, is an error and changes nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_full_disk_is_an_error_and_changes_nothing() {
        let dir = scratch("full");
        let path = dir.join("ledger.json");
        let l = Ledger::open(&path).unwrap();
        l.add_container("c1", rec("base", "one")).unwrap();
        std::os::unix::fs::symlink("/dev/full", path.with_extension("json.tmp")).unwrap();
        let err = l.add_container("c2", rec("base", "two")).unwrap_err();
        assert!(err.to_string().contains("cannot be saved"), "{err}");
        assert_eq!(l.find_container("base", "two"), Lookup::Missing);
        std::fs::remove_file(path.with_extension("json.tmp")).unwrap();
        let again = Ledger::open(&path).unwrap();
        assert!(matches!(
            again.find_container("base", "one"),
            Lookup::Own(_)
        ));
        assert_eq!(again.find_container("base", "two"), Lookup::Missing);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
