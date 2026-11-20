//! Per-daemon ownership map of stock VMs this daemon created, plus a cached
//! stock inventory view. The map is the only source of a VM's name.
//!
//! Assumptions: host `sbx` is trusted, and every name is a fixed prefix plus a
//! random 8-character base36 id, so a name this daemon chose is not reused by
//! anyone else.
//!
//! Rules:
//! - Names are looked up by `(purpose, key)`; a missing entry gets a fresh
//!   random name persisted as an *intent* (no UUID) before `sbx create`.
//! - After create the observed UUID is recorded. An intent whose name later
//!   appears in inventory is adopted. An intent whose name is absent is never
//!   dropped: an `sbx create` outlives the daemon that submitted it (its CLI
//!   child, or the request inside sandboxd), so no timer proves it will not
//!   land. A later use of the same `(purpose, key)` reuses the name.
//! - A VM is usable only if its name exists with the recorded UUID. A name
//!   present with a different UUID, or not in the map, is foreign: refuse.
//! - Stop/remove only ever target a recorded UUID that is currently present.
//!   Removal drops the entry, so the next use gets a new random name, except
//!   that a replacement created under a just-removed name keeps it
//!   (`restore_intent`), and `record` restores a retired name's purpose/key.
//!
//! The inventory view is refreshed (one `sbx ls --json`) only on cold start,
//! after a lifecycle change, or after a failure. Warm requests use the cache.
//!
//! A test scope may also name a mirror file outside its control home: every
//! write of the map (intents included, so before any create) is copied there
//! first, so the map outlives a deleted scope directory (`make check-gc`).

use super::{SbxError, StockInventory};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// Purpose recorded for VMs created by a daemon before purposes existed or
/// recorded without a lookup key.
const UNKEYED: &str = "unkeyed";
/// A VM retired for good (a `marsh workers stop` that did not settle, or a
/// VM the removed `marsh --dev` left, see `retire_dev_vms`): never
/// looked up, prepared or admitted again, and removed as soon as possible,
/// also by the next daemon. The purpose keeps the file schema (and an older
/// marsh) unchanged: an unknown purpose is never looked up by any marsh.
const RETIRED: &str = "retired";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum VmClass {
    Absent,
    Owned { uuid: String, running: bool },
    Foreign,
}

/// What an owned VM is for. The prefix is part of the random name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmPurpose {
    Kit,
    Shell,
    /// A project's services VM (`docs/design/services.md`), keyed by the
    /// canonical project root.
    Services,
}

impl VmPurpose {
    fn label(self) -> &'static str {
        match self {
            Self::Kit => "kit",
            Self::Shell => "shell",
            Self::Services => "services",
        }
    }

    fn prefix(self) -> &'static str {
        match self {
            Self::Kit => "k-",
            Self::Shell => "s-",
            Self::Services => "v-",
        }
    }
}

/// Name prefix for VMs this daemon creates: `marsh-` by default.
/// `MARSH_VM_PREFIX` (e.g. `marsh-xab12c-`) keeps one daemon's names apart
/// from another's, as cloud and the services end-to-end harnesses do.
pub fn vm_prefix() -> &'static str {
    static PREFIX: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PREFIX.get_or_init(|| {
        std::env::var("MARSH_VM_PREFIX")
            .ok()
            .filter(|value| valid_vm_prefix(value))
            .unwrap_or_else(|| "marsh-".to_owned())
    })
}

/// `marsh-` followed by zero or more `x<5 base36>-` segments.
#[must_use]
pub fn valid_vm_prefix(value: &str) -> bool {
    let Some(mut rest) = value.strip_prefix("marsh-") else {
        return false;
    };
    while !rest.is_empty() {
        let bytes = rest.as_bytes();
        if bytes.len() < 7
            || bytes[0] != b'x'
            || bytes[6] != b'-'
            || !bytes[1..6]
                .iter()
                .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase())
        {
            return false;
        }
        rest = &rest[7..];
    }
    true
}

/// A `marsh --dev` grant an older daemon left in the map: only the names of
/// the VMs its child daemon created (`name -> uuid`, `None` = intent) are
/// read. Every other historical field is accepted and ignored.
#[derive(Default, Deserialize)]
struct LegacyGrant {
    #[serde(default)]
    names: BTreeMap<String, Option<String>>,
}

/// One `marsh kit install` attempt that chose this entry's name and has not
/// published its command (`docs/model/KitInstall.tla`, rule 6). It lives in
/// the entry, so retiring the name (removing the VM and forgetting the
/// entry) ends it in the same write, and it survives a restart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRecord {
    /// Unique per attempt, never reused (a random UUID).
    pub attempt: String,
    /// The command name the install was registering.
    pub command: String,
}

impl InstallRecord {
    /// A new attempt of `command` with a fresh random id: never reused, also
    /// across a daemon restart, so no attempt overwrites a persisted record.
    #[must_use]
    pub fn new_attempt(command: &str) -> Self {
        Self {
            attempt: uuid::Uuid::new_v4().to_string(),
            command: command.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    purpose: String,
    key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uuid: Option<String>,
    /// Install attempts recorded under this name (several attempts may name
    /// one VM). Persisted in the records file next to the map
    /// ([`installs_path`]), never in the map: the map stays schema 2, which
    /// an older marsh reads. (A map an earlier build of this change wrote,
    /// schema 3 with records inline, is still read.)
    #[serde(default, skip_serializing)]
    installs: Vec<InstallRecord>,
}

const VERSION: u32 = 2;
/// Read only: the schema an earlier build of this change wrote.
const VERSION_WITH_INSTALLS: u32 = 3;

/// The install records file: `name -> records`, next to the map. A record
/// whose name is not an entry of the map is ended: it is dropped when the
/// files are read, so a name an older marsh retired takes its records along.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallsFile {
    version: u32,
    installs: BTreeMap<String, Vec<InstallRecord>>,
}

/// The bytes last written in full of (the map, its records file).
type OnDisk = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Where the install records of the map at `map` are kept.
fn installs_path(map: &Path) -> PathBuf {
    map.with_file_name(format!(
        "{}-installs.json",
        map.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("vm-ownership")
    ))
}

/// The records file's records, attached to the entries they name.
fn read_installs(map: &Path, entries: &mut BTreeMap<String, Entry>) -> Result<(), SbxError> {
    let path = installs_path(map);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err(SbxError::HostGrantFence(format!(
                    "install records {} are not an owner-only regular file",
                    path.display()
                )));
            }
            let file: InstallsFile = serde_json::from_slice(&fs::read(&path)?)?;
            for (name, records) in file.installs {
                if let Some(entry) = entries.get_mut(&name) {
                    for record in records {
                        if !entry.installs.contains(&record) {
                            entry.installs.push(record);
                        }
                    }
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnershipFile {
    version: u32,
    vms: BTreeMap<String, Entry>,
    /// Read only, to retire what `marsh --dev` left (`retire_dev_vms`).
    #[serde(default, skip_serializing)]
    grants: BTreeMap<String, LegacyGrant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyOwnershipFile {
    version: u32,
    vms: BTreeMap<String, String>,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<String, Entry>,
    /// Purpose/key of names removed in this process. A caller still holding
    /// such a name (e.g. the daemon's fixed shell spec) that recreates it
    /// keeps its lookup identity instead of becoming unkeyed.
    retired: BTreeMap<String, Entry>,
}

/// What a failed write must put back: the maps a mutation changes.
type Snapshot = (BTreeMap<String, Entry>, BTreeMap<String, Entry>);

impl State {
    fn snapshot(&self) -> Snapshot {
        (self.entries.clone(), self.retired.clone())
    }

    fn restore(&mut self, (entries, retired): Snapshot) {
        self.entries = entries;
        self.retired = retired;
    }
}

pub(crate) struct VmOwnership {
    path: Option<PathBuf>,
    mirror: Option<PathBuf>,
    state: Mutex<State>,
    view: Mutex<Option<Arc<StockInventory>>>,
    /// Whether the last [`Self::persist`] got as far as renaming the new map
    /// into place. From then on the disk holds the new state whatever a later
    /// step (the directory sync) reports, so a rollback must not restore the
    /// old memory: memory would then disagree with what a restart reads.
    published: AtomicBool,
    /// A write was published but its directory sync failed: the map is on disk
    /// but not known durable. No ownership authority is handed out again until
    /// a later write succeeds in full (see [`Self::make_durable`]).
    undurable: AtomicBool,
    /// The bytes of the map and of its records file as last written in full
    /// (renamed and synced): a write whose bytes are unchanged is skipped,
    /// so a record write touches only the records file. `None`: unknown.
    on_disk: Mutex<OnDisk>,
}

/// Directories whose syncs fail (tests). Keyed by directory, so a test fails only
/// its own temp directory's map, on whichever thread syncs it (a create may run
/// on a scoped thread), and tests running side by side in one process do not
/// disturb each other.
#[cfg(test)]
static FAILING_SYNC_DIRECTORIES: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

/// While alive, every directory sync of `directory` fails. Dropped on a panic
/// too, so a failing test cannot leave the failpoint set.
#[cfg(test)]
pub(crate) struct FailDirectorySync(PathBuf);

#[cfg(test)]
impl FailDirectorySync {
    pub(crate) fn in_dir(directory: &Path) -> Self {
        FAILING_SYNC_DIRECTORIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(directory.to_owned());
        Self(directory.to_owned())
    }
}

#[cfg(test)]
impl Drop for FailDirectorySync {
    fn drop(&mut self) {
        let mut directories = FAILING_SYNC_DIRECTORIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(index) = directories.iter().position(|d| d == &self.0) {
            directories.remove(index);
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Directory syncs attempted on this thread, and whether to fail them.
    pub(crate) static DIRECTORY_SYNCS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// Fail every directory sync once this many have been attempted.
    pub(crate) static FAIL_SYNCS_FROM: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

fn sync_directory(parent: &Path) -> Result<(), SbxError> {
    #[cfg(test)]
    {
        DIRECTORY_SYNCS.with(|count| count.set(count.get() + 1));
        let attempted = DIRECTORY_SYNCS.with(std::cell::Cell::get);
        if FAILING_SYNC_DIRECTORIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|failing| failing == parent)
            || FAIL_SYNCS_FROM
                .with(std::cell::Cell::get)
                .is_some_and(|from| attempted >= from)
        {
            return Err(std::io::Error::other("injected directory sync failure").into());
        }
    }
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn write_atomically(
    path: &Path,
    bytes: &[u8],
    published: Option<&AtomicBool>,
) -> Result<(), SbxError> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let _ = fs::remove_file(&temporary);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    if let Some(published) = published {
        published.store(true, Ordering::Release);
    }
    // The rename itself is only durable once its directory is: without this a
    // power loss can bring back the old map, losing an intent persisted
    // "before create".
    // A bare relative file name has the empty parent: the working directory.
    if let Some(parent) = path.parent() {
        sync_directory(if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        })?;
    }
    Ok(())
}

/// `marsh --dev` was removed. Mark what it left retired, so the retired-VM
/// pass removes it by recorded UUID: each VM a dev grant's child daemon
/// created (under a random grant prefix that an earlier daemon of this map
/// chose and recorded), and the dev shell VM. Returns whether anything
/// changed.
fn retire_dev_vms(
    entries: &mut BTreeMap<String, Entry>,
    grants: BTreeMap<String, LegacyGrant>,
) -> bool {
    let mut changed = !grants.is_empty();
    for (name, uuid) in grants.into_values().flat_map(|grant| grant.names) {
        entries.entry(name).or_insert_with(|| Entry {
            purpose: RETIRED.into(),
            key: String::new(),
            uuid,
            installs: Vec::new(),
        });
    }
    for entry in entries.values_mut() {
        if entry.purpose == VmPurpose::Shell.label() && entry.key == "dev" {
            entry.purpose = RETIRED.into();
            changed = true;
        }
    }
    changed
}

/// Fresh random name: fixed prefix plus 8 lowercase base36 characters.
pub(crate) fn random_vm_name(purpose: VmPurpose) -> String {
    const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut value = u128::from_le_bytes(*uuid::Uuid::new_v4().as_bytes());
    let mut name = format!("{}{}", vm_prefix(), purpose.prefix());
    for _ in 0..8 {
        name.push(char::from(ALPHABET[(value % 36) as usize]));
        value /= 36;
    }
    name
}

impl VmOwnership {
    pub(crate) fn in_memory() -> Self {
        Self {
            path: None,
            mirror: None,
            state: Mutex::new(State::default()),
            view: Mutex::new(None),
            published: AtomicBool::new(false),
            undurable: AtomicBool::new(false),
            on_disk: Mutex::new((None, None)),
        }
    }

    /// Load (or start) a persisted owner-only map at `path`.
    pub(crate) fn persisted(path: PathBuf) -> Result<Self, SbxError> {
        let mut grants = BTreeMap::new();
        let mut entries = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.uid() != rustix::process::geteuid().as_raw()
                    || metadata.mode() & 0o077 != 0
                {
                    return Err(SbxError::HostGrantFence(format!(
                        "VM ownership map {} is not an owner-only regular file",
                        path.display()
                    )));
                }
                let bytes = fs::read(&path)?;
                if let Ok(file) = serde_json::from_slice::<OwnershipFile>(&bytes)
                    && (file.version == VERSION || file.version == VERSION_WITH_INSTALLS)
                {
                    grants = file.grants;
                    file.vms
                } else {
                    let legacy: LegacyOwnershipFile = serde_json::from_slice(&bytes)?;
                    if legacy.version != 1 {
                        return Err(SbxError::HostGrantFence(
                            "unsupported VM ownership map version".into(),
                        ));
                    }
                    // Old deterministic names stay owned (removable) but are
                    // never looked up again: new use gets a random name.
                    legacy
                        .vms
                        .into_iter()
                        .map(|(name, uuid)| {
                            (
                                name,
                                Entry {
                                    purpose: UNKEYED.into(),
                                    key: String::new(),
                                    uuid: Some(uuid),
                                    installs: Vec::new(),
                                },
                            )
                        })
                        .collect()
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error.into()),
        };
        let migrated = retire_dev_vms(&mut entries, grants);
        let inline = entries.values().any(|entry| !entry.installs.is_empty());
        read_installs(&path, &mut entries)?;
        let ownership = Self {
            path: Some(path),
            mirror: None,
            state: Mutex::new(State {
                entries,
                retired: BTreeMap::new(),
            }),
            view: Mutex::new(None),
            published: AtomicBool::new(false),
            undurable: AtomicBool::new(false),
            on_disk: Mutex::new((None, None)),
        };
        // The records file as read: unchanged records are not written again
        // (and no file is made for none).
        {
            let state = ownership.lock();
            let loaded = Self::installs_bytes(&state)?;
            if !inline {
                ownership
                    .on_disk
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .1 = Some(loaded);
            }
        }
        if migrated || inline {
            ownership.persist(&ownership.lock())?;
        }
        Ok(ownership)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Copy every write of the map to `mirror` (in an existing owner-only
    /// directory), starting with the current map.
    pub(crate) fn with_mirror(mut self, mirror: PathBuf) -> Result<Self, SbxError> {
        let parent = mirror.parent().unwrap_or(Path::new("/"));
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(SbxError::HostGrantFence(format!(
                "VM ownership mirror directory {} is not an owner-only directory",
                parent.display()
            )));
        }
        self.mirror = Some(mirror);
        self.on_disk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0 = None;
        {
            let state = self.lock();
            self.persist(&state)?;
        }
        Ok(self)
    }

    fn installs_bytes(state: &State) -> Result<Vec<u8>, SbxError> {
        Ok(serde_json::to_vec_pretty(&InstallsFile {
            version: 1,
            installs: state
                .entries
                .iter()
                .filter(|(_, entry)| !entry.installs.is_empty())
                .map(|(name, entry)| (name.clone(), entry.installs.clone()))
                .collect(),
        })?)
    }

    fn persist(&self, state: &State) -> Result<(), SbxError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        self.published.store(false, Ordering::Release);
        let bytes = serde_json::to_vec_pretty(&OwnershipFile {
            version: VERSION,
            vms: state.entries.clone(),
            grants: BTreeMap::new(),
        })?;
        let installs = Self::installs_bytes(state)?;
        let (map_written, installs_written) = self
            .on_disk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        // The map, then its records: a record written before its name's
        // entry would be dropped at the next read, never the other way.
        // Either rename counts as published (memory then keeps the new
        // state, and the next write completes both). Unchanged bytes are not
        // written again.
        if map_written.as_ref() != Some(&bytes) {
            // The mirror is written first: it never names fewer VMs than the map.
            if let Some(mirror) = &self.mirror {
                write_atomically(mirror, &bytes, None)?;
            }
            write_atomically(path, &bytes, Some(&self.published))?;
            self.on_disk
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0 = Some(bytes);
        }
        if installs_written.as_ref() != Some(&installs) {
            write_atomically(&installs_path(path), &installs, Some(&self.published))?;
            self.on_disk
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .1 = Some(installs);
        }
        self.undurable.store(false, Ordering::Release);
        Ok(())
    }

    /// Whether the map is known durable, finishing a published-but-unsynced
    /// write first. The gate in front of every `sbx create`.
    pub(crate) fn confirm_durable(&self) -> Result<(), SbxError> {
        let state = self.lock();
        self.make_durable(&state)
    }

    /// Before answering from the map, finish a write that was published but
    /// not synced: a retry must not take the failed barrier for durable.
    fn make_durable(&self, state: &State) -> Result<(), SbxError> {
        if self.undurable.load(Ordering::Acquire) {
            self.persist(state)?;
        }
        Ok(())
    }

    /// Undo a mutation whose write failed, unless the write had already
    /// published it: then the disk holds the new state and memory keeps it.
    fn rollback(&self, state: &mut State, before: Snapshot) {
        if self.published.load(Ordering::Acquire) {
            self.undurable.store(true, Ordering::Release);
        } else {
            state.restore(before);
        }
    }

    /// Name for `(purpose, key)`. An existing entry is reused; otherwise a
    /// fresh random name is persisted as an intent before any create.
    pub(crate) fn assign(&self, purpose: VmPurpose, key: &str) -> Result<String, SbxError> {
        let mut state = self.lock();
        self.make_durable(&state)?;
        if let Some(name) = state
            .entries
            .iter()
            .find(|(_, entry)| entry.purpose == purpose.label() && entry.key == key)
            .map(|(name, _)| name.clone())
        {
            return Ok(name);
        }
        let name = loop {
            let candidate = random_vm_name(purpose);
            if !state.entries.contains_key(&candidate) {
                break candidate;
            }
        };
        let before = state.snapshot();
        state.entries.insert(
            name.clone(),
            Entry {
                purpose: purpose.label().into(),
                key: key.into(),
                uuid: None,
                installs: Vec::new(),
            },
        );
        if let Err(error) = self.persist(&state) {
            self.rollback(&mut state, before);
            return Err(error);
        }
        Ok(name)
    }

    pub(crate) fn uuid(&self, name: &str) -> Option<String> {
        self.lock()
            .entries
            .get(name)
            .and_then(|entry| entry.uuid.clone())
    }

    /// Owned names (recorded UUID) whose purpose is Kit or unkeyed legacy.
    pub(crate) fn owned_kit_names(&self) -> Vec<String> {
        self.lock()
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.uuid.is_some()
                    && (entry.purpose == VmPurpose::Kit.label()
                        || entry.purpose == UNKEYED
                        || entry.purpose == RETIRED)
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Persist that `name` is retired for good, before anything else is done
    /// with it: no later lookup returns it, and every daemon removes it.
    pub(crate) fn mark_retired(&self, name: &str) -> Result<String, SbxError> {
        let mut state = self.lock();
        let before = state.snapshot();
        let Some(entry) = state.entries.get_mut(name) else {
            return Err(SbxError::HostGrantFence(format!(
                "{name} is not recorded in the VM ownership map"
            )));
        };
        let prior = std::mem::replace(&mut entry.purpose, RETIRED.into());
        if let Err(error) = self.persist(&state) {
            self.rollback(&mut state, before);
            return Err(error);
        }
        Ok(prior)
    }

    /// Lift a [`Self::mark_retired`] mark (its stop settled): `prior` is the
    /// purpose it returned. On a failed write the VM stays retired.
    pub(crate) fn unmark_retired(&self, name: &str, prior: String) -> Result<(), SbxError> {
        let mut state = self.lock();
        let key = state.entries.get(name).map(|entry| entry.key.clone());
        // A lookup during the stop handed out a new name for the same Kit:
        // that one serves now, and this VM stays retired.
        if state.entries.iter().any(|(other, entry)| {
            other != name && entry.purpose == prior && Some(&entry.key) == key.as_ref()
        }) {
            return Err(SbxError::HostGrantFence(format!(
                "{name} was replaced while it stopped"
            )));
        }
        let before = state.snapshot();
        let Some(entry) = state.entries.get_mut(name) else {
            return Err(SbxError::HostGrantFence(format!(
                "{name} is not recorded in the VM ownership map"
            )));
        };
        entry.purpose = prior;
        if let Err(error) = self.persist(&state) {
            self.rollback(&mut state, before);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn is_retired(&self, name: &str) -> bool {
        self.lock()
            .entries
            .get(name)
            .is_some_and(|entry| entry.purpose == RETIRED)
    }

    /// Every VM marked retired, removed or not yet.
    pub(crate) fn retired_names(&self) -> Vec<String> {
        self.lock()
            .entries
            .iter()
            .filter(|(_, entry)| entry.purpose == RETIRED)
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Whether `name` is a shell VM with a recorded UUID.
    pub(crate) fn is_owned_shell(&self, name: &str) -> bool {
        self.lock()
            .entries
            .get(name)
            .is_some_and(|entry| entry.uuid.is_some() && entry.purpose == VmPurpose::Shell.label())
    }

    /// Owned services VMs (recorded UUID) as `(name, project key)`.
    pub(crate) fn owned_services(&self) -> Vec<(String, String)> {
        self.lock()
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.uuid.is_some() && entry.purpose == VmPurpose::Services.label()
            })
            .map(|(name, entry)| (name.clone(), entry.key.clone()))
            .collect()
    }

    /// Persisted shell generations, including older environment selectors.
    pub(crate) fn owned_shell_names(&self) -> Vec<String> {
        self.lock()
            .entries
            .iter()
            .filter(|(_, entry)| entry.uuid.is_some() && entry.purpose == VmPurpose::Shell.label())
            .map(|(name, _)| name.clone())
            .collect()
    }

    pub(crate) fn record(&self, name: &str, uuid: &str) -> Result<(), SbxError> {
        let mut state = self.lock();
        self.make_durable(&state)?;
        let before = state.snapshot();
        let retired = state.retired.remove(name);
        let entry = state.entries.entry(name.to_owned()).or_insert_with(|| {
            retired.unwrap_or_else(|| Entry {
                purpose: UNKEYED.into(),
                key: String::new(),
                uuid: None,
                installs: Vec::new(),
            })
        });
        if entry.uuid.as_deref() == Some(uuid) {
            return Ok(());
        }
        entry.uuid = Some(uuid.to_owned());
        if let Err(error) = self.persist(&state) {
            self.rollback(&mut state, before);
            return Err(error);
        }
        Ok(())
    }

    /// Drop the record of a VM that is gone. An intent that was never adopted
    /// (no UUID) is not a removal: its create may still land, and the intent
    /// is the only authority to clean that VM up, so it stays.
    pub(crate) fn forget(&self, name: &str) -> Result<(), SbxError> {
        let mut state = self.lock();
        if state
            .entries
            .get(name)
            .is_some_and(|entry| entry.uuid.is_none())
        {
            return Ok(());
        }
        let before = state.snapshot();
        if let Some(mut entry) = state.entries.remove(name) {
            entry.uuid = None;
            // The entry, and with it every install record naming the name,
            // leaves the persisted map in this write: retiring the name ends
            // them. Only an immediate replacement under the same name
            // (`restore_intent`) brings them back, in this process.
            state.retired.insert(name.to_owned(), entry);
            if let Err(error) = self.persist(&state) {
                self.rollback(&mut state, before);
                return Err(error);
            }
        }
        Ok(())
    }

    /// Forget `name` after a listing found nothing under it. `observed` is
    /// the UUID the map recorded for it before that listing was taken: only
    /// that VM is proven gone by it. A name still an intent, or one whose UUID
    /// was adopted since (a newer listing found a VM landing late), is kept:
    /// forgetting it would make that VM nobody's. Returns whether it forgot.
    pub(crate) fn forget_absent(
        &self,
        name: &str,
        observed: Option<&str>,
    ) -> Result<bool, SbxError> {
        let mut state = self.lock();
        let Some(entry) = state.entries.get(name) else {
            return Ok(false);
        };
        if observed.is_none() || entry.uuid.as_deref() != observed {
            return Ok(false);
        }
        let before = state.snapshot();
        if let Some(mut entry) = state.entries.remove(name) {
            entry.uuid = None;
            state.retired.insert(name.to_owned(), entry);
            if let Err(error) = self.persist(&state) {
                self.rollback(&mut state, before);
                return Err(error);
            }
        }
        Ok(true)
    }

    /// Owned Kit names with the UUID each has now, read before a listing
    /// whose absences [`Self::forget_absent`] then acts on.
    pub(crate) fn owned_kit_uuids(&self) -> Vec<(String, String)> {
        let names = self.owned_kit_names();
        let state = self.lock();
        names
            .into_iter()
            .filter_map(|name| {
                let uuid = state.entries.get(&name)?.uuid.clone()?;
                Some((name, uuid))
            })
            .collect()
    }

    /// Persist a just-forgotten name again as an intent (no UUID), before a
    /// replacement VM is created under it.
    pub(crate) fn restore_intent(&self, name: &str) -> Result<(), SbxError> {
        let mut state = self.lock();
        let before = state.snapshot();
        if let Some(entry) = state.retired.remove(name) {
            state.entries.insert(name.to_owned(), entry);
            if let Err(error) = self.persist(&state) {
                self.rollback(&mut state, before);
                return Err(error);
            }
        }
        Ok(())
    }

    /// `(name, purpose, key)` of each entry with a recorded UUID; a legacy
    /// unkeyed entry counts as a Kit VM with no key.
    pub(crate) fn recorded(&self) -> Vec<(String, VmPurpose, String)> {
        self.lock()
            .entries
            .iter()
            .filter(|(_, entry)| entry.uuid.is_some())
            .map(|(name, entry)| {
                let purpose = if entry.purpose == VmPurpose::Shell.label() {
                    VmPurpose::Shell
                } else if entry.purpose == VmPurpose::Services.label() {
                    VmPurpose::Services
                } else {
                    VmPurpose::Kit
                };
                (name.clone(), purpose, entry.key.clone())
            })
            .collect()
    }

    /// The name recorded for `(purpose, key)`, without assigning one.
    pub(crate) fn lookup(&self, purpose: VmPurpose, key: &str) -> Option<String> {
        self.lock()
            .entries
            .iter()
            .find(|(_, entry)| entry.purpose == purpose.label() && entry.key == key)
            .map(|(name, _)| name.clone())
    }

    /// Whether a create may be submitted under `name`: it is an entry of the
    /// map (an intent or a recorded VM). A persisted map (every daemon's)
    /// refuses any other name. An in-memory map (a scope-less adapter, unit
    /// tests) has no record of names given to it from outside, so there only
    /// a name it forgot is refused.
    pub(crate) fn is_live(&self, name: &str) -> bool {
        let state = self.lock();
        state.entries.contains_key(name)
            || (self.path.is_none() && !state.retired.contains_key(name))
    }

    /// The ownership key of `name`, live or forgotten in this process.
    pub(crate) fn key_of(&self, name: &str) -> Option<String> {
        let state = self.lock();
        state
            .entries
            .get(name)
            .or_else(|| state.retired.get(name))
            .map(|entry| entry.key.clone())
    }

    /// Every live Kit entry, intent or recorded, as `(name, key)`; and the
    /// recorded legacy and retired-for-good Kit VMs.
    pub(crate) fn live_kit_entries(&self) -> Vec<(String, String)> {
        self.lock()
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.purpose == VmPurpose::Kit.label()
                    || (entry.uuid.is_some()
                        && (entry.purpose == UNKEYED || entry.purpose == RETIRED))
            })
            .map(|(name, entry)| (name.clone(), entry.key.clone()))
            .collect()
    }

    /// Persist an install record under the live entry `name`. Refused when
    /// `name` is not an entry.
    pub(crate) fn begin_install(&self, name: &str, record: InstallRecord) -> Result<(), SbxError> {
        let mut state = self.lock();
        self.make_durable(&state)?;
        let before = state.snapshot();
        for entry in state.entries.values_mut() {
            entry
                .installs
                .retain(|other| other.attempt != record.attempt);
        }
        let Some(entry) = state.entries.get_mut(name) else {
            return Err(SbxError::StaleVmName(name.to_owned()));
        };
        entry.installs.push(record);
        if let Err(error) = self.persist(&state) {
            self.rollback(&mut state, before);
            return Err(error);
        }
        Ok(())
    }

    /// End the install record `attempt`, wherever it is. Returns whether it
    /// was found.
    pub(crate) fn end_install(&self, attempt: &str) -> Result<bool, SbxError> {
        let mut state = self.lock();
        let before = state.snapshot();
        let mut found = false;
        for entry in state.entries.values_mut() {
            let count = entry.installs.len();
            entry.installs.retain(|record| record.attempt != attempt);
            found |= entry.installs.len() != count;
        }
        if found && let Err(error) = self.persist(&state) {
            self.rollback(&mut state, before);
            return Err(error);
        }
        Ok(found)
    }

    /// End every record of `command` under `name` (its command was
    /// published on that VM: the registry reaches it now). Returns how many.
    pub(crate) fn end_installs_of(&self, name: &str, command: &str) -> Result<usize, SbxError> {
        let mut state = self.lock();
        let before = state.snapshot();
        let Some(entry) = state.entries.get_mut(name) else {
            return Ok(0);
        };
        let count = entry.installs.len();
        entry.installs.retain(|record| record.command != command);
        let ended = count - entry.installs.len();
        if ended > 0
            && let Err(error) = self.persist(&state)
        {
            self.rollback(&mut state, before);
            return Err(error);
        }
        Ok(ended)
    }

    /// Every install record as `(name, key, record)`.
    pub(crate) fn install_records(&self) -> Vec<(String, String, InstallRecord)> {
        self.lock()
            .entries
            .iter()
            .flat_map(|(name, entry)| {
                entry
                    .installs
                    .iter()
                    .map(|record| (name.clone(), entry.key.clone(), record.clone()))
            })
            .collect()
    }

    pub(crate) fn host_names(&self) -> BTreeSet<String> {
        self.lock().entries.keys().cloned().collect()
    }

    pub(crate) fn cached_view(&self) -> Option<Arc<StockInventory>> {
        self.view
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Store a fresh view and reconcile intents against it: adopt any intent
    /// whose random name is present. An absent intent is kept (see the rules).
    pub(crate) fn store_view(
        &self,
        inventory: StockInventory,
    ) -> Result<Arc<StockInventory>, SbxError> {
        {
            let mut state = self.lock();
            let before = state.snapshot();
            let mut changed = false;
            for (name, entry) in &mut state.entries {
                if entry.uuid.is_none()
                    && let Some(vm) = inventory.get(name)
                {
                    entry.uuid = Some(vm.id.clone());
                    changed = true;
                }
            }
            if changed && let Err(error) = self.persist(&state) {
                self.rollback(&mut state, before);
                return Err(error);
            }
        }
        let inventory = Arc::new(inventory);
        *self
            .view
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&inventory));
        Ok(inventory)
    }

    /// Drop the cached view after any lifecycle change or failure.
    pub(crate) fn invalidate(&self) {
        *self
            .view
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    pub(crate) fn classify(&self, inventory: &StockInventory, name: &str) -> VmClass {
        let recorded = self.uuid(name);
        match inventory.get(name) {
            None => VmClass::Absent,
            Some(vm) if recorded.as_deref() == Some(vm.id.as_str()) => VmClass::Owned {
                uuid: vm.id.clone(),
                // Any state but stopped may be running: a VM caught while it
                // starts or stops is never taken for stopped.
                running: vm.possibly_running(),
            },
            Some(_) => VmClass::Foreign,
        }
    }
}
