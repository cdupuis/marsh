//! The one way to change `$MARSH_HOME/config.json`: `marsh config ...` and the
//! daemon's own cleanups (`marsh docker rm --project` forgets a gone project's
//! setting) both go through [`update`].
//!
//! A change is a read-modify-write, so two writers (two processes, or two
//! threads) that each read the file, change it and rename a new copy over it
//! lose one update even though every rename is atomic. [`update`] holds an
//! exclusive `flock` on `config.json.lock`, next to the file, from the read to
//! the rename; the new copy has a name of its own, is synced, and replaces the
//! file atomically. A writer that cannot get the lock in time fails; it never
//! writes without it. Readers take no lock: they see the old file or the new
//! one, never a partial one.

use rustix::fs::{FlockOperation, Mode, OFlags};
use serde_json::{Map, Value};
use std::{
    fs,
    io::{self, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

pub const CONFIG_FILE: &str = "config.json";
const LOCK_FILE: &str = "config.json.lock";
/// How long a writer waits for another one to finish (a write takes
/// milliseconds).
pub const LOCK_WAIT: Duration = Duration::from_secs(10);

/// Why [`update`] changed nothing.
#[derive(Debug)]
pub enum ConfigError {
    /// The change was refused: the message says why (for example a list in the
    /// file that is not a list of paths).
    Rejected(String),
    /// The lock, the file or the folder could not be used.
    Io(io::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(message) => formatter.write_str(message),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Apply `change` to the document of `scope_root`'s `config.json` (empty when
/// the file is missing) under the lock, and write it back when `change` altered
/// it. Returns what `change` returns. When `change` returns an error the file
/// is left as it was.
///
/// # Errors
/// [`ConfigError::Rejected`] from `change`; [`ConfigError::Io`] when the lock
/// is not obtained within [`LOCK_WAIT`], the file is not a JSON object, or it
/// cannot be written.
pub fn update<R>(
    scope_root: &Path,
    change: impl FnOnce(&mut Map<String, Value>) -> Result<R, String>,
) -> Result<R, ConfigError> {
    update_within(scope_root, LOCK_WAIT, change)
}

/// [`update`] with a chosen wait for the lock.
///
/// # Errors
/// As [`update`].
pub fn update_within<R>(
    scope_root: &Path,
    wait: Duration,
    change: impl FnOnce(&mut Map<String, Value>) -> Result<R, String>,
) -> Result<R, ConfigError> {
    if !scope_root.exists() {
        fs::create_dir_all(scope_root)?;
        fs::set_permissions(scope_root, fs::Permissions::from_mode(0o700))?;
    }
    let _lock = lock(&scope_root.join(LOCK_FILE), wait)?;
    let path = scope_root.join(CONFIG_FILE);
    let mut document = match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<Map<String, Value>>(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Map::new(),
        Err(error) => return Err(error.into()),
    };
    let before = document.clone();
    let result = change(&mut document).map_err(ConfigError::Rejected)?;
    if document != before {
        write_atomically(scope_root, &path, &document)?;
    }
    Ok(result)
}

fn lock(path: &Path, wait: Duration) -> io::Result<rustix::fd::OwnedFd> {
    let file = rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    let deadline = Instant::now() + wait;
    loop {
        match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(file),
            Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(rustix::io::Errno::WOULDBLOCK) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "another marsh process holds {}; nothing was written (try again)",
                        path.display()
                    ),
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// A new file of its own beside `path`, synced, renamed over it. Only a file
/// this call created is ever removed.
fn write_atomically(
    scope_root: &Path,
    path: &Path,
    document: &Map<String, Value>,
) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut encoded = serde_json::to_vec_pretty(document)?;
    encoded.push(b'\n');
    let temporary = scope_root.join(format!(
        ".{CONFIG_FILE}.{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(&encoded)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return result;
    }
    // Make the rename itself durable; the data is already in place.
    if let Ok(directory) = fs::File::open(scope_root) {
        let _ = directory.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Barrier};

    fn read(root: &Path) -> Value {
        serde_json::from_slice(&fs::read(root.join(CONFIG_FILE)).unwrap()).unwrap()
    }

    fn hold(root: &Path) -> rustix::fd::OwnedFd {
        lock(&root.join(LOCK_FILE), Duration::from_secs(1)).unwrap()
    }

    /// A `marsh config shell X`-style set and a daemon-style forget of a list
    /// entry, started together on a large file, over and over: every update
    /// of every round is in the end result.
    #[test]
    fn a_set_and_a_forget_that_overlap_lose_neither_update() {
        let root = tempfile::tempdir().unwrap();
        for round in 0..20 {
            fs::write(
                root.path().join(CONFIG_FILE),
                json!({"shell": "marsh", "services_projects": ["/gone", "/kept"], "pad": "x".repeat(2 << 20)})
                    .to_string(),
            )
            .unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let set = {
                let (root, barrier) = (root.path().to_owned(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    update(&root, |document| {
                        document.insert("shell".into(), "zsh".into());
                        Ok(())
                    })
                })
            };
            let forget = {
                let (root, barrier) = (root.path().to_owned(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    update(&root, |document| {
                        if let Some(Value::Array(roots)) = document.get_mut("services_projects") {
                            roots.retain(|entry| entry != "/gone");
                        }
                        Ok(())
                    })
                })
            };
            set.join().unwrap().unwrap();
            forget.join().unwrap().unwrap();
            let document = read(root.path());
            assert_eq!(document["shell"], "zsh", "round {round}");
            assert_eq!(
                document["services_projects"],
                json!(["/kept"]),
                "round {round}"
            );
        }
    }

    /// Nothing else is left in the folder but the file and its lock.
    #[test]
    fn an_update_leaves_no_temporary_file_and_keeps_the_mode() {
        let root = tempfile::tempdir().unwrap();
        update(root.path(), |document| {
            document.insert("shell".into(), "zsh".into());
            Ok(())
        })
        .unwrap();
        let mut names = fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, ["config.json", "config.json.lock"]);
        let mode = fs::metadata(root.path().join(CONFIG_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// A change that alters nothing writes nothing; a refused change leaves
    /// the file as it was and returns the reason.
    #[test]
    fn an_unchanged_or_refused_update_does_not_write() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join(CONFIG_FILE), "{\"a\":1}").unwrap();
        update(root.path(), |_| Ok(())).unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join(CONFIG_FILE)).unwrap(),
            "{\"a\":1}"
        );
        let refused = update(root.path(), |document| {
            document.insert("a".into(), 2.into());
            Err::<(), _>("no".to_owned())
        });
        assert!(matches!(refused, Err(ConfigError::Rejected(message)) if message == "no"));
        assert_eq!(
            fs::read_to_string(root.path().join(CONFIG_FILE)).unwrap(),
            "{\"a\":1}"
        );
    }

    /// While another writer holds the lock, a writer waits; it writes after
    /// the other lets go, and never before.
    #[test]
    fn a_writer_waits_for_the_lock() {
        let root = tempfile::tempdir().unwrap();
        let held = hold(root.path());
        let writer = {
            let root = root.path().to_owned();
            std::thread::spawn(move || {
                update(&root, |document| {
                    document.insert("shell".into(), "zsh".into());
                    Ok(())
                })
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        assert!(!writer.is_finished());
        assert!(!root.path().join(CONFIG_FILE).exists());
        drop(held);
        writer.join().unwrap().unwrap();
        assert_eq!(read(root.path())["shell"], "zsh");
    }

    /// A writer that cannot get the lock in time fails, naming the cause, and
    /// does not write unlocked.
    #[test]
    fn a_writer_that_cannot_get_the_lock_fails_without_writing() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join(CONFIG_FILE), "{\"a\":1}").unwrap();
        let _held = hold(root.path());
        let error = update_within(root.path(), Duration::from_millis(100), |document| {
            document.insert("a".into(), 2.into());
            Ok(())
        })
        .unwrap_err();
        match error {
            ConfigError::Io(error) => {
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert!(error.to_string().contains("nothing was written"), "{error}");
            }
            other @ ConfigError::Rejected(_) => panic!("{other:?}"),
        }
        assert_eq!(
            fs::read_to_string(root.path().join(CONFIG_FILE)).unwrap(),
            "{\"a\":1}"
        );
    }

    /// A file that is not a JSON object is an error, never overwritten.
    #[test]
    fn an_unreadable_file_is_an_error_and_is_kept() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join(CONFIG_FILE), "{ nope").unwrap();
        let error = update(root.path(), |_| Ok(())).unwrap_err();
        assert!(
            matches!(error, ConfigError::Io(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert_eq!(
            fs::read_to_string(root.path().join(CONFIG_FILE)).unwrap(),
            "{ nope"
        );
    }
}
