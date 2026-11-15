//! The durable side of a freeze (Linux only): what a capture intends to pause,
//! what is confirmed thawed, and the watchdog that enforces both.
//!
//! A capture's staging directory `pool/snapshots/.tmp-<id>` holds:
//!
//! - `intent.json`: the id and the exact workspace;
//! - `journal.json`: every container the capture *may* have paused. It is
//!   written before the first pause call and grows (atomically) before any
//!   later pause, so a pause whose outcome is unknown (timeout, killed agent)
//!   is covered;
//! - `settled/<container id>`: written only after the engine has confirmed
//!   that container is not paused (or no longer exists);
//! - `alive`: a heartbeat the capture refreshes only on real progress;
//! - `revoked`: created by the watchdog or by recovery *before* they thaw
//!   anything. A capture that sees it has lost its freeze and must not publish.
//!
//! The journal is the intent to thaw. Nothing deletes it, or the staging
//! directory, until every id in it is settled; an unreadable journal counts as
//! unsettled. Capture, watchdog and startup recovery all use `thaw` and keep
//! retrying until the engine confirms.

use crate::breaks::break_mode;
use crate::engine_api::{Engine, valid_container_id};
use crate::fsops;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{Duration, Instant};

pub const INTENT: &str = "intent.json";
pub const JOURNAL: &str = "journal.json";
pub const ALIVE: &str = "alive";
pub const REVOKED: &str = "revoked";
pub const SETTLED: &str = "settled";

#[derive(Serialize, Deserialize)]
pub struct Journal {
    pub id: String,
    pub containers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Intent {
    pub id: String,
    pub workspace: String,
}

/// Rewrites the journal atomically.
///
/// # Errors
/// Fails if the file cannot be written.
pub fn write_journal(stage: &OwnedFd, id: &str, containers: &[String]) -> io::Result<()> {
    let bytes = serde_json::to_vec(&Journal {
        id: id.to_owned(),
        containers: containers.to_vec(),
    })
    .map_err(io::Error::other)?;
    fsops::replace_file_at(stage, JOURNAL, &bytes)
}

/// The journal, `None` if the capture never wrote one.
///
/// # Errors
/// An unreadable or corrupt journal is an error, never "nothing to do".
pub fn read_journal(stage: &OwnedFd) -> io::Result<Option<Journal>> {
    match fsops::read_file_at(stage, JOURNAL, 256 * 1024) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Journal ids not yet confirmed thawed.
///
/// # Errors
/// Fails if the journal is unreadable or corrupt.
pub fn unsettled(stage: &OwnedFd) -> io::Result<Vec<String>> {
    let Some(journal) = read_journal(stage)? else {
        return Ok(Vec::new());
    };
    let settled: HashSet<String> = match fsops::open_dir_at(stage, SETTLED) {
        Ok(dir) => fsops::list_names(&dir)?
            .into_iter()
            .filter_map(|name| String::from_utf8(name).ok())
            .collect(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => HashSet::new(),
        Err(error) => return Err(error),
    };
    Ok(journal
        .containers
        .into_iter()
        .filter(|id| !settled.contains(id))
        .collect())
}

fn mark_settled(stage: &OwnedFd, id: &str) -> io::Result<()> {
    let dir = match fsops::open_dir_at(stage, SETTLED) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fsops::mkdir_new(stage, SETTLED) {
                Ok(dir) => dir,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    fsops::open_dir_at(stage, SETTLED)?
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    };
    match fsops::write_new_file_at(&dir, id, b"") {
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => Err(error),
        _ => Ok(()),
    }
}

#[must_use]
pub fn is_revoked(stage: &OwnedFd) -> bool {
    fsops::exists_at(stage, REVOKED)
}

/// Marks the freeze as lost. Idempotent.
pub fn revoke(stage: &OwnedFd) {
    let _ = fsops::write_new_file_at(stage, REVOKED, b"");
}

/// One container: true once the engine says it is not paused (or is gone).
fn thaw_one(engine: &Engine, id: &str) -> bool {
    match engine.is_paused(id) {
        Ok(false) => true,
        Err(error) if error.is_not_found() => true,
        Ok(true) => {
            let _ = engine.unpause(id);
            match engine.is_paused(id) {
                Ok(false) => true,
                Err(error) => error.is_not_found(),
                Ok(true) => false,
            }
        }
        Err(_) => false,
    }
}

/// Thaws every unsettled id, up to `attempts` passes (100 ms apart), writing a
/// settled marker per confirmed container. Returns the ids still unsettled:
/// engine errors, timeouts and "still paused" all leave an id unsettled.
///
/// # Errors
/// Fails if the journal cannot be read.
pub fn thaw(engine: &Engine, stage: &OwnedFd, attempts: u32) -> io::Result<Vec<String>> {
    let mut remaining = unsettled(stage)?;
    for attempt in 0..attempts.max(1) {
        if remaining.is_empty() {
            break;
        }
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(100));
        }
        let mut still = Vec::new();
        for chunk in remaining.chunks(32) {
            let results: Vec<(String, bool)> = std::thread::scope(|scope| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|id| scope.spawn(move || (id.clone(), thaw_one(engine, id))))
                    .collect();
                handles.into_iter().filter_map(|h| h.join().ok()).collect()
            });
            for (id, settled) in results {
                if settled && valid_container_id(&id) && mark_settled(stage, &id).is_ok() {
                    continue;
                }
                still.push(id);
            }
        }
        remaining = still;
    }
    Ok(remaining)
}

/// `capture-watchdog --engine-socket S --dir D --bound-ms N`: the independent
/// timer, a separate process that outlives a killed or hung agent.
///
/// While the journal has unsettled ids it watches the heartbeat. When the
/// heartbeat is older than the bound it first creates `revoked` (so the capture
/// can no longer publish), then thaws, and keeps retrying every 100 ms until the
/// engine has confirmed every container. It exits when nothing is unsettled.
/// `D` is built by the agent from a validated id.
#[must_use]
pub fn watchdog_main(args: &[String]) -> i32 {
    let mut socket = None;
    let mut dir = None;
    let mut bound_ms = 3000_u64;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        match (flag.as_str(), iter.next()) {
            ("--engine-socket", Some(v)) => socket = Some(v.clone()),
            ("--dir", Some(v)) => dir = Some(std::path::PathBuf::from(v)),
            ("--bound-ms", Some(v)) => bound_ms = v.parse().unwrap_or(bound_ms),
            #[cfg(feature = "test-breaks")]
            ("--break-modes", Some(v)) => crate::breaks::install(
                &v.split(',')
                    .filter(|mode| !mode.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            ),
            _ => return 2,
        }
    }
    let (Some(socket), Some(dir)) = (socket, dir) else {
        return 2;
    };
    let Ok(stage) = fsops::open_dir_by_path(&dir) else {
        return 0;
    };
    let engine = Engine::new(socket);
    let bound = Duration::from_millis(bound_ms);
    let started = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(100));
        match unsettled(&stage) {
            Ok(ids) if ids.is_empty() => return 0,
            Ok(_) => {}
            // An unreadable journal is never "done"; keep looking.
            Err(_) => continue,
        }
        let age = heartbeat_age(&dir);
        let overdue = age.map_or(started.elapsed() > bound, |age| age > bound);
        if !overdue && !is_revoked(&stage) {
            continue;
        }
        revoke(&stage);
        let _ = thaw(&engine, &stage, 1);
        if break_mode("watchdog-discard-journal") {
            // Deliberately wrong (a break mode): give up after one attempt.
            let _ = fsops::remove_file_at(&stage, JOURNAL);
            return 0;
        }
    }
}

fn heartbeat_age(dir: &Path) -> Option<Duration> {
    std::fs::metadata(dir.join(ALIVE))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    /// What the fake engine does for one container.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Mode {
        Paused,
        Running,
        Gone,
        /// Accepts `unpause` and stays paused.
        Stuck,
        /// Answers 500 to everything.
        Broken,
    }

    /// A small engine on a unix socket: inspect (`State.Paused`) and unpause,
    /// per container, with every request recorded.
    struct FakeEngine {
        socket: PathBuf,
        state: Arc<Mutex<HashMap<String, Mode>>>,
        log: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        /// Whether `revoked` already existed when the first unpause arrived.
        revoked_first: Arc<Mutex<Option<bool>>>,
    }

    impl FakeEngine {
        fn start(dir: &Path, containers: &[(&str, Mode)]) -> Self {
            let socket = dir.join("engine.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let state: Arc<Mutex<HashMap<String, Mode>>> = Arc::new(Mutex::new(
                containers
                    .iter()
                    .map(|(id, mode)| ((*id).to_owned(), *mode))
                    .collect(),
            ));
            let log = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let revoked_first = Arc::new(Mutex::new(None));
            let (state2, log2, stop2) = (state.clone(), log.clone(), stop.clone());
            let (revoked2, dir2) = (revoked_first.clone(), dir.to_path_buf());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop2.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Ok(stream) = stream {
                        let (state, log) = (state2.clone(), log2.clone());
                        let (revoked, dir) = (revoked2.clone(), dir2.clone());
                        std::thread::spawn(move || serve(stream, &state, &log, (&revoked, &dir)));
                    }
                }
            });
            Self {
                socket,
                state,
                log,
                stop,
                revoked_first,
            }
        }

        fn engine(&self) -> Engine {
            Engine::new(&self.socket)
        }

        fn set(&self, id: &str, mode: Mode) {
            self.state.lock().unwrap().insert(id.to_owned(), mode);
        }

        fn mode(&self, id: &str) -> Mode {
            self.state.lock().unwrap()[id]
        }

        fn requests(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    impl Drop for FakeEngine {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = UnixStream::connect(&self.socket);
        }
    }

    fn serve(
        stream: UnixStream,
        state: &Mutex<HashMap<String, Mode>>,
        log: &Mutex<Vec<String>>,
        probe: (&Mutex<Option<bool>>, &Path),
    ) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut first = String::new();
        if reader.read_line(&mut first).unwrap_or(0) == 0 {
            return;
        }
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
        }
        let mut words = first.split_whitespace();
        let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
        log.lock().unwrap().push(format!("{method} {path}"));
        if method == "POST" && path.ends_with("/unpause") {
            probe
                .0
                .lock()
                .unwrap()
                .get_or_insert_with(|| probe.1.join(REVOKED).exists());
        }
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let (code, body) = match (method, parts.as_slice()) {
            (_, ["containers", id, action, ..]) => {
                let mut state = state.lock().unwrap();
                match (state.get(*id).copied(), method, *action) {
                    (None | Some(Mode::Gone), ..) => {
                        (404, r#"{"message":"No such container"}"#.to_owned())
                    }
                    (Some(Mode::Broken), ..) => (500, r#"{"message":"engine error"}"#.to_owned()),
                    (Some(mode), "GET", "json") => (
                        200,
                        format!(
                            r#"{{"State":{{"Paused":{}}}}}"#,
                            matches!(mode, Mode::Paused | Mode::Stuck)
                        ),
                    ),
                    (Some(mode), "POST", "unpause") => {
                        if mode == Mode::Paused {
                            state.insert((*id).to_owned(), Mode::Running);
                        }
                        (204, String::new())
                    }
                    _ => (400, String::new()),
                }
            }
            _ => (404, String::new()),
        };
        let mut stream = stream;
        let _ = write!(
            stream,
            "HTTP/1.0 {code} X\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("freeze-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn stage(dir: &Path, journal: &[&str]) -> OwnedFd {
        let stage = fsops::open_dir_by_path(dir).unwrap();
        let ids: Vec<String> = journal.iter().map(|id| (*id).to_owned()).collect();
        write_journal(&stage, "snap", &ids).unwrap();
        stage
    }

    fn settled_ids(dir: &Path) -> Vec<String> {
        let mut ids: Vec<String> = std::fs::read_dir(dir.join(SETTLED))
            .map(|entries| {
                entries
                    .map(|e| e.unwrap().file_name().into_string().unwrap())
                    .collect()
            })
            .unwrap_or_default();
        ids.sort();
        ids
    }

    #[test]
    fn a_journal_round_trips_and_a_bad_one_is_never_nothing_to_do() {
        let dir = scratch("journal");
        let stage = fsops::open_dir_by_path(&dir).unwrap();
        assert!(read_journal(&stage).unwrap().is_none());
        assert_eq!(unsettled(&stage).unwrap().len(), 0);

        write_journal(&stage, "snap", &[A.to_owned(), B.to_owned()]).unwrap();
        let journal = read_journal(&stage).unwrap().unwrap();
        assert_eq!((journal.id.as_str(), journal.containers.len()), ("snap", 2));
        // It grows atomically: the next write replaces the whole file.
        write_journal(&stage, "snap", &[A.to_owned(), B.to_owned(), C.to_owned()]).unwrap();
        assert_eq!(unsettled(&stage).unwrap(), [A, B, C]);

        // Unreadable, corrupt, oversized and linked journals are errors: a
        // capture whose journal cannot be read still has things to thaw.
        for bad in [
            b"{ not json".to_vec(),
            vec![b' '; 256 * 1024 + 1],
            br#"{"id":"snap"}"#.to_vec(),
        ] {
            std::fs::write(dir.join(JOURNAL), &bad).unwrap();
            assert!(read_journal(&stage).is_err());
            assert!(unsettled(&stage).is_err());
        }
        std::fs::remove_file(dir.join(JOURNAL)).unwrap();
        std::fs::write(dir.join("elsewhere"), br#"{"id":"x","containers":[]}"#).unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join(JOURNAL)).unwrap();
        assert!(read_journal(&stage).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The freeze is over only for containers the engine confirmed: paused ones
    /// that unpause, running ones, and removed ones. A stuck container and an
    /// engine error stay unsettled, and a later pass finishes the job.
    #[test]
    fn thaw_settles_only_what_the_engine_confirmed() {
        let dir = scratch("thaw");
        let engine = FakeEngine::start(
            &dir,
            &[
                (A, Mode::Paused),
                (B, Mode::Running),
                (C, Mode::Gone),
                (D, Mode::Stuck),
                (E, Mode::Broken),
            ],
        );
        let stage = stage(&dir, &[A, B, C, D, E]);

        let left = thaw(&engine.engine(), &stage, 2).unwrap();
        let mut left_sorted = left.clone();
        left_sorted.sort();
        assert_eq!(left_sorted, [D, E]);
        assert_eq!(settled_ids(&dir), [A, B, C]);
        assert_eq!(engine.mode(A), Mode::Running);
        let mut pending = unsettled(&stage).unwrap();
        pending.sort();
        assert_eq!(pending, [D, E]);
        // Settled ones are not asked about again.
        let before = engine.requests().iter().filter(|r| r.contains(A)).count();
        engine.set(D, Mode::Paused);
        engine.set(E, Mode::Paused);
        assert_eq!(thaw(&engine.engine(), &stage, 2).unwrap().len(), 0);
        assert_eq!(settled_ids(&dir), [A, B, C, D, E]);
        assert_eq!(
            engine.requests().iter().filter(|r| r.contains(A)).count(),
            before
        );
        assert_eq!(unsettled(&stage).unwrap().len(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A journal entry that is not a container id is never sent to the engine
    /// and never written as a marker (the id becomes a path component).
    #[test]
    fn thaw_never_uses_a_journal_entry_that_is_not_a_container_id() {
        let dir = scratch("badid");
        let engine = FakeEngine::start(&dir, &[(A, Mode::Paused)]);
        let stage = stage(&dir, &["../escape", "abc", A]);
        let left = thaw(&engine.engine(), &stage, 1).unwrap();
        assert_eq!(left, ["../escape", "abc"]);
        assert_eq!(settled_ids(&dir), [A]);
        assert!(!dir.join("escape").exists());
        assert!(
            engine
                .requests()
                .iter()
                .all(|request| !request.contains("escape") && !request.contains("abc")),
            "{:?}",
            engine.requests()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn revoking_is_idempotent_and_visible() {
        let dir = scratch("revoke");
        let stage = fsops::open_dir_by_path(&dir).unwrap();
        assert!(!is_revoked(&stage));
        revoke(&stage);
        revoke(&stage);
        assert!(is_revoked(&stage));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn watchdog(engine: &FakeEngine, dir: &Path, bound_ms: u64) -> std::thread::JoinHandle<i32> {
        let args = [
            "--engine-socket".to_owned(),
            engine.socket.display().to_string(),
            "--dir".to_owned(),
            dir.display().to_string(),
            "--bound-ms".to_owned(),
            bound_ms.to_string(),
        ];
        std::thread::spawn(move || watchdog_main(&args))
    }

    /// With no heartbeat past the bound, the watchdog revokes first, then
    /// thaws, and exits only once everything is confirmed.
    #[test]
    fn the_watchdog_revokes_then_thaws_when_the_heartbeat_is_overdue() {
        let dir = scratch("watchdog");
        let engine = FakeEngine::start(&dir, &[(A, Mode::Paused), (B, Mode::Stuck)]);
        let stage = stage(&dir, &[A, B]);
        let handle = watchdog(&engine, &dir, 200);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !is_revoked(&stage) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(is_revoked(&stage), "the capture was never told");
        // B is stuck: the watchdog keeps retrying and does not exit.
        std::thread::sleep(Duration::from_millis(500));
        assert!(!handle.is_finished());
        assert_eq!(engine.mode(A), Mode::Running);
        engine.set(B, Mode::Paused);
        assert_eq!(handle.join().unwrap(), 0);
        // Revoked before the first thaw: a capture that still publishes while
        // its containers are being thawed would publish an inconsistent copy.
        assert_eq!(*engine.revoked_first.lock().unwrap(), Some(true));
        assert_eq!(settled_ids(&dir), [A, B]);
        assert_eq!(unsettled(&stage).unwrap().len(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A fresh heartbeat holds the watchdog off.
    #[test]
    fn the_watchdog_leaves_a_live_capture_alone() {
        let dir = scratch("alive");
        let engine = FakeEngine::start(&dir, &[(A, Mode::Paused)]);
        let stage = stage(&dir, &[A]);
        std::fs::write(dir.join(ALIVE), b"").unwrap();
        let handle = watchdog(&engine, &dir, 60_000);
        std::thread::sleep(Duration::from_millis(600));
        assert!(!handle.is_finished());
        assert!(!is_revoked(&stage));
        assert_eq!(engine.mode(A), Mode::Paused);
        // The capture settles on its own: nothing is left, the watchdog ends.
        mark_settled(&stage, A).unwrap();
        assert_eq!(handle.join().unwrap(), 0);
        assert_eq!(engine.mode(A), Mode::Paused);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_watchdog_rejects_bad_arguments_and_ignores_a_vanished_stage() {
        assert_eq!(watchdog_main(&["--engine-socket".into()]), 2);
        assert_eq!(watchdog_main(&["--bogus".into(), "x".into()]), 2);
        assert_eq!(watchdog_main(&[]), 2);
        let dir = scratch("gone");
        let args = [
            "--engine-socket".to_owned(),
            "/nonexistent".to_owned(),
            "--dir".to_owned(),
            dir.join("missing").display().to_string(),
        ];
        assert_eq!(watchdog_main(&args), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
