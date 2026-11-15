//! The endpoint against a scripted engine, in process (no VM): the behaviors of
//! the E3 round-2 fixes that need a connection, a clock or a failing disk.
//!
//! Each test states what must hold. `e3/witness.sh` runs every test again with
//! the break mode that reintroduces its defect and requires the test to fail
//! (`E3_TEST_BREAKS`, read only by the unit-test build, see `breaks.rs`).

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{Authority, Config, Services};
use crate::ledger::{ContainerRec, PinRec, now};

const NET_ID: &str = "7777777777777777777777777777777777777777777777777777777777777777";

#[derive(Clone, Debug)]
struct Req {
    method: String,
    target: String,
    body: Vec<u8>,
}

type Handler = Arc<dyn Fn(&Req, &mut UnixStream) -> bool + Send + Sync>;

struct Engine {
    log: Arc<Mutex<Vec<Req>>>,
    release: Arc<AtomicBool>,
    created: Arc<AtomicUsize>,
}

fn read_req(s: &mut UnixStream) -> Option<Req> {
    let mut buf = Vec::new();
    let mut b = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = s.read(&mut b).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&b[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut lines = head.lines();
    let first = lines.next()?;
    let mut it = first.split(' ');
    let (method, target) = (it.next()?.to_string(), it.next()?.to_string());
    let len = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .and_then(|v| v.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    let mut body = buf[end..].to_vec();
    while body.len() < len {
        let n = s.read(&mut b).ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&b[..n]);
    }
    Some(Req {
        method,
        target,
        body,
    })
}

fn answer(s: &mut UnixStream, status: u16, body: &str) {
    let _ = write!(
        s,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

impl Engine {
    /// `custom` sees every request first; it returns whether it answered.
    fn start(path: &Path, custom: Handler) -> Self {
        let log: Arc<Mutex<Vec<Req>>> = Arc::default();
        let release = Arc::new(AtomicBool::new(false));
        let created = Arc::new(AtomicUsize::new(0));
        let l = UnixListener::bind(path).unwrap();
        let (log2, created2) = (log.clone(), created.clone());
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let (log, custom, created) = (log2.clone(), custom.clone(), created2.clone());
                std::thread::spawn(move || {
                    let Some(req) = read_req(&mut s) else { return };
                    log.lock().unwrap().push(req.clone());
                    if custom(&req, &mut s) {
                        return;
                    }
                    let t = req.target.split('?').next().unwrap_or("");
                    match (req.method.as_str(), t) {
                        ("POST", "/networks/create") => {
                            answer(&mut s, 201, &format!("{{\"Id\":\"{NET_ID}\"}}"));
                        }
                        ("GET", t) if t.starts_with("/networks/") => {
                            answer(&mut s, 200, &format!("{{\"Id\":\"{NET_ID}\"}}"));
                        }
                        ("POST", "/containers/create") => {
                            let n = created.fetch_add(1, Ordering::SeqCst) + 1;
                            answer(&mut s, 201, &format!("{{\"Id\":\"{n:064x}\"}}"));
                        }
                        ("GET", t) if t.starts_with("/containers/") && t.ends_with("/json") => {
                            answer(&mut s, 200, "{\"Mounts\":[]}");
                        }
                        ("DELETE", _) => {
                            let _ = s
                                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
                        }
                        _ => answer(&mut s, 404, "{\"message\":\"no such object\"}"),
                    }
                });
            }
        });
        Self {
            log,
            release,
            created,
        }
    }

    fn last_body(&self, method: &str, prefix: &str) -> String {
        self.log
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|r| r.method == method && r.target.starts_with(prefix))
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .unwrap_or_default()
    }

    fn saw(&self, method: &str, prefix: &str) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.method == method && r.target.starts_with(prefix))
            .count()
    }
}

struct H {
    dir: PathBuf,
    svc: Arc<Services>,
    engine: Engine,
    auth: Authority,
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("e3-ep-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn no_custom() -> Handler {
    Arc::new(|_, _| false)
}

impl H {
    fn new(
        name: &str,
        file_ledger: bool,
        custom: Handler,
        tweak: impl FnOnce(&mut Config),
    ) -> Self {
        let dir = scratch(name);
        let mut cfg = Config::default();
        cfg.paths.ledger = if file_ledger {
            dir.join("ledger.json")
        } else {
            PathBuf::new()
        };
        cfg.paths.bind_root = dir.join("binds");
        cfg.paths.socket_root = dir.join("socks");
        cfg.hijack_poll = Duration::from_millis(20);
        tweak(&mut cfg);
        let engine_path = dir.join("engine.sock");
        let engine = Engine::start(&engine_path, custom);
        let svc = Services::new(cfg, &engine_path).unwrap();
        let auth = Authority {
            project_root: dir.clone(),
            workspace: "lane-a".into(),
            attempt: "att1".into(),
        };
        Self {
            dir,
            svc,
            engine,
            auth,
        }
    }

    /// Serve `auth` on its own socket; returns the client path.
    fn serve(&self, auth: &Authority) -> PathBuf {
        let p = self
            .dir
            .join(format!("c-{}-{}.sock", auth.workspace, auth.attempt));
        let _ = std::fs::remove_file(&p);
        let l = UnixListener::bind(&p).unwrap();
        let (svc, a) = (self.svc.clone(), auth.clone());
        std::thread::spawn(move || {
            let _ = svc.serve_listener(&l, &a);
        });
        p
    }

    fn own_container(&self, id: &str, pins: &[&str]) {
        self.svc
            .ledger
            .add_container(
                id,
                ContainerRec {
                    scope: self.auth.workspace.clone(),
                    attempt: self.auth.attempt.clone(),
                    name: None,
                    pins: pins.iter().map(|s| (*s).to_string()).collect(),
                    created: now(),
                },
            )
            .unwrap();
    }
}

impl Drop for H {
    fn drop(&mut self) {
        self.engine.release.store(true, Ordering::SeqCst);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn call(sock: &Path, method: &str, target: &str, body: Option<&str>) -> (u16, String) {
    let mut s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let b = body.unwrap_or("");
    let ct = if body.is_some() {
        "Content-Type: application/json\r\n"
    } else {
        ""
    };
    write!(
        s,
        "{method} {target} HTTP/1.1\r\nHost: d\r\n{ct}Content-Length: {}\r\nConnection: close\r\n\r\n{b}",
        b.len()
    )
    .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map_or("", |x| x.1).to_string();
    (status, body)
}

fn wait_for(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    f()
}

const C1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const CREATE: &str = r#"{"Image":"busybox"}"#;

const SWITCH: &[u8] = b"HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n";

/// Attach to an owned container; the engine answers `101` and then runs
/// `after`. Returns the open client stream, positioned after the head.
fn attach(h: &H, sock: &Path) -> UnixStream {
    h.own_container(C1, &[]);
    let mut c = UnixStream::connect(sock).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        c,
        "POST /containers/{C1}/attach?stream=1&stdin=1&stdout=1 HTTP/1.1\r\nHost: d\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n"
    )
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(c.read(&mut b).unwrap(), 1, "no switch head: {head:?}");
        head.push(b[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    c
}

fn engine_attach(
    after: impl Fn(&mut UnixStream, &AtomicBool) + Send + Sync + 'static,
    release: Arc<AtomicBool>,
) -> Handler {
    Arc::new(move |req, s| {
        if req.target.contains("/attach") {
            s.write_all(SWITCH).unwrap();
            after(s, &release);
            return true;
        }
        false
    })
}

// --- hijack deadlines and disconnect cleanup (Sol: streams) ------------------

/// A hijacked stream that carries nothing either way is closed at the idle
/// limit. (`hijack-deadlines-off`: it stays open for ever.)
#[test]
fn a_silent_hijacked_stream_is_closed_at_the_idle_limit() {
    let rel = Arc::new(AtomicBool::new(false));
    let r2 = rel.clone();
    let h = H::new(
        "silent",
        false,
        engine_attach(
            |s, rel| {
                let end = Instant::now() + Duration::from_secs(20);
                while !rel.load(Ordering::SeqCst) && Instant::now() < end {
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = s.shutdown(std::net::Shutdown::Both);
            },
            rel,
        ),
        |c| c.hijack_idle = Duration::from_millis(400),
    );
    let sock = h.serve(&h.auth);
    let mut c = attach(&h, &sock);
    c.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let mut b = [0u8; 16];
    let r = c.read(&mut b);
    r2.store(true, Ordering::SeqCst);
    assert!(matches!(r, Ok(0)), "the idle stream was not closed: {r:?}");
    assert!(wait_for(Duration::from_secs(2), || h
        .svc
        .open_connections()
        == 0));
}

/// A client that vanishes frees its slot although the engine side is silent.
/// Linux only: it relies on POLLHUP meaning both directions are gone, which BSD
/// poll does not distinguish from a half-close.
#[cfg(target_os = "linux")]
#[test]
fn a_vanished_client_frees_the_slot() {
    let rel = Arc::new(AtomicBool::new(false));
    let r2 = rel.clone();
    let h = H::new(
        "vanish",
        false,
        engine_attach(
            |s, rel| {
                let end = Instant::now() + Duration::from_secs(20);
                while !rel.load(Ordering::SeqCst) && Instant::now() < end {
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = s.shutdown(std::net::Shutdown::Both);
            },
            rel,
        ),
        |c| c.hijack_idle = Duration::from_secs(600),
    );
    let sock = h.serve(&h.auth);
    let c = attach(&h, &sock);
    assert_eq!(h.svc.open_connections(), 1);
    drop(c);
    let freed = wait_for(Duration::from_secs(4), || h.svc.open_connections() == 0);
    r2.store(true, Ordering::SeqCst);
    assert!(freed, "the slot of a vanished client was never released");
}

/// A client that stops reading is cut after the write timeout instead of
/// holding the pump in a blocked write.
#[test]
fn a_client_that_stops_reading_is_cut() {
    let rel = Arc::new(AtomicBool::new(false));
    let r2 = rel.clone();
    let h = H::new(
        "blocked",
        false,
        engine_attach(
            |s, rel| {
                let chunk = vec![b'x'; 256 * 1024];
                while !rel.load(Ordering::SeqCst) {
                    if s.write_all(&chunk).is_err() {
                        return;
                    }
                }
            },
            rel,
        ),
        |c| {
            c.hijack_idle = Duration::from_secs(600);
            c.http.progress = Duration::from_millis(400);
        },
    );
    let sock = h.serve(&h.auth);
    let c = attach(&h, &sock);
    // Never read again.
    let freed = wait_for(Duration::from_secs(6), || h.svc.open_connections() == 0);
    r2.store(true, Ordering::SeqCst);
    drop(c);
    assert!(freed, "a stalled reader held the stream");
}

/// Control: half-closing the client's side does not cut the engine's output
/// (`docker exec -i < file`).
#[test]
fn a_half_closed_client_still_gets_the_engine_output() {
    let rel = Arc::new(AtomicBool::new(false));
    let h = H::new(
        "halfclose",
        false,
        engine_attach(
            |s, _| {
                let mut all = Vec::new();
                let _ = s.read_to_end(&mut all);
                std::thread::sleep(Duration::from_millis(300));
                let _ = s.write_all(b"after-eof:");
                let _ = s.write_all(&all);
                let _ = s.shutdown(std::net::Shutdown::Both);
            },
            rel,
        ),
        |c| c.hijack_idle = Duration::from_secs(30),
    );
    let sock = h.serve(&h.auth);
    let mut c = attach(&h, &sock);
    c.write_all(b"input").unwrap();
    c.shutdown(std::net::Shutdown::Write).unwrap();
    let mut got = Vec::new();
    c.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"after-eof:input");
}

// --- connection caps ----------------------------------------------------------

/// The cap is per project, not per workspace root: connections from other
/// roots of the same engine count against it. A second project is separate.
#[test]
fn the_project_cap_counts_every_workspace_root() {
    let h = H::new("cap", false, no_custom(), |c| {
        c.max_conns_project = 2;
        c.max_conns_attempt = 64;
    });
    let auth = |ws: &str| Authority {
        project_root: scratch(&format!("cap-root-{ws}")),
        workspace: ws.into(),
        attempt: "att1".into(),
    };
    let socks: Vec<PathBuf> = ["w1", "w2", "w3"]
        .iter()
        .map(|w| h.serve(&auth(w)))
        .collect();
    let _c1 = UnixStream::connect(&socks[0]).unwrap();
    let _c2 = UnixStream::connect(&socks[1]).unwrap();
    assert!(wait_for(Duration::from_secs(2), || h
        .svc
        .open_connections()
        == 2));
    let mut c3 = UnixStream::connect(&socks[2]).unwrap();
    c3.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut b = [0u8; 12];
    let n = c3.read(&mut b).unwrap_or(0);
    assert_eq!(
        &b[..n],
        b"HTTP/1.1 429",
        "a third root was admitted past the project cap"
    );

    // Control: another project (its own Services) is not held back by it.
    let other = H::new("cap-other", false, no_custom(), |c| c.max_conns_project = 2);
    let s = other.serve(&auth("w9"));
    let mut c4 = UnixStream::connect(&s).unwrap();
    c4.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let r = c4.read(&mut b);
    assert!(r.is_err(), "a separate project was refused: {r:?}");
}

// --- ledger persistence at the endpoint ---------------------------------------

/// A ledger that cannot be written refuses the create and takes the engine's
/// container back; admission resumes when writes work again.
#[test]
fn a_ledger_write_failure_refuses_and_leaves_no_engine_object() {
    let h = H::new("ledgerfail", true, no_custom(), |_| {});
    let sock = h.serve(&h.auth);
    let (st, body) = call(&sock, "POST", "/containers/create", Some(CREATE));
    assert_eq!(st, 201, "baseline create: {body}");
    assert_eq!(h.engine.created.load(Ordering::SeqCst), 1);

    let tmp = h.dir.join("ledger.lock");
    std::fs::remove_file(&tmp).unwrap();
    std::fs::create_dir(&tmp).unwrap();
    let (st, body) = call(&sock, "POST", "/containers/create", Some(CREATE));
    assert_eq!(st, 503, "an unsaved create was acknowledged: {body}");
    assert_eq!(
        h.engine.saw("DELETE", "/containers/"),
        1,
        "the engine's container was left behind"
    );
    // Degraded: nothing new is admitted, and the engine is not asked.
    let before = h.engine.created.load(Ordering::SeqCst);
    let (st, _) = call(&sock, "POST", "/containers/create", Some(CREATE));
    assert_eq!(st, 503);
    assert_eq!(h.engine.created.load(Ordering::SeqCst), before);

    std::fs::remove_dir(&tmp).unwrap();
    let (st, body) = call(&sock, "POST", "/containers/create", Some(CREATE));
    assert_eq!(st, 201, "admission did not resume: {body}");
}

/// A second agent serving the same ledger (a replacement that started before
/// the old relay exited) is refused, so it cannot answer from a stale view and
/// let a request delete a volume the ledger has since given to another
/// workspace.
#[test]
fn a_second_serving_agent_on_one_ledger_is_refused() {
    let h = H::new("secondagent", true, no_custom(), |_| {});
    let mut cfg = Config::default();
    cfg.paths.ledger = h.dir.join("ledger.json");
    cfg.ledger_serve_wait = Duration::from_millis(100);
    let error = Services::new(cfg.clone(), &h.dir.join("engine.sock"))
        .err()
        .expect("a second server must be refused");
    assert!(error.to_string().contains("another agent"), "{error}");
    drop(h);
    assert!(Services::new(cfg, &scratch("secondagent-engine").join("e.sock")).is_ok());
}

/// A corrupt ledger forgets which paths are protected: binds of a project
/// folder are refused (nothing reaches the engine) until an operator clears
/// the note; other requests still work.
#[cfg(target_os = "linux")]
#[test]
fn a_corrupt_ledger_refuses_project_binds_but_not_other_creates() {
    let h = H::new("quarantine", true, no_custom(), |_| {});
    std::fs::create_dir_all(h.dir.join("data")).unwrap();
    std::fs::write(
        h.dir.join("ledger.quarantine"),
        "corrupt ledger kept as x\n",
    )
    .unwrap();
    let sock = h.serve(&h.auth);
    let body = format!(
        r#"{{"Image":"busybox","HostConfig":{{"Binds":["{}:/data"]}}}}"#,
        h.dir.join("data").display()
    );
    let (status, reply) = call(&sock, "POST", "/containers/create", Some(&body));
    assert_eq!(status, 403, "{reply}");
    assert!(
        reply.contains(&h.dir.join("ledger.quarantine").display().to_string()),
        "the full path of the note: {reply}"
    );
    assert_eq!(h.engine.created.load(Ordering::SeqCst), 0);
    let (status, reply) = call(&sock, "POST", "/containers/create", Some(CREATE));
    assert_eq!(status, 201, "{reply}");
}

/// A DELETE admitted while lane A owned `data` must not reach the engine after
/// lane A's ownership ended and lane B created its own `data`: each volume
/// operation is checked, sent and recorded under one lock, so the later
/// requests wait for the first (or are refused) instead of overtaking it.
/// (An earlier DELETE held at the engine, a second DELETE that releases A's
/// ownership, B's create; then the first is released.)
#[test]
fn a_delayed_delete_cannot_remove_a_volume_another_workspace_now_owns() {
    let store: Arc<Mutex<std::collections::HashMap<String, String>>> = Arc::default();
    let deletes = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(AtomicBool::new(false));
    let custom: Handler = {
        let (store, deletes, gate) = (store.clone(), deletes.clone(), gate.clone());
        Arc::new(move |req, s| {
            let name = req.target.trim_start_matches("/volumes/").to_owned();
            match (req.method.as_str(), req.target.as_str()) {
                ("POST", "/volumes/create") => {
                    let body = String::from_utf8_lossy(&req.body).into_owned();
                    let named = body
                        .split("\"Name\":\"")
                        .nth(1)
                        .and_then(|rest| rest.split('"').next())
                        .unwrap_or("")
                        .to_owned();
                    store.lock().unwrap().insert(named, body.clone());
                    answer(s, 201, &body);
                    true
                }
                ("GET", t) if t.starts_with("/volumes/") => {
                    match store.lock().unwrap().get(&name).cloned() {
                        Some(body) => answer(s, 200, &body),
                        None => answer(s, 404, "{\"message\":\"no such volume\"}"),
                    }
                    true
                }
                ("DELETE", t) if t.starts_with("/volumes/") => {
                    if deletes.fetch_add(1, Ordering::SeqCst) == 0 {
                        while !gate.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                    let found = store.lock().unwrap().remove(&name).is_some();
                    if found {
                        let _ =
                            s.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
                    } else {
                        answer(s, 404, "{\"message\":\"no such volume\"}");
                    }
                    true
                }
                _ => false,
            }
        })
    };
    let h = H::new("staledelete", false, custom, |_| {});
    let auth_b = Authority {
        project_root: h.dir.clone(),
        workspace: "lane-b".into(),
        attempt: "att2".into(),
    };
    let (sock_a, sock_b) = (h.serve(&h.auth), h.serve(&auth_b));
    let (status, body) = call(
        &sock_a,
        "POST",
        "/volumes/create",
        Some(r#"{"Name":"data"}"#),
    );
    assert_eq!(status, 201, "{body}");

    let first = {
        let sock = sock_a.clone();
        std::thread::spawn(move || call(&sock, "DELETE", "/volumes/data", None).0)
    };
    assert!(wait_for(Duration::from_secs(5), || deletes
        .load(Ordering::SeqCst)
        == 1));
    let second = {
        let sock = sock_a.clone();
        std::thread::spawn(move || call(&sock, "DELETE", "/volumes/data", None).0)
    };
    let create_b = {
        let sock = sock_b.clone();
        std::thread::spawn(move || {
            call(&sock, "POST", "/volumes/create", Some(r#"{"Name":"data"}"#)).0
        })
    };
    // Neither may overtake the first while it is still at the engine.
    std::thread::sleep(Duration::from_millis(400));
    assert!(!second.is_finished(), "a second delete overtook the first");
    assert!(
        !create_b.is_finished(),
        "another workspace claimed the name meanwhile"
    );
    gate.store(true, Ordering::SeqCst);
    assert_eq!(first.join().unwrap(), 204);
    assert_eq!(
        second.join().unwrap(),
        404,
        "the name was no longer lane A's"
    );
    assert_eq!(create_b.join().unwrap(), 201);
    // Lane B's volume exists, in the engine and in the ledger.
    assert!(store.lock().unwrap().contains_key("data"));
    assert!(h.svc.ledger.has_volume("lane-b", "data"));
    assert!(!h.svc.ledger.has_volume("lane-a", "data"));
}

// --- freeze ordering ------------------------------------------------------------

fn inflight(svc: &Services, ws: &str) -> usize {
    svc.gate
        .scopes
        .lock()
        .unwrap()
        .get(ws)
        .map_or(0, |e| e.inflight)
}

/// A freeze begins only after an admitted mutation has finished, even one whose
/// body is still arriving; mutations after it are refused.
#[test]
fn a_freeze_waits_for_a_mutation_whose_body_is_still_arriving() {
    let h = H::new("freeze", false, no_custom(), |c| {
        c.http.progress = Duration::from_secs(5);
    });
    let sock = h.serve(&h.auth);
    // Warm the scope network so the delayed create is one engine call.
    let (st, _) = call(&sock, "POST", "/containers/create", Some(CREATE));
    assert_eq!(st, 201);
    let seen_before = h.engine.created.load(Ordering::SeqCst);

    let sock2 = sock.clone();
    let slow = std::thread::spawn(move || {
        let mut s = UnixStream::connect(&sock2).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            s,
            "POST /containers/create HTTP/1.1\r\nHost: d\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            CREATE.len()
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(700));
        s.write_all(CREATE.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).starts_with("HTTP/1.1 201")
    });
    assert!(wait_for(Duration::from_secs(3), || inflight(
        &h.svc, "lane-a"
    ) == 1));
    let guard = h.svc.freeze_scope("lane-a");
    let engine_has_it = h.engine.created.load(Ordering::SeqCst) > seen_before;
    assert!(
        engine_has_it,
        "the freeze was granted while a mutation was still in flight"
    );
    // Frozen: further mutations are refused, every time (a refusal must not end
    // the freeze), reads are not.
    for round in 0..3 {
        let (st, _) = call(&sock, "POST", "/containers/create", Some(CREATE));
        assert_eq!(
            st, 503,
            "refusal {round}: the freeze ended after an earlier refusal"
        );
    }
    let (st, _) = call(&sock, "DELETE", &format!("/containers/{C1}"), None);
    assert_eq!(st, 503);
    let (st, _) = call(&sock, "GET", "/containers/json", None);
    assert_ne!(st, 503);
    drop(guard);
    assert!(slow.join().unwrap(), "the delayed create was not answered");
    let (st, _) = call(&sock, "POST", "/containers/create", Some(CREATE));
    assert_eq!(st, 201, "the freeze did not end with its guard");
}

/// The same when the delay is in the engine (upstream admission): the freeze is
/// granted only after the engine has answered and the ledger is updated.
#[test]
fn a_freeze_waits_for_a_mutation_stuck_in_the_engine() {
    let answered = Arc::new(AtomicBool::new(false));
    let a2 = answered.clone();
    let h = H::new(
        "freeze-engine",
        false,
        Arc::new(move |req, s| {
            if req.method == "POST" && req.target.starts_with("/containers/create") {
                std::thread::sleep(Duration::from_millis(900));
                answer(s, 201, &format!("{{\"Id\":\"{:064x}\"}}", 5));
                a2.store(true, Ordering::SeqCst);
                return true;
            }
            false
        }),
        |_| {},
    );
    let sock = h.serve(&h.auth);
    let sock2 = sock.clone();
    let slow =
        std::thread::spawn(move || call(&sock2, "POST", "/containers/create", Some(CREATE)).0);
    assert!(wait_for(Duration::from_secs(3), || inflight(
        &h.svc, "lane-a"
    ) == 1));
    let guard = h.svc.freeze_scope("lane-a");
    assert!(
        answered.load(Ordering::SeqCst),
        "the freeze was granted while the engine had not answered an admitted create"
    );
    // The ledger knows the container the moment the freeze is granted.
    assert!(matches!(
        h.svc
            .ledger
            .find_container("lane-a", &format!("{:064x}", 5)),
        super::Lookup::Own(_)
    ));
    drop(guard);
    assert_eq!(slow.join().unwrap(), 201);
}

// --- list filtering --------------------------------------------------------------

/// An engine answer that cannot be filtered is not passed on (it would show the
/// other workspaces' objects); a parseable one is filtered by the ledger.
#[test]
fn a_list_that_cannot_be_filtered_fails_closed() {
    let garbage = Arc::new(AtomicBool::new(true));
    let g2 = garbage.clone();
    let h = H::new(
        "listfail",
        false,
        Arc::new(move |req, s| {
            if req.method == "GET" && req.target.starts_with("/containers/json") {
                if g2.load(Ordering::SeqCst) {
                    answer(s, 200, "[{\"Id\":\"aaaa\"} this is not json");
                } else {
                    answer(
                        s,
                        200,
                        &format!("[{{\"Id\":\"{C1}\"}},{{\"Id\":\"{:064x}\"}}]", 9),
                    );
                }
                return true;
            }
            false
        }),
        |_| {},
    );
    let sock = h.serve(&h.auth);
    let (st, body) = call(&sock, "GET", "/containers/json", None);
    assert_eq!(st, 502, "an unfiltered answer was passed on: {body}");
    assert!(!body.contains("aaaa"));

    garbage.store(false, Ordering::SeqCst);
    h.own_container(C1, &[]);
    let (st, body) = call(&sock, "GET", "/containers/json", None);
    assert_eq!(st, 200, "{body}");
    assert!(body.contains(C1), "{body}");
    assert!(!body.contains(&format!("{:064x}", 9)), "{body}");
}

// --- inherited pins ----------------------------------------------------------------

/// A container that takes volumes from another holds that container's pins: they
/// survive the original's deletion.
#[test]
fn volumes_from_keeps_the_pin_alive_after_the_original_is_deleted() {
    let h = H::new("inherit", false, no_custom(), |_| {});
    let sock = h.serve(&h.auth);
    h.svc
        .ledger
        .add_pin(
            "p1",
            PinRec {
                scope: "lane-a".into(),
                project_root: h.dir.to_string_lossy().into_owned(),
                rel: "data".into(),
                read_only: false,
                is_dir: true,
                subs: vec![],
                dev: 0,
                ino: 0,
                created: now(),
                failed: false,
            },
        )
        .unwrap();
    h.own_container(C1, &["p1"]);
    let body = format!(r#"{{"Image":"busybox","HostConfig":{{"VolumesFrom":["{C1}"]}}}}"#);
    let (st, out) = call(&sock, "POST", "/containers/create", Some(&body));
    assert_eq!(st, 201, "{out}");
    // The engine is given the scope network's ID, which Docker resolves before
    // any name, not the name.
    let sent = h.engine.last_body("POST", "/containers/create");
    assert!(
        sent.contains(&format!("\"NetworkMode\":\"{NET_ID}\"")),
        "{sent}"
    );
    let (st, _) = call(&sock, "DELETE", &format!("/containers/{C1}"), None);
    assert_eq!(st, 204);
    assert!(
        h.svc.ledger.pin("p1").is_some(),
        "the pin was released while a container still takes volumes from it"
    );
    let child = format!("{:064x}", 1);
    assert_eq!(h.svc.ledger.container_pins(&child), vec!["p1".to_string()]);
    // And it is released with the last holder.
    let (st, _) = call(&sock, "DELETE", &format!("/containers/{child}"), None);
    assert_eq!(st, 204);
    assert!(h.svc.ledger.pin("p1").is_none());
}

// --- long-lived state ---------------------------------------------------------

/// DA1-06: per-attempt, per-root and per-workspace connection counts go
/// when their last connection does; the endpoint still serves afterwards.
#[test]
fn ended_attempts_leave_no_connection_counts_behind() {
    let h = H::new("state", false, no_custom(), |_| {});
    let socks = (0..8)
        .map(|n| {
            h.serve(&Authority {
                project_root: scratch(&format!("state-root-{n}")),
                workspace: format!("ws{n}"),
                attempt: format!("att{n}"),
            })
        })
        .collect::<Vec<_>>();
    let clients = socks
        .iter()
        .map(|sock| UnixStream::connect(sock).unwrap())
        .collect::<Vec<_>>();
    assert!(wait_for(Duration::from_secs(5), || h.svc.tracked().1 == 8));
    drop(clients);
    assert!(
        wait_for(Duration::from_secs(5), || {
            let (_, attempts, roots, workspaces) = h.svc.tracked();
            (attempts, roots, workspaces) == (0, 0, 0)
        }),
        "{:?}",
        h.svc.tracked()
    );
    let (status, body) = call(
        &h.serve(&h.auth),
        "POST",
        "/containers/create",
        Some(CREATE),
    );
    assert_eq!(status, 201, "{body}");
}

/// DA1-06: a bind root's descriptor goes with the last workspace that used
/// it (bind roots open only on Linux).
#[cfg(target_os = "linux")]
#[test]
fn a_forgotten_workspace_releases_its_bind_roots() {
    let h = H::new("roots", false, no_custom(), |_| {});
    let shared = scratch("roots-shared");
    h.svc.hold_root(&shared, "ws-a");
    h.svc.hold_root(&shared, "ws-b");
    h.svc.hold_root(&scratch("roots-own"), "ws-a");
    assert_eq!(h.svc.tracked().0, 2);
    h.svc.forget_scope("ws-a").unwrap();
    assert_eq!(h.svc.tracked().0, 1, "a root another workspace uses stays");
    h.svc.forget_scope("ws-b").unwrap();
    assert_eq!(h.svc.tracked().0, 0);
}

/// A `containers/create` with a bind under `root`, as a request.
#[cfg(target_os = "linux")]
fn bind_create(root: &Path) -> String {
    let body = format!(
        r#"{{"Image":"busybox","HostConfig":{{"Binds":["{}:/data"]}}}}"#,
        root.join("data").display()
    );
    format!(
        "POST /containers/create HTTP/1.1\r\nHost: d\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// DA1-06: a bind mount in a real `containers/create` opens its root under
/// the connection's own workspace, kept while the workspace is served, so
/// forgetting that workspace releases it.
#[cfg(target_os = "linux")]
#[test]
fn a_bind_in_a_create_is_released_with_its_workspace() {
    let h = H::new("bindroot", false, no_custom(), |_| {});
    std::fs::create_dir_all(h.dir.join("data")).unwrap();
    let sock = h.svc.socket_for(&h.auth).unwrap();
    let mut c = UnixStream::connect(&sock).unwrap();
    c.write_all(bind_create(&h.dir).as_bytes()).unwrap();
    // Whether or not this host may mount the pin, the root was opened.
    let _ = c.read_to_end(&mut Vec::new());
    assert!(wait_for(Duration::from_secs(5), || h
        .svc
        .open_connections()
        == 0));
    assert_eq!(h.svc.tracked().0, 1);
    h.svc.forget_scope("another-workspace").unwrap();
    assert_eq!(h.svc.tracked().0, 1);
    h.svc.forget_scope(&h.auth.workspace).unwrap();
    assert_eq!(h.svc.tracked().0, 0);
}

/// DA1-06: a bind request that arrives on a connection accepted before its
/// workspace was forgotten opens the root again, but only for that
/// connection's life: eight such workspaces leave no root behind.
#[cfg(target_os = "linux")]
#[test]
fn a_late_bind_does_not_bring_back_a_forgotten_root() {
    let h = H::new("lateroot", false, no_custom(), |_| {});
    for index in 0..8 {
        let root = scratch(&format!("lateroot-{index}"));
        std::fs::create_dir_all(root.join("data")).unwrap();
        let auth = Authority {
            project_root: root.clone(),
            workspace: format!("ws{index}"),
            attempt: "att1".into(),
        };
        let sock = h.svc.socket_for(&auth).unwrap();
        let mut c = UnixStream::connect(&sock).unwrap();
        assert!(wait_for(Duration::from_secs(5), || h
            .svc
            .open_connections()
            == 1));
        h.svc.forget_scope(&auth.workspace).unwrap();
        c.write_all(bind_create(&root).as_bytes()).unwrap();
        let _ = c.read_to_end(&mut Vec::new());
        drop(c);
        assert!(wait_for(Duration::from_secs(5), || h
            .svc
            .open_connections()
            == 0));
    }
    assert_eq!(h.svc.tracked().0, 0, "forgotten roots came back");
    assert_eq!(h.svc.tracked().3, 0, "ended workspaces kept a count");
}

// --- image tag ownership (DA1-02) ---------------------------------------------

/// An engine that has `postgres:16` (pulled by the base: it has a registry
/// digest) and learns every tag the engine accepts and every delete;
/// `/images/<name>/json` says whether it has the name. `slow` is how long a tag
/// call takes (the request is in flight meanwhile).
fn image_engine_with(start: &[&str], slow: Duration) -> (Handler, Arc<Mutex<Vec<String>>>) {
    let mut names: Vec<String> = vec!["postgres:16".to_owned()];
    names.extend(start.iter().map(|s| (*s).to_owned()));
    let tags: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(names));
    let state = tags.clone();
    // Names that are another tag of the pulled `postgres:16` image.
    let aliases: Arc<Mutex<Vec<String>>> = Arc::default();
    let handler: Handler = Arc::new(move |req, s| {
        let path = req.target.split('?').next().unwrap_or("");
        let has = |name: &str| tags.lock().unwrap().iter().any(|t| t == name);
        if req.method == "GET"
            && let Some(name) = path
                .strip_prefix("/images/")
                .and_then(|p| p.strip_suffix("/json"))
        {
            let alias = aliases.lock().unwrap().clone();
            if name == "postgres:16" || alias.iter().any(|a| a == name) {
                let all: Vec<String> = std::iter::once("postgres:16".to_owned())
                    .chain(alias.into_iter().filter(|a| has(a)))
                    .map(|t| format!("\"{t}\""))
                    .collect();
                answer(
                    s,
                    200,
                    &format!(
                        r#"{{"RepoTags":[{}],"RepoDigests":["postgres@sha256:aa"]}}"#,
                        all.join(",")
                    ),
                );
            } else if has(name) {
                answer(s, 200, &format!(r#"{{"RepoTags":["{name}"]}}"#));
            } else {
                answer(s, 404, "{}");
            }
            return true;
        }
        match (req.method.as_str(), path) {
            ("GET", "/containers/json" | "/networks") => {
                answer(s, 200, "[]");
                return true;
            }
            ("GET", "/volumes") => {
                answer(s, 200, r#"{"Volumes":[]}"#);
                return true;
            }
            _ => {}
        }
        if req.method == "GET" && path == "/images/json" {
            let list: Vec<String> = tags
                .lock()
                .unwrap()
                .iter()
                .map(|t| format!(r#"{{"RepoTags":["{t}"]}}"#))
                .collect();
            answer(s, 200, &format!("[{}]", list.join(",")));
            return true;
        }
        if req.method == "DELETE"
            && let Some(name) = path.strip_prefix("/images/")
        {
            tags.lock().unwrap().retain(|t| t != name);
            answer(s, 200, "[]");
            return true;
        }
        if req.method == "POST" && path.starts_with("/images/") && path.ends_with("/tag") {
            std::thread::sleep(slow);
            if path == "/images/postgres:16/tag" {
                let q = req.target.split('?').nth(1).unwrap_or("");
                let get = |k: &str| {
                    q.split('&')
                        .find_map(|p| p.strip_prefix(&format!("{k}=")))
                        .unwrap_or("")
                        .to_owned()
                };
                aliases
                    .lock()
                    .unwrap()
                    .push(format!("{}:{}", get("repo"), get("tag")));
            }
            let q: Vec<&str> = req
                .target
                .split('?')
                .nth(1)
                .unwrap_or("")
                .split('&')
                .collect();
            let get = |k: &str| {
                q.iter()
                    .find_map(|p| p.strip_prefix(&format!("{k}=")))
                    .unwrap_or("")
                    .to_owned()
            };
            tags.lock()
                .unwrap()
                .push(format!("{}:{}", get("repo"), get("tag")));
            answer(s, 201, "{}");
            return true;
        }
        false
    });
    (handler, state)
}

fn image_engine() -> Handler {
    image_engine_with(&[], Duration::ZERO).0
}

fn lane(h: &H, name: &str) -> PathBuf {
    h.serve(&Authority {
        workspace: name.into(),
        attempt: format!("att-{name}"),
        ..h.auth.clone()
    })
}

fn tag_call(sock: &Path, repo: &str, tag: &str) -> u16 {
    call(
        sock,
        "POST",
        &format!("/images/src/tag?repo={repo}&tag={tag}"),
        None,
    )
    .0
}

/// Another workspace of the project cannot move a tag a workspace created or
/// the engine holds from a pull, by `tag`, `build -t`, or a build's `outputs`;
/// the creator can, and a name nobody has is free. (REST routes only: a build
/// through `/grpc` is not seen, see docs/docker.md.)
#[test]
fn one_workspace_cannot_move_a_tag_another_created_or_pulled() {
    let h = H::new("tags", false, image_engine(), |_| {});
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    assert_eq!(tag_call(&lane_a, "app", "1"), 201, "a free name");
    assert_eq!(
        h.svc.ledger.tag_owner("app:1").map(|r| r.scope),
        Some("lane-a".into()),
        "the engine accepted it, so the creator is recorded"
    );
    assert_eq!(
        tag_call(&lane_a, "app", "1"),
        201,
        "the creator moves its own tag"
    );
    assert_eq!(
        tag_call(&lane_b, "app", "1"),
        403,
        "another workspace's tag"
    );
    assert_eq!(tag_call(&lane_b, "postgres", "16"), 403, "a pulled image");
    assert_eq!(tag_call(&lane_b, "mine", "1"), 201);
    assert_eq!(tag_call(&lane_a, "mine", "1"), 403);

    let builds_before = h.engine.saw("POST", "/build");
    let outputs =
        "%5B%7B%22Type%22%3A%22moby%22%2C%22Attrs%22%3A%7B%22name%22%3A%22app%3A1%22%7D%7D%5D";
    for target in [
        "/build?t=app%3A1".to_owned(),
        "/build?t=postgres%3A16".to_owned(),
        format!("/build?outputs={outputs}"),
    ] {
        let (st, body) = call(&lane_b, "POST", &target, None);
        assert_eq!(st, 403, "{target}: {body}");
    }
    assert_eq!(
        h.engine.saw("POST", "/build"),
        builds_before,
        "a refused build reached the engine"
    );
}

/// Review witness (gpt): a pull over another workspace's tag is refused.
#[test]
fn a_foreign_pull_is_refused() {
    let custom: Handler = {
        let inner = image_engine_with(&["app:1"], Duration::ZERO).0;
        Arc::new(move |req, s| {
            if req.method == "POST" && req.target.starts_with("/images/create?") {
                answer(s, 200, "{}");
                return true;
            }
            inner(req, s)
        })
    };
    let h = H::new("tag-pull", false, custom, |_| {});
    h.svc.ledger.set_tag("lane-a", "app:1").unwrap();
    let lane_b = lane(&h, "lane-b");
    let (st, body) = call(&lane_b, "POST", "/images/create?fromImage=app&tag=1", None);
    assert_eq!(st, 403, "foreign pull reached the engine: {body}");
    // Its own tag, a free name and a digest are not refused.
    let lane_a = h.serve(&h.auth);
    for target in [
        "/images/create?fromImage=app&tag=1",
        "/images/create?fromImage=busybox&tag=latest",
        "/images/create?fromImage=app%40sha256%3Aaa",
    ] {
        let who = if target.contains("app&") {
            &lane_a
        } else {
            &lane_b
        };
        assert_eq!(call(who, "POST", target, None).0, 200, "{target}");
    }
}

/// Review witness (gpt), extended: deleting another workspace's tag, a pulled
/// image, or an image by ID that carries such a tag is refused; your own is not.
#[test]
fn a_foreign_delete_is_refused() {
    let (custom, names) = image_engine_with(&["app:1", "mine:1"], Duration::ZERO);
    let h = H::new("tag-delete", false, custom, |_| {});
    h.svc.ledger.set_tag("lane-a", "app:1").unwrap();
    h.svc.ledger.set_tag("lane-b", "mine:1").unwrap();
    let lane_b = lane(&h, "lane-b");
    for target in ["/images/app:1", "/images/postgres:16"] {
        let (st, body) = call(&lane_b, "DELETE", target, None);
        assert_eq!(st, 403, "{target}: {body}");
    }
    assert!(names.lock().unwrap().iter().any(|t| t == "app:1"));
    assert_eq!(call(&lane_b, "DELETE", "/images/mine:1", None).0, 200);
}

/// After `docker rmi` the name is free again at once: a record whose image is
/// gone holds nothing.
#[test]
fn a_tag_is_free_again_after_its_image_is_deleted() {
    let h = H::new("tag-rmi", false, image_engine(), |_| {});
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    assert_eq!(tag_call(&lane_a, "app", "1"), 201);
    assert_eq!(tag_call(&lane_b, "app", "1"), 403);
    assert_eq!(call(&lane_a, "DELETE", "/images/app:1", None).0, 200);
    assert_eq!(tag_call(&lane_b, "app", "1"), 201);
    assert_eq!(
        h.svc.ledger.tag_owner("app:1").map(|r| r.scope),
        Some("lane-b".into())
    );
}

/// Review witnesses (gpt): a request the engine refused, or one refused part
/// way through a set of names, leaves no record.
#[test]
fn a_failed_or_refused_request_leaves_no_claim() {
    let custom: Handler = {
        let inner = image_engine_with(&["app:1"], Duration::ZERO).0;
        Arc::new(move |req, s| {
            if req.method == "POST" && req.target.starts_with("/images/missing/tag?") {
                answer(s, 404, "{}");
                return true;
            }
            inner(req, s)
        })
    };
    let h = H::new("tag-failed", false, custom, |_| {});
    h.svc.ledger.set_tag("lane-a", "app:1").unwrap();
    let lane_b = lane(&h, "lane-b");
    let (st, _) = call(
        &lane_b,
        "POST",
        "/images/missing/tag?repo=unused&tag=1",
        None,
    );
    assert_eq!(st, 404);
    assert!(
        h.svc.ledger.tag_owner("unused:1").is_none(),
        "a failed tag left a record"
    );
    let target = "/build?outputs=%5B%7B%22Type%22%3A%22moby%22%2C%22Attrs%22%3A%7B%22name%22%3A%22aaa%3A1%2Capp%3A1%22%7D%7D%5D";
    assert_eq!(call(&lane_b, "POST", target, None).0, 403);
    assert!(
        h.svc.ledger.tag_owner("aaa:1").is_none(),
        "a refused set left a partial claim"
    );
    assert!(
        h.svc.lock_tags().is_empty(),
        "a reservation was left behind"
    );
}

/// Review witness (gpt): while a workspace's build of a tag is running, no other
/// workspace can take the name, however old or missing the record is.
#[test]
fn an_active_build_keeps_its_tag() {
    let release = Arc::new(AtomicBool::new(false));
    let gate = release.clone();
    let inner = image_engine();
    let custom: Handler = Arc::new(move |req, s| {
        if req.method == "POST" && req.target.starts_with("/build?") {
            let until = Instant::now() + Duration::from_secs(5);
            while !gate.load(Ordering::SeqCst) && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
            answer(s, 200, "{}");
            return true;
        }
        inner(req, s)
    });
    let h = H::new("tag-active", false, custom, |_| {});
    h.svc.ledger.set_tag("lane-a", "app:1").unwrap();
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let building = std::thread::spawn(move || call(&lane_a, "POST", "/build?t=app%3A1", None));
    assert!(wait_for(Duration::from_secs(5), || h
        .engine
        .saw("POST", "/build")
        > 0));
    let (st, body) = call(&lane_b, "POST", "/images/src/tag?repo=app&tag=1", None);
    assert_eq!(
        st, 403,
        "another workspace took an active build's name: {body}"
    );
    release.store(true, Ordering::SeqCst);
    assert_eq!(building.join().unwrap().0, 200);
    assert!(
        h.svc.lock_tags().is_empty(),
        "the reservation outlived the build"
    );
}

/// The reservation is atomic: workspaces racing for one new name, while the
/// engine is slow, give it to exactly one.
#[test]
fn racing_workspaces_get_a_new_tag_once() {
    let (custom, _) = image_engine_with(&[], Duration::from_millis(150));
    let h = H::new("tag-race", false, custom, |_| {});
    let socks: Vec<PathBuf> = (0..8).map(|n| lane(&h, &format!("lane-{n}"))).collect();
    let results: Vec<u16> = std::thread::scope(|sc| {
        let handles: Vec<_> = socks
            .iter()
            .map(|s| sc.spawn(move || tag_call(s, "race", "1")))
            .collect();
        handles.into_iter().map(|t| t.join().unwrap()).collect()
    });
    assert_eq!(
        results.iter().filter(|c| **c == 201).count(),
        1,
        "{results:?}"
    );
    assert_eq!(
        results.iter().filter(|c| **c == 403).count(),
        7,
        "{results:?}"
    );
}

/// A full tag table does not refuse for ever: records of images that are gone
/// go, and a record of an image that is there stays.
#[test]
fn a_full_tag_table_drops_records_of_missing_images_only() {
    let (custom, _) = image_engine_with(&["keep:1"], Duration::ZERO);
    let h = H::new("tag-cap", false, custom, |_| {});
    for n in 0..crate::ledger::MAX_TAGS - 1 {
        h.svc.ledger.set_tag("dead", &format!("dead:{n}")).unwrap();
    }
    h.svc.ledger.set_tag("lane-b", "keep:1").unwrap();
    assert_eq!(h.svc.ledger.tag_count(), crate::ledger::MAX_TAGS);
    let lane_a = h.serve(&h.auth);
    assert_eq!(tag_call(&lane_a, "fresh", "1"), 201);
    assert!(h.svc.ledger.tag_count() < 10, "stale records stayed");
    assert_eq!(
        h.svc.ledger.tag_owner("keep:1").map(|r| r.scope),
        Some("lane-b".into()),
        "a live owner's record was evicted"
    );
    assert_eq!(tag_call(&lane_a, "keep", "1"), 403);
}

/// A dropped workspace's tag records go with it.
#[test]
fn forgetting_a_workspace_drops_its_tag_records() {
    let h = H::new("tag-forget", false, image_engine(), |_| {});
    let lane_a = h.serve(&h.auth);
    assert_eq!(tag_call(&lane_a, "app", "1"), 201);
    h.svc.forget_scope("lane-a").unwrap();
    assert!(h.svc.ledger.tag_owner("app:1").is_none());
}

// --- review round 2 ---------------------------------------------------------

fn gated(engine: Handler, prefix: &'static str) -> (Handler, Arc<AtomicBool>) {
    let release = Arc::new(AtomicBool::new(false));
    let gate = release.clone();
    let handler: Handler = Arc::new(move |req, s| {
        if req.method == "POST" && req.target.starts_with(prefix) {
            let until = Instant::now() + Duration::from_secs(5);
            while !gate.load(Ordering::SeqCst) && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        engine(req, s)
    });
    (handler, release)
}

/// A workspace may delete its own alias of a pulled image (`docker tag
/// postgres:16 mine:pg; docker rmi mine:pg`); the image's other tags are
/// untouched, so only the name asked for is checked. An image ID would remove
/// every tag, so all of them are checked. (Claude r2 witness.)
#[test]
fn deleting_your_own_alias_of_a_pulled_image_is_allowed() {
    let (custom, _) = image_engine_with(&[], Duration::ZERO);
    let h = H::new("tag-alias", false, custom, |_| {});
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let (st, body) = call(
        &lane_a,
        "POST",
        "/images/postgres:16/tag?repo=mine&tag=pg",
        None,
    );
    assert_eq!(st, 201, "{body}");
    assert_eq!(
        call(&lane_b, "DELETE", "/images/mine:pg", None).0,
        403,
        "another's alias"
    );
    assert_eq!(
        call(&lane_a, "DELETE", "/images/postgres:16", None).0,
        403,
        "the pulled tag"
    );
    assert_eq!(
        call(&lane_a, "DELETE", "/images/mine:pg", None).0,
        200,
        "its own alias"
    );
    // By ID, every tag of the image counts, the pulled one included.
    let inner = image_engine_with(&[], Duration::ZERO).0;
    let by_id: Handler = Arc::new(move |req, s| {
        if req.method == "GET" && req.target == "/images/sha256:abcdabcdabcd/json" {
            answer(
                s,
                200,
                r#"{"RepoTags":["postgres:16","mine:pg"],"RepoDigests":["x@sha256:aa"]}"#,
            );
            return true;
        }
        inner(req, s)
    });
    let h = H::new("tag-alias-id", false, by_id, |_| {});
    let lane_a = h.serve(&h.auth);
    assert_eq!(
        call(&lane_a, "DELETE", "/images/sha256:abcdabcdabcd", None).0,
        403
    );
}

/// `docker pull app` without a tag pulls every tag: refused. (gpt r2 witness.)
#[test]
fn a_pull_of_every_tag_is_refused() {
    let h = H::new("tag-pull-all", false, image_engine(), |_| {});
    let lane_b = lane(&h, "lane-b");
    for target in [
        "/images/create?fromImage=app",
        "/images/create?fromImage=app&tag=",
        // The engine drops one trailing colon, then pulls every tag.
        "/images/create?fromImage=app%3A",
        "/images/create?fromImage=app%3A&tag=",
        "/images/create?fromImage=localhost%3A5000%2Fapp",
    ] {
        assert_eq!(call(&lane_b, "POST", target, None).0, 403, "{target}");
    }
    assert_eq!(h.engine.saw("POST", "/images/create"), 0);
}

/// A pull in flight holds the name against a tag or build of it, and a pull
/// does not hold it against other pulls. (gpt r2 witness.)
#[test]
fn an_active_pull_keeps_its_name_but_not_against_pulls() {
    let (inner, _) = image_engine_with(&[], Duration::ZERO);
    let (custom, release) = gated(inner, "/images/create?");
    let h = H::new("tag-pull-race", false, custom, |_| {});
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let lane_c = lane(&h, "lane-c");
    let b = lane_b.clone();
    let pulling =
        std::thread::spawn(move || call(&b, "POST", "/images/create?fromImage=app&tag=1", None).0);
    assert!(wait_for(Duration::from_secs(3), || h
        .engine
        .saw("POST", "/images/create")
        > 0));
    assert_eq!(
        tag_call(&lane_a, "app", "1"),
        403,
        "tag during another's pull"
    );
    assert_eq!(
        call(&lane_a, "POST", "/build?t=app%3A1", None).0,
        403,
        "build during a pull"
    );
    let c = std::thread::spawn(move || {
        call(&lane_c, "POST", "/images/create?fromImage=app&tag=1", None).0
    });
    release.store(true, Ordering::SeqCst);
    assert_eq!(pulling.join().unwrap(), 404);
    assert_eq!(
        c.join().unwrap(),
        404,
        "a second pull is not blocked by the first"
    );
    assert!(h.svc.lock_tags().is_empty());
}

/// A tag the engine accepted keeps its owner when the client has gone before
/// the answer. (gpt r2 witness.)
#[test]
fn a_client_that_disconnects_keeps_the_ownership_of_its_tag() {
    let (inner, _) = image_engine_with(&[], Duration::ZERO);
    let (custom, release) = gated(inner, "/images/src/tag");
    let h = H::new("tag-disconnect", false, custom, |_| {});
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let mut client = UnixStream::connect(&lane_a).unwrap();
    client
        .write_all(b"POST /images/src/tag?repo=app&tag=1 HTTP/1.1\r\nHost: d\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .unwrap();
    assert!(wait_for(Duration::from_secs(3), || h
        .engine
        .saw("POST", "/images/src/tag")
        > 0));
    drop(client);
    release.store(true, Ordering::SeqCst);
    assert!(wait_for(Duration::from_secs(3), || h
        .svc
        .lock_tags()
        .is_empty()));
    assert_eq!(
        tag_call(&lane_b, "app", "1"),
        403,
        "adoptable because its client left"
    );
}

/// A request in flight counts against the table, so two requests cannot both
/// fill the last slot. (gpt r2 witness.)
#[test]
fn requests_in_flight_reserve_capacity_in_the_tag_table() {
    let (inner, present) = image_engine_with(&[], Duration::ZERO);
    let (custom, release) = gated(inner, "/images/src/tag?repo=first&");
    let h = H::new("tag-cap-inflight", false, custom, |_| {});
    for n in 0..crate::ledger::MAX_TAGS - 1 {
        let name = format!("keep:{n}");
        h.svc.ledger.set_tag("lane-a", &name).unwrap();
        present.lock().unwrap().push(name);
    }
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let tagging = std::thread::spawn(move || tag_call(&lane_a, "first", "1"));
    assert!(wait_for(Duration::from_secs(3), || h
        .engine
        .saw("POST", "/images/src/tag")
        > 0));
    assert_eq!(
        tag_call(&lane_b, "second", "1"),
        403,
        "the last slot is taken"
    );
    release.store(true, Ordering::SeqCst);
    assert_eq!(tagging.join().unwrap(), 201);
    assert_eq!(
        h.svc.ledger.tag_owner("first:1").map(|r| r.scope),
        Some("lane-a".into())
    );
}

/// An active request's name, and a name nobody recorded, are not evicted; the
/// reconcile pass sheds records of images that are gone. (Claude r2 survivors.)
#[test]
fn reconcile_sheds_stale_tag_records_but_not_held_or_live_ones() {
    let (custom, _) = image_engine_with(&["live:1"], Duration::ZERO);
    let h = H::new("tag-reconcile", false, custom, |_| {});
    h.svc.ledger.set_tag("lane-a", "live:1").unwrap();
    h.svc.ledger.set_tag("lane-a", "gone:1").unwrap();
    h.svc.ledger.set_tag("lane-a", "held:1").unwrap();
    h.svc
        .lock_tags()
        .entry("held:1".into())
        .or_default()
        .add("lane-a", super::HoldKind::Claim);
    h.svc.reconcile();
    assert!(
        h.svc.ledger.tag_owner("gone:1").is_none(),
        "reconcile left a stale record"
    );
    assert!(
        h.svc.ledger.tag_owner("live:1").is_some(),
        "a live record went"
    );
    assert!(
        h.svc.ledger.tag_owner("held:1").is_some(),
        "an in-flight name went"
    );
}

/// An active build's name also blocks another workspace's delete of an image
/// that has it (no record yet) and its pull. (Claude r2 survivor.)
#[test]
fn an_active_build_blocks_a_delete_of_its_name() {
    let (inner, _) = image_engine_with(&["app:1"], Duration::ZERO);
    let (custom, release) = gated(inner, "/build?");
    let h = H::new("tag-build-delete", false, custom, |_| {});
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let building = std::thread::spawn(move || call(&lane_a, "POST", "/build?t=app%3A1", None).0);
    assert!(wait_for(Duration::from_secs(3), || h
        .engine
        .saw("POST", "/build")
        > 0));
    assert_eq!(call(&lane_b, "DELETE", "/images/app:1", None).0, 403);
    assert_eq!(
        call(&lane_b, "POST", "/images/create?fromImage=app&tag=1", None).0,
        403
    );
    release.store(true, Ordering::SeqCst);
    let _ = building.join();
}

/// Two requests of one workspace for one name: the first to end does not
/// release the other's hold. (Claude r2 survivor.)
#[test]
fn a_name_stays_held_until_every_request_of_the_workspace_ends() {
    use super::HoldKind::{Claim, Delete, Pull};
    let mut held = super::TagHeld::default();
    held.add("a", Claim);
    held.add("a", Claim);
    assert!(!held.release("a", Claim));
    assert!(held.blocks_claim("b"));
    assert!(held.release("a", Claim));
    // Who excludes whom: pulls share a name, a delete shares only with deletes.
    held.add("a", Pull);
    assert!(held.blocks_claim("b") && !held.blocks_pull("b") && held.blocks_delete("b"));
    assert!(held.release("a", Pull));
    held.add("a", Delete);
    assert!(held.blocks_claim("b") && held.blocks_pull("b") && !held.blocks_delete("b"));
    assert!(!held.blocks_claim("a") && !held.blocks_pull("a") && !held.blocks_delete("a"));
}

/// The Go SDK sends `busybox@sha256:..` as `fromImage=busybox&tag=sha256:..`;
/// a digest pull moves no tag, so it is not refused and needs no hold.
/// (gpt r3 witness.)
#[test]
fn a_digest_pull_in_either_encoding_is_allowed() {
    let h = H::new("tag-pull-digest", false, image_engine(), |_| {});
    let lane_b = lane(&h, "lane-b");
    let digest = format!("sha256%3A{}", "ab".repeat(32));
    for target in [
        format!("/images/create?fromImage=busybox&tag={digest}"),
        format!("/images/create?fromImage=busybox%40{digest}"),
    ] {
        let (st, body) = call(&lane_b, "POST", &target, None);
        assert_ne!(st, 403, "{target}: {body}");
    }
    assert_eq!(h.engine.saw("POST", "/images/create"), 2);
    // Something that is not a digest in `tag` is still refused.
    let (st, _) = call(
        &lane_b,
        "POST",
        "/images/create?fromImage=busybox&tag=a%3Ab",
        None,
    );
    assert_eq!(st, 403);
}

/// A short image ID (Docker takes any unique prefix) removes every tag of the
/// image, so it is checked like a full ID. (gpt r3 witness.)
#[test]
fn a_short_image_id_cannot_delete_a_foreign_tag() {
    let inner = image_engine_with(&["app:1"], Duration::ZERO).0;
    let custom: Handler = Arc::new(move |req, s| {
        if req.method == "GET" && req.target == "/images/abcd/json" {
            answer(s, 200, r#"{"RepoTags":["app:1"]}"#);
            return true;
        }
        inner(req, s)
    });
    let h = H::new("tag-short-id", false, custom, |_| {});
    h.svc.ledger.set_tag("lane-a", "app:1").unwrap();
    let lane_b = lane(&h, "lane-b");
    assert_eq!(call(&lane_b, "DELETE", "/images/abcd?force=1", None).0, 403);
    assert_eq!(h.engine.saw("DELETE", "/images/abcd"), 0);
}

/// A delete holds the names it removes until the engine has finished, even a
/// name no image has yet, so a tag made meanwhile is not removed from under its
/// owner. (gpt r3 witness.)
#[test]
fn a_delete_holds_its_name_until_the_engine_finishes() {
    let inner = image_engine();
    let release = Arc::new(AtomicBool::new(false));
    let gate = release.clone();
    let custom: Handler = Arc::new(move |req, s| {
        if req.method == "DELETE" && req.target.starts_with("/images/app:1") {
            let until = Instant::now() + Duration::from_secs(5);
            while !gate.load(Ordering::SeqCst) && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        inner(req, s)
    });
    let h = H::new("tag-delete-hold", false, custom, |_| {});
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let deleting = std::thread::spawn(move || call(&lane_b, "DELETE", "/images/app:1", None).0);
    assert!(wait_for(Duration::from_secs(3), || h
        .engine
        .saw("DELETE", "/images/app:1")
        > 0));
    assert_eq!(
        tag_call(&lane_a, "app", "1"),
        403,
        "a tag made during another's delete"
    );
    release.store(true, Ordering::SeqCst);
    assert_eq!(deleting.join().unwrap(), 200);
    assert!(h.svc.lock_tags().is_empty());
    assert!(
        h.svc.ledger.tag_owner("app:1").is_none(),
        "a delete recorded its names as the deleter's"
    );
    assert_eq!(
        tag_call(&lane_a, "app", "1"),
        201,
        "free once the delete is over"
    );
}

/// A pull of a name another workspace's delete holds is refused (the delete
/// would otherwise remove the pulled tag and free the name), while the delete's
/// own workspace and other deletes are not blocked. (gpt r4 witness.)
#[test]
fn a_pull_waits_for_another_workspaces_delete_of_its_name() {
    let inner = image_engine();
    let release = Arc::new(AtomicBool::new(false));
    let gate = release.clone();
    let custom: Handler = Arc::new(move |req, s| {
        if req.method == "DELETE" && req.target.starts_with("/images/app:1") {
            let until = Instant::now() + Duration::from_secs(5);
            while !gate.load(Ordering::SeqCst) && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        inner(req, s)
    });
    let h = H::new("tag-delete-pull", false, custom, |_| {});
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let b = lane_b.clone();
    let deleting = std::thread::spawn(move || call(&b, "DELETE", "/images/app:1", None).0);
    assert!(wait_for(Duration::from_secs(3), || h
        .engine
        .saw("DELETE", "/images/app:1")
        > 0));
    let (st, body) = call(&lane_a, "POST", "/images/create?fromImage=app&tag=1", None);
    assert_eq!(st, 403, "pull during another's delete: {body}");
    assert_ne!(
        call(&lane_b, "POST", "/images/create?fromImage=app&tag=1", None).0,
        403,
        "a workspace's own pull is not blocked by its delete"
    );
    release.store(true, Ordering::SeqCst);
    assert_eq!(deleting.join().unwrap(), 200);
    assert!(h.svc.lock_tags().is_empty());
}

/// A delete of a name no image has yet still waits for another workspace that
/// is building it. (Claude r4 survivor.)
#[test]
fn a_delete_of_an_absent_name_waits_for_a_build_of_it() {
    let (inner, _) = image_engine_with(&[], Duration::ZERO);
    let (custom, release) = gated(inner, "/build?");
    let h = H::new("tag-absent-delete", false, custom, |_| {});
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let building = std::thread::spawn(move || call(&lane_a, "POST", "/build?t=app%3A1", None).0);
    assert!(wait_for(Duration::from_secs(3), || h
        .engine
        .saw("POST", "/build")
        > 0));
    assert_eq!(call(&lane_b, "DELETE", "/images/app:1", None).0, 403);
    assert_eq!(h.engine.saw("DELETE", "/images/app:1"), 0);
    release.store(true, Ordering::SeqCst);
    let _ = building.join();
}

/// An engine whose image `abcd` (ID `sha256:abcd`) has B's `mine:1`; a delete
/// of `/images/abcd` or a tag from it can be held at the engine.
fn id_engine(gate_on: &'static str) -> (Handler, Arc<AtomicBool>) {
    let inner = image_engine_with(&["mine:1"], Duration::ZERO).0;
    let release = Arc::new(AtomicBool::new(false));
    let gate = release.clone();
    let handler: Handler = Arc::new(move |req, s| {
        if req.method == "GET" && req.target == "/images/abcd/json" {
            answer(s, 200, r#"{"Id":"sha256:abcd","RepoTags":["mine:1"]}"#);
            return true;
        }
        if req.method == gate_on.split_once(' ').unwrap().0
            && req.target.starts_with(gate_on.split_once(' ').unwrap().1)
        {
            let until = Instant::now() + Duration::from_secs(5);
            while !gate.load(Ordering::SeqCst) && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        inner(req, s)
    });
    (handler, release)
}

/// A tag put on an image while an ID delete of it is running would be removed
/// with the image: refused. (gpt r4 witness.)
#[test]
fn a_tag_cannot_be_put_on_an_image_while_it_is_being_deleted_by_id() {
    let (custom, release) = id_engine("DELETE /images/abcd");
    let h = H::new("tag-id-delete", false, custom, |_| {});
    h.svc.ledger.set_tag("lane-b", "mine:1").unwrap();
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let deleting =
        std::thread::spawn(move || call(&lane_b, "DELETE", "/images/abcd?force=1", None).0);
    assert!(wait_for(Duration::from_secs(3), || h
        .engine
        .saw("DELETE", "/images/abcd")
        > 0));
    let (st, body) = call(&lane_a, "POST", "/images/abcd/tag?repo=app&tag=1", None);
    assert_eq!(st, 403, "tag on an image being deleted: {body}");
    release.store(true, Ordering::SeqCst);
    assert_eq!(deleting.join().unwrap(), 200);
    assert!(h.svc.lock_tags().is_empty());
}

/// ... and the other way round: an ID delete waits for a tag being put on the
/// image.
#[test]
fn an_id_delete_waits_for_a_tag_being_put_on_the_image() {
    let (custom, release) = id_engine("POST /images/abcd/tag");
    let h = H::new("tag-id-delete2", false, custom, |_| {});
    h.svc.ledger.set_tag("lane-b", "mine:1").unwrap();
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let tagging = std::thread::spawn(move || {
        call(&lane_a, "POST", "/images/abcd/tag?repo=app&tag=1", None).0
    });
    assert!(wait_for(Duration::from_secs(3), || h
        .engine
        .saw("POST", "/images/abcd/tag")
        > 0));
    assert_eq!(call(&lane_b, "DELETE", "/images/abcd?force=1", None).0, 403);
    assert_eq!(h.engine.saw("DELETE", "/images/abcd"), 0);
    release.store(true, Ordering::SeqCst);
    assert_eq!(tagging.join().unwrap(), 201);
    assert!(h.svc.lock_tags().is_empty());
}

// --- fourth window: no forced ID deletes -------------------------------------

fn delete_target(h: &H, prefix: &str) -> String {
    h.engine
        .log
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.method == "DELETE" && r.target.starts_with(prefix))
        .map(|r| r.target.clone())
        .unwrap_or_default()
}

/// A delete by ID, short ID or digest never carries `force` to the engine (the
/// engine then refuses an image that has several tags), while a delete by one of
/// the image's own tag names keeps it. (gpt and claude r5.)
#[test]
fn an_id_delete_is_never_forced_and_a_named_one_keeps_force() {
    let (custom, _) = id_engine("DELETE /nothing");
    let h = H::new("tag-unforced", false, custom, |_| {});
    h.svc.ledger.set_tag("lane-b", "mine:1").unwrap();
    let lane_b = lane(&h, "lane-b");
    assert_eq!(
        call(&lane_b, "DELETE", "/images/abcd?force=1&noprune=0", None).0,
        200
    );
    let sent = delete_target(&h, "/images/abcd");
    assert!(!sent.contains("force"), "an ID delete was forced: {sent}");
    assert!(sent.contains("noprune=0"), "{sent}");
    assert_eq!(
        call(&lane_b, "DELETE", "/images/mine:1?force=1", None).0,
        200
    );
    assert!(delete_target(&h, "/images/mine:1").contains("force=1"));
}

/// An engine whose image `abcd` has the tags in `tags`; a REST build of `app:1`
/// is a cache hit that adds that tag to it; a delete of `/images/abcd` is held
/// until released, then does what the real engine does: refuses an unforced
/// delete of an image with several tags, removes everything when forced.
fn cache_engine(tags: Arc<Mutex<Vec<String>>>) -> (Handler, Arc<AtomicBool>) {
    let inner = image_engine();
    let release = Arc::new(AtomicBool::new(false));
    let gate = release.clone();
    let handler: Handler = Arc::new(move |req, s| {
        let path = req.target.split('?').next().unwrap_or("");
        let has = |n: &str| tags.lock().unwrap().iter().any(|t| t == n);
        if req.method == "GET"
            && (path == "/images/abcd/json"
                || path == "/images/mine:1/json"
                || path == "/images/app:1/json")
        {
            let name = path
                .trim_start_matches("/images/")
                .trim_end_matches("/json");
            if name == "abcd" || has(name) {
                let list: Vec<String> = tags
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|t| format!("\"{t}\""))
                    .collect();
                answer(
                    s,
                    200,
                    &format!(r#"{{"Id":"sha256:abcd","RepoTags":[{}]}}"#, list.join(",")),
                );
            } else {
                answer(s, 404, "{}");
            }
            return true;
        }
        if req.method == "POST" && path == "/build" {
            tags.lock().unwrap().push("app:1".into());
            answer(s, 200, "{}");
            return true;
        }
        if req.method == "DELETE" && path == "/images/abcd" {
            let until = Instant::now() + Duration::from_secs(5);
            while !gate.load(Ordering::SeqCst) && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
            let forced = req.target.contains("force=1");
            let mut t = tags.lock().unwrap();
            if !forced && t.len() > 1 {
                answer(
                    s,
                    409,
                    r#"{"message":"image is referenced in multiple repositories"}"#,
                );
            } else {
                t.clear();
                answer(s, 200, "[]");
            }
            return true;
        }
        inner(req, s)
    });
    (handler, release)
}

/// gpt r5: B's forced ID delete is held, A's cached build puts `app:1` on the same
/// image, the delete is released. The delete must not take A's tag with it (the
/// engine refuses because it is not forced), so B cannot then take the name.
#[test]
fn a_cached_build_alias_survives_a_forced_id_delete_and_cannot_be_taken() {
    let tags = Arc::new(Mutex::new(vec!["mine:1".to_owned()]));
    let (custom, release) = cache_engine(tags.clone());
    let h = H::new("tag-cache-delete", false, custom, |_| {});
    h.svc.ledger.set_tag("lane-b", "mine:1").unwrap();
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let b = lane_b.clone();
    let deleting = std::thread::spawn(move || call(&b, "DELETE", "/images/abcd?force=1", None).0);
    assert!(wait_for(Duration::from_secs(3), || h
        .engine
        .saw("DELETE", "/images/abcd")
        > 0));
    assert_eq!(call(&lane_a, "POST", "/build?t=app%3A1", None).0, 200);
    assert_eq!(
        h.svc.ledger.tag_owner("app:1").map(|r| r.scope),
        Some("lane-a".into())
    );
    release.store(true, Ordering::SeqCst);
    assert_eq!(
        deleting.join().unwrap(),
        409,
        "the engine must refuse the unforced delete"
    );
    assert!(
        tags.lock().unwrap().iter().any(|t| t == "app:1"),
        "the alias was removed"
    );
    assert_eq!(
        tag_call(&lane_b, "app", "1"),
        403,
        "the name was taken after the delete"
    );
    assert!(h.svc.lock_tags().is_empty());
}

/// An image with no tags (empty `RepoTags`) is deleted by ID under the image hold:
/// a `docker tag` of it waits, the delete is not forced, and the table empties.
/// (claude r5.)
#[test]
fn an_untagged_image_is_deleted_by_id_under_its_image_hold() {
    let inner = image_engine();
    let release = Arc::new(AtomicBool::new(false));
    let gate = release.clone();
    let custom: Handler = Arc::new(move |req, s| {
        if req.method == "GET" && req.target == "/images/dddd/json" {
            answer(s, 200, r#"{"Id":"sha256:dddd","RepoTags":[]}"#);
            return true;
        }
        if req.method == "DELETE" && req.target.starts_with("/images/dddd") {
            let until = Instant::now() + Duration::from_secs(5);
            while !gate.load(Ordering::SeqCst) && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        inner(req, s)
    });
    let h = H::new("tag-untagged", false, custom, |_| {});
    let lane_a = h.serve(&h.auth);
    let lane_b = lane(&h, "lane-b");
    let b = lane_b.clone();
    let deleting = std::thread::spawn(move || call(&b, "DELETE", "/images/dddd?force=1", None).0);
    assert!(wait_for(Duration::from_secs(3), || h
        .engine
        .saw("DELETE", "/images/dddd")
        > 0));
    assert_eq!(
        call(&lane_a, "POST", "/images/dddd/tag?repo=app&tag=1", None).0,
        403
    );
    assert!(!delete_target(&h, "/images/dddd").contains("force"));
    release.store(true, Ordering::SeqCst);
    assert_eq!(deleting.join().unwrap(), 200);
    assert!(h.svc.lock_tags().is_empty());
    assert_eq!(
        call(&lane_a, "POST", "/images/dddd/tag?repo=app&tag=1", None).0,
        201
    );
}

// --- tag named like an ID prefix (claude, fourth window) ---------------------------------------------------

/// Engine: image ID `sha256:abcdef123456...` with A's `app:1` and a tag named like
/// the ID's own prefix, `abcdef123456:latest`, owned by B. The engine's delete code
/// (`isImageIDPrefix`) treats a reference that is a prefix of the image ID as an ID
/// delete even when it is also a tag name; forced, that removes every tag.
fn collide_engine(tags: Arc<Mutex<Vec<String>>>, absent_first: Option<Arc<AtomicBool>>) -> Handler {
    let inner = image_engine();
    Arc::new(move |req, s| {
        let path = req.target.split('?').next().unwrap_or("");
        if req.method == "GET" && path == "/images/abcdef123456/json" {
            if let Some(a) = &absent_first
                && !a.swap(true, Ordering::SeqCst)
            {
                answer(s, 404, "{}");
                return true;
            }
            let list: Vec<String> = tags
                .lock()
                .unwrap()
                .iter()
                .map(|t| format!("\"{t}\""))
                .collect();
            answer(
                s,
                200,
                &format!(
                    r#"{{"Id":"sha256:abcdef1234560000","RepoTags":[{}]}}"#,
                    list.join(",")
                ),
            );
            return true;
        }
        if req.method == "DELETE" && path == "/images/abcdef123456" {
            let forced = req.target.contains("force=1");
            let mut t = tags.lock().unwrap();
            if !forced && t.len() > 1 {
                answer(s, 409, r#"{"message":"multiple"}"#);
            } else {
                t.clear();
                answer(s, 200, "[]");
            }
            return true;
        }
        inner(req, s)
    })
}

#[test]
fn a_tag_named_like_the_id_prefix_cannot_force_delete_the_image() {
    let tags = Arc::new(Mutex::new(vec![
        "app:1".to_owned(),
        "abcdef123456:latest".to_owned(),
    ]));
    let h = H::new(
        "w4-collide",
        false,
        collide_engine(tags.clone(), None),
        |_| {},
    );
    h.svc.ledger.set_tag("lane-a", "app:1").unwrap();
    let lane_b = lane(&h, "lane-b");
    // B puts a name on A's image through the real route; that is allowed.
    assert_eq!(tag_call_from(&lane_b, "app:1", "abcdef123456"), 201);
    assert_eq!(
        h.svc
            .ledger
            .tag_owner("abcdef123456:latest")
            .map(|r| r.scope),
        Some("lane-b".into())
    );
    let st = call(&lane_b, "DELETE", "/images/abcdef123456?force=1", None).0;
    let left = tags.lock().unwrap().clone();
    assert!(
        left.iter().any(|t| t == "app:1"),
        "A's tag was removed (status {st}); sent: {}",
        delete_target(&h, "/images/abcdef123456")
    );
}

/// Same, but the reference is absent when marsh looks and present when the engine does.
#[test]
fn an_absent_id_looking_name_is_not_forced() {
    let tags = Arc::new(Mutex::new(vec!["app:1".to_owned(), "mine:1".to_owned()]));
    let h = H::new(
        "w4-absent",
        false,
        collide_engine(tags.clone(), Some(Arc::new(AtomicBool::new(false)))),
        |_| {},
    );
    h.svc.ledger.set_tag("lane-a", "app:1").unwrap();
    h.svc.ledger.set_tag("lane-b", "mine:1").unwrap();
    let lane_b = lane(&h, "lane-b");
    let st = call(&lane_b, "DELETE", "/images/abcdef123456?force=1", None).0;
    let left = tags.lock().unwrap().clone();
    assert!(
        left.iter().any(|t| t == "app:1"),
        "A's tag was removed (status {st}); sent: {}",
        delete_target(&h, "/images/abcdef123456")
    );
}

fn tag_call_from(sock: &Path, src: &str, repo: &str) -> u16 {
    call(
        sock,
        "POST",
        &format!("/images/{src}/tag?repo={repo}"),
        None,
    )
    .0
}
