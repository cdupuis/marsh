//! A `BuildKit` stream that moves another workspace's image tag (DA1-02/04): the
//! tag is put back when the stream ends and an event is raised, unless the
//! change has another explanation. The engine is a fake that keeps tag to image
//! ID, so a test plays the build by changing it while a stream is open.

use std::collections::{BTreeMap, HashSet};

use super::super::TagEventKind;
use super::*;

#[derive(Default)]
struct Store {
    tags: BTreeMap<String, String>,
    /// Images the engine has, tagged or not.
    images: HashSet<String>,
    pulled: HashSet<String>,
    /// Targets of every `POST /images/<ref>/tag`.
    tag_posts: Vec<String>,
    deletes: usize,
    fail_list: bool,
}

type Shared = Arc<Mutex<Store>>;

impl Store {
    fn add(&mut self, tag: &str, id: &str, pulled: bool) {
        self.tags.insert(tag.to_owned(), id.to_owned());
        self.images.insert(id.to_owned());
        if pulled {
            self.pulled.insert(id.to_owned());
        }
    }

    fn resolve(&self, reference: &str) -> Option<String> {
        if let Some(id) = self.tags.get(reference) {
            return Some(id.clone());
        }
        let id = if reference == "src" {
            "sha256:src"
        } else {
            reference
        };
        self.images.contains(id).then(|| id.to_owned())
    }

    fn entry(&self, id: &str) -> String {
        let tags: Vec<String> = self
            .tags
            .iter()
            .filter(|(_, i)| *i == id)
            .map(|(t, _)| format!("\"{t}\""))
            .collect();
        let digests = if self.pulled.contains(id) {
            r#"["x@sha256:aa"]"#
        } else {
            "[]"
        };
        format!(
            r#"{{"Id":"{id}","RepoTags":[{}],"RepoDigests":{digests}}}"#,
            tags.join(",")
        )
    }
}

fn query(target: &str, key: &str) -> String {
    target
        .split('?')
        .nth(1)
        .unwrap_or("")
        .split('&')
        .find_map(|p| p.strip_prefix(&format!("{key}=")))
        .unwrap_or("")
        .to_owned()
}

fn bk_engine(st: Shared) -> Handler {
    Arc::new(move |req, s| {
        let path = req.target.split('?').next().unwrap_or("").to_owned();
        let mut st = st.lock().unwrap();
        match (req.method.as_str(), path.as_str()) {
            ("POST", "/grpc" | "/session") => {
                drop(st);
                s.write_all(SWITCH).unwrap();
                let mut b = [0u8; 256];
                while s.read(&mut b).is_ok_and(|n| n > 0) {}
                return true;
            }
            ("GET", "/images/json") => {
                if st.fail_list {
                    answer(s, 500, "{}");
                } else {
                    let all: Vec<String> = st.images.iter().map(|i| st.entry(i)).collect();
                    answer(s, 200, &format!("[{}]", all.join(",")));
                }
            }
            ("GET", p) if p.starts_with("/images/") && p.ends_with("/json") => {
                let name = p.trim_start_matches("/images/").trim_end_matches("/json");
                match st.resolve(name) {
                    Some(id) => answer(s, 200, &st.entry(&id)),
                    None => answer(s, 404, "{}"),
                }
            }
            ("POST", "/images/create") => {
                let tag = format!(
                    "{}:{}",
                    query(&req.target, "fromImage"),
                    query(&req.target, "tag")
                );
                st.add(&tag, "sha256:repulled", true);
                answer(s, 200, "{}");
            }
            ("POST", p) if p.starts_with("/images/") && p.ends_with("/tag") => {
                st.tag_posts.push(req.target.clone());
                let name = p.trim_start_matches("/images/").trim_end_matches("/tag");
                match st.resolve(name) {
                    Some(id) => {
                        let tag = format!(
                            "{}:{}",
                            query(&req.target, "repo"),
                            query(&req.target, "tag")
                        );
                        st.tags.insert(tag, id);
                        answer(s, 201, "{}");
                    }
                    None => answer(s, 404, "{}"),
                }
            }
            ("DELETE", _) => {
                st.deletes += 1;
                answer(s, 200, "[]");
            }
            ("GET", "/containers/json" | "/networks") => answer(s, 200, "[]"),
            ("GET", "/volumes") => answer(s, 200, r#"{"Volumes":[]}"#),
            _ => return false,
        }
        true
    })
}

struct World {
    h: H,
    st: Shared,
}

impl World {
    fn with(name: &str, wrap: impl FnOnce(Handler) -> Handler) -> Self {
        let st: Shared = Arc::default();
        {
            let mut s = st.lock().unwrap();
            s.add("postgres:16", "sha256:pg", true);
            s.add("base-app:1", "sha256:a1", false);
            s.images.insert("sha256:lane".into());
            s.images.insert("sha256:src".into());
        }
        let h = H::new(name, false, wrap(bk_engine(st.clone())), |_| {});
        // The base workspace (lane-a) built `base-app:1`.
        h.svc.ledger.set_tag("lane-a", "base-app:1").unwrap();
        Self { h, st }
    }

    fn new(name: &str) -> Self {
        Self::with(name, |e| e)
    }

    fn tag(&self, name: &str) -> Option<String> {
        self.st.lock().unwrap().tags.get(name).cloned()
    }

    /// What a build does: a name now points at another image.
    fn build(&self, name: &str, id: &str) {
        self.st.lock().unwrap().add(name, id, false);
    }

    fn events(&self) -> Vec<(String, String, TagEventKind)> {
        self.h
            .svc
            .tag_events()
            .into_iter()
            .map(|e| (e.workspace, e.tag, e.kind))
            .collect()
    }

    fn quiet(&self) {
        let events = self.events();
        assert!(events.is_empty(), "unexpected events: {events:?}");
    }

    fn deletes(&self) -> usize {
        self.st.lock().unwrap().deletes
    }

    /// The client closes; returns once the workspace has no connection left,
    /// that is once the check at the end of its stream is done.
    fn end(&self, client: &UnixStream, ws: &str) {
        self.close(client);
        self.settled(ws);
    }

    #[allow(clippy::unused_self)]
    fn close(&self, client: &UnixStream) {
        let _ = client.shutdown(std::net::Shutdown::Both);
    }

    fn settled(&self, ws: &str) {
        assert!(
            wait_for(Duration::from_secs(10), || {
                !self
                    .h
                    .svc
                    .counts
                    .lock()
                    .unwrap()
                    .workspaces
                    .contains_key(ws)
            }),
            "the stream of {ws} did not end"
        );
    }
}

fn open_stream(sock: &Path, path: &str) -> UnixStream {
    let mut c = UnixStream::connect(sock).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        c,
        "POST {path} HTTP/1.1\r\nHost: d\r\nConnection: Upgrade\r\nUpgrade: h2c\r\nContent-Length: 0\r\n\r\n"
    )
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(c.read(&mut b).unwrap(), 1, "no switch head: {head:?}");
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 101"));
    c
}

const A: &str = "lane-a";
const B: &str = "lane-b";

fn ev(ws: &str, tag: &str, kind: TagEventKind) -> (String, String, TagEventKind) {
    (ws.to_owned(), tag.to_owned(), kind)
}

/// A build in B's stream that took A's tag: the tag goes back to A's image when
/// the stream ends, the event says so, nothing is deleted, the restore is a plain
/// tag (no `force`), and B's next REST request is not affected.
#[test]
fn a_tag_another_workspace_recorded_is_put_back_when_the_stream_ends() {
    let w = World::new("bk-restore");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
    assert_eq!(w.events(), [ev(B, "base-app:1", TagEventKind::Restored)]);
    assert_eq!(w.deletes(), 0);
    let posts = w.st.lock().unwrap().tag_posts.clone();
    assert_eq!(posts, ["/images/sha256:a1/tag?repo=base-app&tag=1"]);
    assert_eq!(tag_call(&b, "mine", "1"), 201);
    assert_eq!(w.h.svc.ledger.tag_owner("mine:1").unwrap().scope, B);
}

/// `/session` is watched like `/grpc`.
#[test]
fn a_session_stream_is_watched_too() {
    let w = World::new("bk-session");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/session");
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
}

/// A name nobody recorded on a pulled image (`postgres:16`) is protected from a
/// stream too; a name on a local image nobody recorded is anyone's.
#[test]
fn an_unrecorded_pulled_name_is_put_back_and_a_local_one_is_left() {
    let w = World::new("bk-pulled");
    w.st.lock().unwrap().add("scratch:1", "sha256:s1", false);
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("postgres:16", "sha256:lane");
    w.build("scratch:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("postgres:16").as_deref(), Some("sha256:pg"));
    assert_eq!(w.tag("scratch:1").as_deref(), Some("sha256:lane"));
    assert_eq!(w.events(), [ev(B, "postgres:16", TagEventKind::Restored)]);
}

/// A workspace's stream moving its own tag is a build doing its work.
#[test]
fn a_stream_moving_its_own_tag_changes_nothing() {
    let w = World::new("bk-own");
    w.build("mine:1", "sha256:m1");
    w.h.svc.ledger.set_tag(B, "mine:1").unwrap();
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("mine:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("mine:1").as_deref(), Some("sha256:lane"));
    w.quiet();
    assert_eq!(w.st.lock().unwrap().tag_posts.len(), 0);
}

/// The owner's own `tag` during the stream is not undone (its record is a newer
/// claim).
#[test]
fn the_owners_tag_request_during_the_stream_is_not_undone() {
    let w = World::new("bk-owner-tag");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let c = open_stream(&b, "/grpc");
    assert_eq!(tag_as(&a, "src", "base-app"), 201);
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:src"));
    w.quiet();
}

/// Nor is a pull of its own name: no new claim, so only the request is evidence.
#[test]
fn the_owners_pull_during_the_stream_is_not_undone() {
    let w = World::new("bk-owner-pull");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let c = open_stream(&b, "/grpc");
    assert_eq!(
        call(&a, "POST", "/images/create?fromImage=base-app&tag=1", None).0,
        200
    );
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:repulled"));
    w.quiet();
}

/// A record released meanwhile (its workspace was dropped) leaves the name no
/// one's to restore.
#[test]
fn a_released_record_is_not_restored() {
    let w = World::new("bk-owner-gone");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    let claim = w.h.svc.ledger.tag_owner("base-app:1").unwrap().claim;
    w.h.svc.ledger.release_tag(A, "base-app:1", claim).unwrap();
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane"));
    w.quiet();
}

/// A request of the owner that was in the engine when the stream began, and
/// lands during it, is the owner's change.
#[test]
fn a_request_in_flight_when_the_stream_began_is_not_undone() {
    let (gate, release) = {
        let r = Arc::new(AtomicBool::new(false));
        (r.clone(), r)
    };
    let w = World::with("bk-inflight", |e| {
        let g = gate.clone();
        Arc::new(move |req: &Req, s: &mut UnixStream| {
            if req.target.starts_with("/images/create") {
                let until = Instant::now() + Duration::from_secs(5);
                while !g.load(Ordering::SeqCst) && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            e(req, s)
        })
    });
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let pull = std::thread::spawn(move || {
        call(&a, "POST", "/images/create?fromImage=base-app&tag=1", None).0
    });
    assert!(wait_for(Duration::from_secs(5), || w
        .h
        .engine
        .saw("POST", "/images/create")
        == 1));
    let c = open_stream(&b, "/grpc");
    release.store(true, Ordering::SeqCst);
    assert_eq!(pull.join().unwrap(), 200);
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:repulled"));
    w.quiet();
}

/// While the owner has a stream of its own open (or had one in the window), a
/// change of its tag may be its own build: the event is raised and nothing is
/// restored.
#[test]
fn a_tag_whose_owner_was_building_too_is_reported_not_restored() {
    let w = World::new("bk-amb");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let ca = open_stream(&a, "/grpc");
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane"));
    assert_eq!(w.events(), [ev(B, "base-app:1", TagEventKind::NotRestored)]);
    w.end(&ca, A);

    // The owner's stream began and ended inside the window.
    let w = World::new("bk-amb2");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let cb = open_stream(&b, "/grpc");
    let ca = open_stream(&a, "/grpc");
    w.end(&ca, A);
    w.build("base-app:1", "sha256:lane");
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane"));
    assert_eq!(w.events(), [ev(B, "base-app:1", TagEventKind::NotRestored)]);

    // The owner's stream ended before the window: not ambiguous.
    let w = World::new("bk-amb3");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let ca = open_stream(&a, "/grpc");
    w.end(&ca, A);
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
}

/// Two other workspaces' streams over one moved tag: it goes back once, and the
/// second stream does not undo the restore.
#[test]
fn two_overlapping_streams_restore_once() {
    let w = World::new("bk-two");
    let (b, c3) = (lane(&w.h, B), lane(&w.h, "lane-c"));
    let cb = open_stream(&b, "/grpc");
    let cc = open_stream(&c3, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&cb, B);
    w.end(&cc, "lane-c");
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
    assert_eq!(w.events().len(), 1);
    assert_eq!(w.st.lock().unwrap().tag_posts.len(), 1);
}

/// A snapshot that cannot be taken, or a check that cannot be made, does not
/// block the stream: it runs, with an event, and nothing is changed.
#[test]
fn a_failed_snapshot_or_check_lets_the_stream_run_and_raises_an_event() {
    let w = World::new("bk-open-start");
    w.st.lock().unwrap().fail_list = true;
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.st.lock().unwrap().fail_list = false;
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane"));
    assert_eq!(w.events(), [ev(B, "", TagEventKind::Unchecked)]);
    assert_eq!(w.deletes(), 0);

    let w = World::new("bk-open-end");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.st.lock().unwrap().fail_list = true;
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane"));
    assert_eq!(w.events(), [ev(B, "", TagEventKind::Unchecked)]);
    assert_eq!(w.deletes(), 0);
}

/// An image that is gone cannot be tagged again: the event says so, and no
/// image is deleted or any tag forced.
#[test]
fn a_restore_that_the_engine_refuses_is_reported_and_deletes_nothing() {
    let w = World::new("bk-refused");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.st.lock().unwrap().images.remove("sha256:a1");
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane"));
    assert_eq!(w.events(), [ev(B, "base-app:1", TagEventKind::NotRestored)]);
    assert_eq!(w.deletes(), 0);
    assert!(
        w.st.lock()
            .unwrap()
            .tag_posts
            .iter()
            .all(|p| !p.contains("force"))
    );
}

/// At most 256 protected tags are watched per stream, recorded ones first; the
/// rest are said to be unwatched.
#[test]
fn only_the_first_256_protected_tags_are_watched() {
    let w = World::new("bk-bound");
    for i in 0..300 {
        let tag = format!("t{i:03}:1");
        w.build(&tag, &format!("sha256:t{i:03}"));
        w.h.svc.ledger.set_tag(A, &tag).unwrap();
    }
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("t000:1", "sha256:lane");
    w.build("t299:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("t000:1").as_deref(), Some("sha256:t000"));
    assert_eq!(w.tag("t299:1").as_deref(), Some("sha256:lane"));
    assert!(w.events().contains(&ev(B, "", TagEventKind::Unchecked)));
}

/// The restore is made under the tag lock: a request that claims the name
/// meanwhile waits for it, and then finds the name A's.
#[test]
fn the_restore_holds_the_tag_lock_against_a_claim() {
    let release = Arc::new(AtomicBool::new(false));
    let gate = release.clone();
    let w = World::with("bk-lock", |e| {
        Arc::new(move |req: &Req, s: &mut UnixStream| {
            if req.method == "POST" && req.target.starts_with("/images/sha256:a1/tag") {
                let until = Instant::now() + Duration::from_secs(5);
                while !gate.load(Ordering::SeqCst) && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            e(req, s)
        })
    });
    let (b, c3) = (lane(&w.h, B), lane(&w.h, "lane-c"));
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.close(&cb);
    assert!(wait_for(Duration::from_secs(5), || w
        .h
        .engine
        .saw("POST", "/images/sha256:a1/tag")
        == 1));
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = send.send(tag_call(&c3, "base-app", "1"));
    });
    assert!(
        receive.recv_timeout(Duration::from_millis(400)).is_err(),
        "a claim went through while the restore was in the engine"
    );
    release.store(true, Ordering::SeqCst);
    assert_eq!(receive.recv_timeout(Duration::from_secs(5)), Ok(403));
    w.settled(B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
}
