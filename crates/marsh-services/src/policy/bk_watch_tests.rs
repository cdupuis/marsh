//! A `BuildKit` stream that moves another workspace's image tag (DA1-02/04): the
//! tag is put back when the stream ends and an event is raised, unless the
//! change has another explanation. The engine is a fake that keeps tag to image
//! ID, so a test plays the build by changing it while a stream is open.

use std::collections::{BTreeMap, HashSet};

use super::super::{Scope, TagEventKind};
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
    lists: usize,
    /// Hold the answer to the next image list (computed before the wait).
    list_delay: Option<Duration>,
    /// Put a tag back to an image right after the second list is answered.
    heal: Option<(String, String)>,
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
                    let body = format!("[{}]", all.join(","));
                    if let Some(delay) = st.list_delay.take() {
                        drop(st);
                        std::thread::sleep(delay);
                        answer(s, 200, &body);
                        return true;
                    }
                    answer(s, 200, &body);
                    st.lists += 1;
                    if st.lists == 2
                        && let Some((tag, id)) = st.heal.take()
                    {
                        st.tags.insert(tag, id);
                    }
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

/// Two streams of one lane: the first one's end restores; the second's build
/// moves the tag again afterwards, and its end restores that too (a restore is
/// not a REST request and hides nothing).
#[test]
fn a_second_overwrite_after_a_restore_is_restored_too() {
    let w = World::new("bk-second");
    let b = lane(&w.h, B);
    let c1 = open_stream(&b, "/session");
    let c2 = open_stream(&b, "/session");
    w.build("base-app:1", "sha256:lane");
    w.close(&c1);
    assert!(wait_for(Duration::from_secs(5), || w.events().len() == 1));
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
    w.build("base-app:1", "sha256:lane2");
    w.end(&c2, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
    assert_eq!(w.events().len(), 2);
}

/// A stream that begins after another's overwrite does not take the overwritten
/// tag for the owner's: it restores the image the owner had, whichever stream
/// ends first, and the first stream's end finds nothing left to do.
#[test]
fn a_stream_that_began_after_an_overwrite_restores_the_legitimate_image() {
    let w = World::new("bk-late");
    let (b, c3) = (lane(&w.h, B), lane(&w.h, "lane-c"));
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    let cc = open_stream(&c3, "/grpc");
    w.build("base-app:1", "sha256:lane2");
    w.end(&cc, "lane-c");
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
    assert_eq!(w.events().len(), 1);

    // The other order: the first stream ends first and restores.
    let w = World::new("bk-late2");
    let (b, c3) = (lane(&w.h, B), lane(&w.h, "lane-c"));
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    let cc = open_stream(&c3, "/grpc");
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
    w.end(&cc, "lane-c");
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
}

/// A lane's many REST requests during its build (more than any log could hold)
/// do not hide its overwrite.
#[test]
fn many_rest_requests_do_not_hide_an_overwrite() {
    let w = World::new("bk-many");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    for _ in 0..4100 {
        assert_eq!(tag_call(&b, "mine", "1"), 201);
    }
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
    assert_eq!(w.events(), [ev(B, "base-app:1", TagEventKind::Restored)]);
}

/// What the engine says between the list and the lock decides: a tag that is
/// already back on its image is left alone.
#[test]
fn a_tag_that_is_back_when_it_is_read_again_is_left_alone() {
    let w = World::new("bk-back");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.st.lock().unwrap().heal = Some(("base-app:1".into(), "sha256:a1".into()));
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
    assert_eq!(w.st.lock().unwrap().tag_posts.len(), 0);
    w.quiet();
}

/// The stream's own workspace pulling a protected name is a request like any
/// other: what the pull left is the name's image, and the stream's overwrite
/// after it is put back.
#[test]
fn the_streams_own_pull_is_the_new_baseline() {
    let w = World::new("bk-selfpull");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    assert_eq!(
        call(&b, "POST", "/images/create?fromImage=postgres&tag=16", None).0,
        200
    );
    w.build("postgres:16", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("postgres:16").as_deref(), Some("sha256:repulled"));
    assert_eq!(w.events(), [ev(B, "postgres:16", TagEventKind::Restored)]);
}

/// With no record of what a tag legitimately is (its owner has a stream of its
/// own running, so its own request's result is not trusted, and this stream
/// began then), a change is reported and the tag is not restored to what it was
/// when the stream began.
#[test]
fn a_baseline_that_cannot_be_known_is_reported_not_restored() {
    let w = World::new("bk-weak");
    let (a, b, c3) = (lane(&w.h, A), lane(&w.h, B), lane(&w.h, "lane-c"));
    // Another lane's stream watches the name, so the request's result is seen
    // by the agent, which does not trust it while the owner is building.
    let cc = open_stream(&c3, "/grpc");
    let ca = open_stream(&a, "/grpc");
    assert_eq!(tag_as(&a, "src", "base-app"), 201);
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane"));
    assert_eq!(w.events(), [ev(B, "base-app:1", TagEventKind::NotRestored)]);
    w.end(&ca, A);
    w.end(&cc, "lane-c");
}

/// What is remembered is bounded: past the cap of legitimate images a tag is
/// watched but not trusted (reported, not restored).
#[test]
fn a_full_table_of_legitimate_images_reports_instead_of_restoring() {
    let w = World::new("bk-cap");
    w.h.svc.bk_fill_legit(4096);
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane"));
    assert_eq!(w.events(), [ev(B, "base-app:1", TagEventKind::NotRestored)]);
}

/// The event list keeps the latest 64.
#[test]
fn the_event_list_is_bounded() {
    let w = World::new("bk-events");
    let b = lane(&w.h, B);
    for _ in 0..70 {
        w.st.lock().unwrap().fail_list = true;
        let c = open_stream(&b, "/grpc");
        w.end(&c, B);
    }
    assert_eq!(w.h.svc.tag_events().len(), 64);
}

/// A stream leaves nothing behind: running, watched and per-workspace state go
/// when it ends or is dropped, and a forgotten workspace's go with it.
#[test]
fn a_stream_leaves_no_state_behind() {
    let w = World::new("bk-state");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    assert_eq!(w.h.svc.bk_sizes(), [1, 2, 2]);
    w.end(&c, B);
    // Entries stay (legitimate images); the running and watched ones go.
    assert_eq!(w.h.svc.bk_sizes(), [0, 2, 0]);
    // Forgetting a workspace drops the records of its names.
    w.h.svc.forget_scope(A).unwrap();
    assert_eq!(w.h.svc.bk_sizes()[1], 1);

    // A stream dropped without its check (the client write failed).
    let scope = Scope {
        svc: w.h.svc.clone(),
        auth: Authority {
            workspace: B.into(),
            ..w.h.auth.clone()
        },
    };
    let watch = scope.bk_begin();
    assert_eq!(w.h.svc.bk_sizes()[0], 1);
    drop(watch);
    let sizes = w.h.svc.bk_sizes();
    assert_eq!((sizes[0], sizes[2]), (0, 0));
}

/// What was recorded of a tag is dropped when its owner's build begins: the
/// owner's build may move its own tag, and a later stream must not put the
/// tag back to what it was before.
#[test]
fn an_owners_build_makes_what_was_recorded_stale() {
    let w = World::new("bk-stale");
    let (a, b, c3) = (lane(&w.h, A), lane(&w.h, B), lane(&w.h, "lane-c"));
    let cc = open_stream(&c3, "/grpc");
    let ca = open_stream(&a, "/grpc");
    w.build("base-app:1", "sha256:a2");
    w.end(&ca, A);
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane"));
    assert_eq!(w.events(), [ev(B, "base-app:1", TagEventKind::NotRestored)]);
    w.end(&cc, "lane-c");
}

/// A pull of an unrecorded name by another workspace during a stream makes what
/// was recorded of it stale, and what the pull left is the new record: a stream
/// that begins then puts the name back to the pulled image, not the older one.
#[test]
fn a_pull_during_another_stream_becomes_the_recorded_image() {
    let w = World::new("bk-pullstale");
    let (a, b, c3) = (lane(&w.h, A), lane(&w.h, B), lane(&w.h, "lane-c"));
    let cc = open_stream(&c3, "/grpc");
    assert_eq!(
        call(&a, "POST", "/images/create?fromImage=postgres&tag=16", None).0,
        200
    );
    let cb = open_stream(&b, "/grpc");
    w.build("postgres:16", "sha256:lane");
    w.end(&cb, B);
    assert_eq!(w.tag("postgres:16").as_deref(), Some("sha256:repulled"));
    assert_eq!(w.events(), [ev(B, "postgres:16", TagEventKind::Restored)]);
    w.end(&cc, "lane-c");
}

/// A pulled name that a stream overwrote stays watched by a stream that begins
/// later (it is known as a pulled name, though it no longer looks like one), so
/// that stream's own overwrite is put back too.
#[test]
fn a_late_stream_still_watches_an_overwritten_pulled_name() {
    let w = World::new("bk-pulledlate");
    let b = lane(&w.h, B);
    let cb = open_stream(&b, "/grpc");
    w.build("postgres:16", "sha256:first-overwrite");
    let cc = open_stream(&b, "/session");
    w.close(&cb);
    assert!(wait_for(Duration::from_secs(5), || w.events().len() == 1));
    assert_eq!(w.tag("postgres:16").as_deref(), Some("sha256:pg"));
    w.build("postgres:16", "sha256:second-overwrite");
    w.end(&cc, B);
    assert_eq!(w.tag("postgres:16").as_deref(), Some("sha256:pg"));
    assert_eq!(w.events().len(), 2);
}

/// A stream that finishes after its workspace was forgotten, and one that
/// finishes before, leave no per-workspace state behind.
#[test]
fn a_stream_finishing_after_its_workspace_was_forgotten_keeps_nothing() {
    let w = World::new("bk-forgot");
    for i in 0..8 {
        let ws = format!("gone{i}");
        let b = lane(&w.h, &ws);
        let c = open_stream(&b, "/grpc");
        w.h.svc.forget_scope(&ws).unwrap();
        w.end(&c, &ws);
    }
    assert_eq!(w.h.svc.bk_sizes()[0], 0);
    assert_eq!(w.h.svc.bk_sizes()[2], 0);
}

/// The first list of images is read before the tag lock is taken, so a REST
/// request is not made to wait for it; and a request that lands while it is
/// read makes the list stale, so it is read again: the baseline is what the
/// request left, not what the list saw.
#[test]
fn the_first_image_list_does_not_hold_the_tag_lock_and_is_read_again_after_a_request() {
    let w = World::new("bk-listlock");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    w.st.lock().unwrap().list_delay = Some(Duration::from_millis(1500));
    let opening = std::thread::spawn(move || open_stream(&b, "/grpc"));
    assert!(wait_for(Duration::from_secs(5), || {
        w.h.engine.saw("GET", "/images/json") == 1
    }));
    let started = Instant::now();
    assert_eq!(tag_as(&a, "src", "base-app"), 201);
    let took = started.elapsed();
    let c = opening.join().unwrap();
    assert!(
        took < Duration::from_millis(1000),
        "the request waited {took:?} for the list"
    );
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:src"));
    assert_eq!(w.events(), [ev(B, "base-app:1", TagEventKind::Restored)]);
}

/// A request's result is the tag's legitimate image: the owner's `tag` during
/// the stream does not hide a later overwrite, and the next stream's baseline is
/// the owner's image, never the overwrite.
#[test]
fn a_request_during_the_stream_neither_hides_a_later_overwrite_nor_poisons_the_baseline() {
    let w = World::new("bk-touch");
    let (a, b, c3) = (lane(&w.h, A), lane(&w.h, B), lane(&w.h, "lane-c"));
    let cb = open_stream(&b, "/grpc");
    assert_eq!(tag_as(&a, "src", "base-app"), 201);
    w.build("base-app:1", "sha256:lane");
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:src"));
    assert_eq!(w.events(), [ev(B, "base-app:1", TagEventKind::Restored)]);
    let cc = open_stream(&c3, "/grpc");
    w.end(&cc, "lane-c");
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane2");
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:src"));
    assert_eq!(w.events().len(), 2);
}

/// Another workspace's pull of an unrecorded pulled name during a stream does
/// not hide the stream's overwrite either.
#[test]
fn another_lanes_pull_does_not_hide_an_overwrite() {
    let w = World::new("bk-otherpull");
    let (b, c3) = (lane(&w.h, B), lane(&w.h, "lane-c"));
    let cb = open_stream(&b, "/grpc");
    assert_eq!(
        call(
            &c3,
            "POST",
            "/images/create?fromImage=postgres&tag=16",
            None
        )
        .0,
        200
    );
    w.build("postgres:16", "sha256:lane");
    w.end(&cb, B);
    assert_eq!(w.tag("postgres:16").as_deref(), Some("sha256:repulled"));
    assert_eq!(w.events(), [ev(B, "postgres:16", TagEventKind::Restored)]);
}

/// An open stream of another lane does not make a request of the owner defeat
/// the restore: what the request left is recorded.
#[test]
fn an_open_stream_and_requests_do_not_stop_a_restore() {
    let w = World::new("bk-open");
    let (a, b, c3) = (lane(&w.h, A), lane(&w.h, B), lane(&w.h, "lane-c"));
    let hold = open_stream(&c3, "/session");
    assert_eq!(tag_as(&a, "src", "base-app"), 201);
    assert_eq!(tag_as(&a, "sha256:a1", "base-app"), 201);
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
    w.end(&hold, "lane-c");
}

/// A record whose owner or claim is not the ledger's is not used (a claim the
/// requests did not see): the change is reported, not restored.
#[test]
fn a_record_of_another_claim_is_not_used() {
    let w = World::new("bk-claim");
    let (b, c3) = (lane(&w.h, B), lane(&w.h, "lane-c"));
    let cc = open_stream(&c3, "/grpc");
    w.h.svc.ledger.set_tag(A, "base-app:1").unwrap();
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane"));
    assert_eq!(w.events(), [ev(B, "base-app:1", TagEventKind::NotRestored)]);
    w.end(&cc, "lane-c");
}

/// Recorded tags are watched before unrecorded pulled names, whatever their
/// order by name, when there are more than the stream can watch.
#[test]
fn recorded_tags_come_before_pulled_names_in_the_watch() {
    let w = World::new("bk-order");
    for i in 0..300 {
        let tag = format!("aaa{i:03}:1");
        w.st.lock()
            .unwrap()
            .add(&tag, &format!("sha256:p{i:03}"), true);
    }
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
}

/// A request the engine refused leaves the name as it was: it is not a new
/// legitimate state, so an overwrite made before it does not become the baseline.
#[test]
fn a_refused_request_does_not_make_an_overwrite_the_baseline() {
    let w = World::new("bk-refusedreq");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    assert_eq!(tag_as(&a, "nosuch", "base-app"), 404);
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane"));
    assert_eq!(w.events(), [ev(B, "base-app:1", TagEventKind::NotRestored)]);
}

/// A request of the owner that is in the engine when the stream ends decides
/// what the name is: the stream's check leaves the name to it and says nothing.
#[test]
fn a_request_in_the_engine_at_the_end_of_the_stream_is_left_alone() {
    let (gate, release) = {
        let r = Arc::new(AtomicBool::new(false));
        (r.clone(), r)
    };
    let w = World::with("bk-atend", |e| {
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
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    let pull = std::thread::spawn(move || {
        call(&a, "POST", "/images/create?fromImage=base-app&tag=1", None).0
    });
    assert!(wait_for(Duration::from_secs(5), || w
        .h
        .engine
        .saw("POST", "/images/create")
        == 1));
    w.end(&cb, B);
    w.quiet();
    release.store(true, Ordering::SeqCst);
    assert_eq!(pull.join().unwrap(), 200);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:repulled"));
}

/// A record of another claim than the ledger's (a claim no request of the agent
/// saw) is replaced, when nothing else runs, by what the tag is.
#[test]
fn a_stale_record_is_replaced_when_nothing_else_runs() {
    let w = World::new("bk-replace");
    let (b, c3) = (lane(&w.h, B), lane(&w.h, "lane-c"));
    let first = open_stream(&b, "/grpc");
    w.end(&first, B);
    w.h.svc.ledger.set_tag(A, "base-app:1").unwrap();
    let cc = open_stream(&c3, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&cc, "lane-c");
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:a1"));
}

/// An overwrite that puts the tag back on the image it had when the stream
/// began is still one, if a request has changed what the tag should be since.
#[test]
fn an_overwrite_back_to_the_start_image_after_a_request_is_seen() {
    let w = World::new("bk-backto");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let cb = open_stream(&b, "/grpc");
    assert_eq!(tag_as(&a, "src", "base-app"), 201);
    w.build("base-app:1", "sha256:a1");
    w.end(&cb, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:src"));
}

/// The daemon's status read (the base workspace, attempt `status`) gets the
/// agent's own answer on the filtered endpoint: the events, in the shape the
/// daemon shows. Nothing else does: not a lane, not a base job, not a base
/// workspace's substituted socket (which has its job's attempt), and the engine
/// is never asked.
#[test]
fn only_the_daemons_status_read_gets_the_tag_events() {
    let w = World::new("bk-route");
    let as_attempt = |workspace: &str, attempt: &str| {
        w.h.serve(&Authority {
            workspace: workspace.into(),
            attempt: attempt.into(),
            ..w.h.auth.clone()
        })
    };
    let (status_read, b) = (as_attempt("base", "status"), lane(&w.h, B));
    let (status, body) = call(&status_read, "GET", "/_marsh/tag-events", None);
    assert_eq!((status, body.as_str()), (200, r#"{"events":[]}"#));
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    let (status, body) = call(&status_read, "GET", "/_marsh/tag-events", None);
    assert_eq!(status, 200);
    let answer: serde_json::Value = serde_json::from_str(&body).unwrap();
    let events = answer["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["tag"], "base-app:1");
    assert_eq!(events[0]["workspace"], B);
    assert_eq!(events[0]["kind"], "restored");
    for (who, sock) in [
        ("a lane's job", b.clone()),
        ("a base job", as_attempt("base", "job1")),
        ("a base shell", as_attempt("base", "shell")),
        ("a lane's status-named attempt", as_attempt(B, "status")),
    ] {
        let (status, body) = call(&sock, "GET", "/_marsh/tag-events", None);
        assert_eq!(status, 403, "{who} read the events: {body}");
    }
    assert_eq!(w.h.engine.saw("GET", "/_marsh"), 0);
}
