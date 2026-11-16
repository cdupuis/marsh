//! A `BuildKit` stream that moves another workspace's image tag (DA1-02/04) is
//! reported when it ends, and nothing is changed. The engine is a fake that keeps
//! tag to image ID, so a test plays the build by changing it while a stream is open.

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
    /// Hold the answer to the next image list (computed before the wait).
    list_delay: Option<Duration>,
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

    /// The tag changes reported: tag, previous image, current image, ambiguous.
    fn reports(&self) -> Vec<(String, String, Option<String>, bool)> {
        self.h
            .svc
            .tag_events()
            .into_iter()
            .filter(|e| e.kind == TagEventKind::Changed)
            .map(|e| (e.tag, e.previous, e.current, e.ambiguous))
            .collect()
    }

    fn unchecked(&self) -> usize {
        self.h
            .svc
            .tag_events()
            .iter()
            .filter(|e| e.kind == TagEventKind::Unchecked)
            .count()
    }

    fn quiet(&self) {
        let events = self.h.svc.tag_events();
        assert!(events.is_empty(), "unexpected events: {events:?}");
    }

    /// Requests the engine got that are not reads.
    fn writes(&self) -> Vec<String> {
        self.h
            .engine
            .log
            .lock()
            .unwrap()
            .iter()
            // The streams themselves are relayed to the engine.
            .filter(|r| r.method != "GET" && !matches!(r.target.as_str(), "/grpc" | "/session"))
            .map(|r| format!("{} {}", r.method, r.target))
            .collect()
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

fn rep(
    tag: &str,
    previous: &str,
    current: &str,
    ambiguous: bool,
) -> (String, String, Option<String>, bool) {
    (
        tag.to_owned(),
        previous.to_owned(),
        Some(current.to_owned()),
        ambiguous,
    )
}

/// A build in B's stream took A's tag: the end of the stream reports it with
/// everything the user needs (tag, owner, both images, the command), and the
/// engine is not changed: the tag stays where the build put it and the agent
/// made no request but reads.
#[test]
fn a_tag_another_workspace_recorded_is_reported_and_nothing_is_changed() {
    let w = World::new("bk-report");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane"));
    assert_eq!(
        w.reports(),
        [rep("base-app:1", "sha256:a1", "sha256:lane", false)]
    );
    let ev = &w.h.svc.tag_events()[0];
    assert_eq!((ev.workspace.as_str(), ev.owner.as_deref()), (B, Some(A)));
    assert!(
        ev.detail.contains("docker tag sha256:a1 base-app:1")
            && ev.detail.contains("workspace lane-a"),
        "{}",
        ev.detail
    );
    assert!(
        ev.detail.contains("not undone") && ev.detail.contains("sha256:lane"),
        "{}",
        ev.detail
    );
    assert_eq!(w.writes(), Vec::<String>::new());
    let st = w.st.lock().unwrap();
    assert_eq!((st.tag_posts.len(), st.deletes), (0, 0));
}

/// The detector asks the engine for nothing but reads, whatever it finds.
#[test]
fn the_detector_sends_the_engine_nothing_but_reads() {
    let w = World::new("bk-reads");
    let (b, c3) = (lane(&w.h, B), lane(&w.h, "lane-c"));
    let cb = open_stream(&b, "/grpc");
    let cc = open_stream(&c3, "/session");
    w.build("base-app:1", "sha256:lane");
    w.build("postgres:16", "sha256:lane2");
    w.end(&cb, B);
    w.end(&cc, "lane-c");
    assert_eq!(w.reports().len(), 2);
    assert_eq!(w.writes(), Vec::<String>::new());
    assert!(w.h.engine.saw("GET", "/images/json") >= 4);
}

/// `/session` is watched like `/grpc`.
#[test]
fn a_session_stream_is_watched_too() {
    let w = World::new("bk-session");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/session");
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.reports().len(), 1);
}

/// A name nobody recorded on a pulled image (`postgres:16`) is reported too, with
/// the command that gets it back (a pulled name cannot be re-tagged through the
/// filter); a name on a local image nobody recorded is anyone's.
#[test]
fn an_unrecorded_pulled_name_is_reported_and_a_local_one_is_not() {
    let w = World::new("bk-pulled");
    w.st.lock().unwrap().add("scratch:1", "sha256:s1", false);
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("postgres:16", "sha256:lane");
    w.build("scratch:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(
        w.reports(),
        [rep("postgres:16", "sha256:pg", "sha256:lane", false)]
    );
    let ev = &w.h.svc.tag_events()[0];
    assert_eq!(ev.owner, None);
    assert!(
        ev.detail.contains("docker pull postgres:16"),
        "{}",
        ev.detail
    );
}

/// A tag that went is reported as gone.
#[test]
fn a_tag_that_disappeared_is_reported() {
    let w = World::new("bk-gone");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.st.lock().unwrap().tags.remove("base-app:1");
    w.end(&c, B);
    let events = w.h.svc.tag_events();
    assert_eq!(events.len(), 1);
    assert_eq!(
        (events[0].current.clone(), events[0].previous.as_str()),
        (None, "sha256:a1")
    );
    assert!(events[0].detail.contains("no longer has the name"));
}

/// A workspace's stream moving its own tag is a build doing its work.
#[test]
fn a_stream_moving_its_own_tag_reports_nothing() {
    let w = World::new("bk-own");
    w.build("mine:1", "sha256:m1");
    w.h.svc.ledger.set_tag(B, "mine:1").unwrap();
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("mine:1", "sha256:lane");
    w.end(&c, B);
    w.quiet();
}

/// The owner's own request on the name during the stream (a `tag`, a pull) may
/// explain a change, and the report says so: ambiguous.
#[test]
fn an_owners_request_during_the_stream_makes_the_report_ambiguous() {
    let w = World::new("bk-ambig-rest");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let c = open_stream(&b, "/grpc");
    assert_eq!(tag_as(&a, "src", "base-app"), 201);
    w.end(&c, B);
    assert_eq!(
        w.reports(),
        [rep("base-app:1", "sha256:a1", "sha256:src", true)]
    );
    assert!(
        w.h.svc.tag_events()[0]
            .detail
            .contains("may be the owner's own change")
    );

    // A second overwrite after the owner's request is reported too (not hidden).
    let w = World::new("bk-ambig-rest2");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let c = open_stream(&b, "/grpc");
    assert_eq!(tag_as(&a, "src", "base-app"), 201);
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(
        w.reports(),
        [rep("base-app:1", "sha256:a1", "sha256:lane", true)]
    );
}

/// The same for a pull of an unrecorded pulled name by any other lane.
#[test]
fn another_lanes_pull_makes_the_report_ambiguous() {
    let w = World::new("bk-ambig-pull");
    let (b, c3) = (lane(&w.h, B), lane(&w.h, "lane-c"));
    let c = open_stream(&b, "/grpc");
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
    w.end(&c, B);
    assert_eq!(
        w.reports(),
        [rep("postgres:16", "sha256:pg", "sha256:lane", true)]
    );
}

/// A stream of the tag's owner running at the start, or beginning during the
/// window, makes the report ambiguous; one that ended before the window does not.
#[test]
fn an_owners_stream_in_the_window_makes_the_report_ambiguous() {
    let w = World::new("bk-ambig-open");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let ca = open_stream(&a, "/grpc");
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&cb, B);
    assert_eq!(
        w.reports(),
        [rep("base-app:1", "sha256:a1", "sha256:lane", true)]
    );
    w.end(&ca, A);

    // The owner's stream begins during the window.
    let w = World::new("bk-ambig-late");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let cb = open_stream(&b, "/grpc");
    let ca = open_stream(&a, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&ca, A);
    w.end(&cb, B);
    assert_eq!(
        w.reports(),
        [rep("base-app:1", "sha256:a1", "sha256:lane", true)]
    );

    // The owner's stream ended before the window: not ambiguous.
    let w = World::new("bk-ambig-before");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let ca = open_stream(&a, "/grpc");
    w.end(&ca, A);
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&cb, B);
    assert_eq!(
        w.reports(),
        [rep("base-app:1", "sha256:a1", "sha256:lane", false)]
    );
}

/// Two streams of one lane that both see the move report it once.
#[test]
fn two_streams_of_one_lane_report_a_move_once() {
    let w = World::new("bk-two");
    let b = lane(&w.h, B);
    let c1 = open_stream(&b, "/grpc");
    let c2 = open_stream(&b, "/session");
    w.build("base-app:1", "sha256:lane");
    w.close(&c1);
    w.end(&c2, B);
    assert_eq!(w.h.svc.bk_running(), 0);
    assert_eq!(w.reports().len(), 1);
}

/// A second overwrite after the first was reported is reported too, and a stream
/// that began after the first overwrite reports what it saw (the tag moving again).
#[test]
fn a_later_overwrite_and_a_late_stream_are_reported() {
    let w = World::new("bk-late");
    let (b, c3) = (lane(&w.h, B), lane(&w.h, "lane-c"));
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    let cc = open_stream(&c3, "/grpc");
    w.build("base-app:1", "sha256:lane2");
    w.end(&cc, "lane-c");
    w.end(&cb, B);
    let reports = w.reports();
    assert!(
        reports.contains(&rep("base-app:1", "sha256:a1", "sha256:lane2", false)),
        "{reports:?}"
    );
    assert!(
        reports.contains(&rep("base-app:1", "sha256:lane", "sha256:lane2", false)),
        "{reports:?}"
    );
    assert_eq!(w.tag("base-app:1").as_deref(), Some("sha256:lane2"));
    assert_eq!(w.writes(), Vec::<String>::new());
}

/// A lane's many REST requests during its build do not hide its overwrite.
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
    assert_eq!(
        w.reports(),
        [rep("base-app:1", "sha256:a1", "sha256:lane", false)]
    );
}

/// A stream that finishes after its workspace was forgotten is reported and
/// leaves nothing behind.
#[test]
fn a_stream_finishing_after_its_workspace_was_forgotten_is_reported_and_leaves_nothing() {
    let w = World::new("bk-forgot");
    for i in 0..8 {
        let ws = format!("gone{i}");
        let b = lane(&w.h, &ws);
        let c = open_stream(&b, "/grpc");
        w.build("base-app:1", &format!("sha256:lane{i}"));
        w.h.svc.forget_scope(&ws).unwrap();
        w.end(&c, &ws);
    }
    assert_eq!(w.h.svc.bk_running(), 0);
    assert_eq!(w.reports().len(), 8);
}

/// A list that cannot be read, at the start or at the end, lets the stream run
/// and is reported; nothing else is said or changed.
#[test]
fn a_failed_list_lets_the_stream_run_and_is_reported() {
    let w = World::new("bk-open-start");
    w.st.lock().unwrap().fail_list = true;
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.st.lock().unwrap().fail_list = false;
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!((w.unchecked(), w.reports().len()), (1, 0));
    assert!(w.h.svc.tag_events()[0].detail.contains("unable to check"));

    let w = World::new("bk-open-end");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.st.lock().unwrap().fail_list = true;
    w.end(&c, B);
    assert_eq!((w.unchecked(), w.reports().len()), (1, 0));
    assert_eq!(w.writes(), Vec::<String>::new());
}

/// At most 256 protected tags are noted per stream, recorded ones first; the
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
    let tags: Vec<String> = w.reports().into_iter().map(|r| r.0).collect();
    assert_eq!(tags, ["t000:1"]);
    assert_eq!(w.unchecked(), 1);
}

/// Recorded tags are noted before unrecorded pulled names, whatever their order
/// by name, when there are more than a stream can watch.
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
    assert_eq!(
        w.reports(),
        [rep("base-app:1", "sha256:a1", "sha256:lane", false)]
    );
}

/// The event list holds 64.
#[test]
fn the_event_list_is_bounded() {
    let w = World::new("bk-events");
    for i in 0..70 {
        let tag = format!("t{i:02}:1");
        w.build(&tag, &format!("sha256:t{i:02}"));
        w.h.svc.ledger.set_tag(A, &tag).unwrap();
    }
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    for i in 0..70 {
        w.build(&format!("t{i:02}:1"), "sha256:lane");
    }
    w.end(&c, B);
    assert_eq!(w.h.svc.tag_events().len(), 64);
}

/// Running state goes when a stream ends and when one is dropped without its check.
#[test]
fn a_stream_leaves_no_state_behind() {
    let w = World::new("bk-state");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    assert_eq!(w.h.svc.bk_running(), 1);
    w.end(&c, B);
    assert_eq!(w.h.svc.bk_running(), 0);
    let scope = super::super::Scope {
        svc: w.h.svc.clone(),
        auth: Authority {
            workspace: B.into(),
            ..w.h.auth.clone()
        },
    };
    let watch = scope.bk_begin();
    assert_eq!(w.h.svc.bk_running(), 1);
    drop(watch);
    assert_eq!(w.h.svc.bk_running(), 0);
}

/// The owner puts the tag back (as the report says) and the lane's next build, a
/// cached one with the same image, moves it again: reported again.
#[test]
fn a_repeated_identical_overwrite_is_reported_again() {
    let w = World::new("bk-repeat");
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(tag_as(&a, "sha256:a1", "base-app"), 201);
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(w.reports().len(), 2);
}

/// An owner's request that is in the engine when the stream begins, and lands
/// during it, makes the report ambiguous (and so does one that lands while the
/// first list is being read, and an owner's stream that runs during that list).
#[test]
fn a_request_in_flight_at_the_start_makes_the_report_ambiguous() {
    let (gate, release) = {
        let r = Arc::new(AtomicBool::new(false));
        (r.clone(), r)
    };
    let w = World::with("bk-inflight", |e| {
        let g = gate.clone();
        Arc::new(move |req: &Req, s: &mut UnixStream| {
            if req.target.starts_with("/images/src/tag") {
                let until = Instant::now() + Duration::from_secs(5);
                while !g.load(Ordering::SeqCst) && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            e(req, s)
        })
    });
    let (a, b) = (lane(&w.h, A), lane(&w.h, B));
    let tagging = std::thread::spawn(move || tag_as(&a, "src", "base-app"));
    assert!(wait_for(Duration::from_secs(5), || w
        .h
        .engine
        .saw("POST", "/images/src/tag")
        == 1));
    let c = open_stream(&b, "/grpc");
    release.store(true, Ordering::SeqCst);
    assert_eq!(tagging.join().unwrap(), 201);
    w.end(&c, B);
    assert_eq!(
        w.reports(),
        [rep("base-app:1", "sha256:a1", "sha256:src", true)]
    );
}

#[test]
fn a_request_or_an_owner_stream_during_the_first_list_makes_the_report_ambiguous() {
    for owner_stream in [false, true] {
        let w = World::new(&format!("bk-dl{}", u8::from(owner_stream)));
        let (a, b) = (lane(&w.h, A), lane(&w.h, B));
        w.st.lock().unwrap().list_delay = Some(Duration::from_millis(800));
        let opening = std::thread::spawn({
            let b = b.clone();
            move || open_stream(&b, "/grpc")
        });
        assert!(wait_for(Duration::from_secs(5), || w
            .h
            .engine
            .saw("GET", "/images/json")
            == 1));
        if owner_stream {
            let ca = open_stream(&a, "/grpc");
            w.build("base-app:1", "sha256:src");
            w.end(&ca, A);
        } else {
            assert_eq!(tag_as(&a, "src", "base-app"), 201);
        }
        let c = opening.join().unwrap();
        w.end(&c, B);
        assert_eq!(
            w.reports(),
            [rep("base-app:1", "sha256:a1", "sha256:src", true)],
            "owner_stream={owner_stream}"
        );
    }
}

/// A stream that stays open does not remember the workspaces of streams that came
/// and went and own nothing it watches.
#[test]
fn a_long_stream_keeps_no_unrelated_workspaces() {
    let w = World::new("bk-longstream");
    let b = lane(&w.h, B);
    let long = open_stream(&b, "/grpc");
    for i in 0..20 {
        let ws = format!("gone{i}");
        let s = lane(&w.h, &ws);
        let c = open_stream(&s, "/grpc");
        w.h.svc.forget_scope(&ws).unwrap();
        w.end(&c, &ws);
    }
    assert_eq!(w.h.svc.bk_others(), 0);
    // The owner's own stream is remembered.
    let a = lane(&w.h, A);
    let ca = open_stream(&a, "/grpc");
    assert!(w.h.svc.bk_others() >= 1);
    w.end(&ca, A);
    w.end(&long, B);
}

/// A lane cannot age the reports out: "unable to check" is kept once, and the
/// oldest report of a tag (the owner's original image) is kept when the list is full.
#[test]
fn reports_are_not_aged_out_by_unchecked_events_or_repeated_overwrites() {
    let w = World::new("bk-evict");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane0");
    w.end(&c, B);
    for _ in 0..70 {
        w.st.lock().unwrap().fail_list = true;
        let c = open_stream(&b, "/grpc");
        w.end(&c, B);
    }
    assert_eq!(w.unchecked(), 1);
    assert_eq!(w.reports().len(), 1);
    w.st.lock().unwrap().fail_list = false;
    for i in 1..80 {
        let c = open_stream(&b, "/grpc");
        w.build("base-app:1", &format!("sha256:lane{i}"));
        w.end(&c, B);
    }
    let reports = w.reports();
    assert_eq!(w.h.svc.tag_events().len(), 64);
    assert_eq!(
        reports[0],
        rep("base-app:1", "sha256:a1", "sha256:lane0", false)
    );
}

/// What a report tells the user to do, and whose stream it names.
#[test]
fn the_recovery_text_is_conditional_and_the_stream_is_named_with_its_overlap() {
    let w = World::new("bk-text");
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.build("postgres:16", "sha256:lane2");
    w.end(&c, B);
    let events = w.h.svc.tag_events();
    let owned = events.iter().find(|e| e.tag == "base-app:1").unwrap();
    assert!(
        owned
            .detail
            .contains("if image sha256:a1 still exists, `docker tag sha256:a1 base-app:1` run in workspace lane-a puts it back (else rebuild it)"),
        "{}",
        owned.detail
    );
    assert!(
        owned.to_string().contains("or one that ran with it"),
        "{owned}"
    );
    let pulled = events.iter().find(|e| e.tag == "postgres:16").unwrap();
    assert!(
        pulled
            .detail
            .contains("`docker pull postgres:16` fetches the registry's current image, not necessarily sha256:pg"),
        "{}",
        pulled.detail
    );
}

/// Streams that begin while another stream is reading its first list are
/// remembered only if they own something it watches.
#[test]
fn workspaces_met_during_the_first_list_are_trimmed_afterwards() {
    let w = World::new("bk-trim");
    let b = lane(&w.h, B);
    w.st.lock().unwrap().list_delay = Some(Duration::from_millis(800));
    let opening = std::thread::spawn(move || open_stream(&b, "/grpc"));
    assert!(wait_for(Duration::from_secs(5), || w
        .h
        .engine
        .saw("GET", "/images/json")
        == 1));
    let other = lane(&w.h, "lane-z");
    let cz = open_stream(&other, "/grpc");
    let cb = opening.join().unwrap();
    assert_eq!(w.h.svc.bk_others(), 0);
    w.end(&cz, "lane-z");
    w.end(&cb, B);
}

/// A request that reserves a name between the stream's look at the held names and
/// its window (the reviewer's interleaving) is not missed: the tag table stays
/// locked until the window exists, so the request waits, then finds the window.
#[test]
fn a_request_between_the_held_names_and_the_window_makes_the_report_ambiguous() {
    let (gate, release) = {
        let r = Arc::new(AtomicBool::new(false));
        (r.clone(), r)
    };
    let w = World::with("bk-atomic", |e| {
        let g = gate.clone();
        Arc::new(move |req: &Req, s: &mut UnixStream| {
            if req.target.starts_with("/images/src/tag") {
                let until = Instant::now() + Duration::from_secs(5);
                while !g.load(Ordering::SeqCst) && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            e(req, s)
        })
    });
    let (a, b) = (lane(&w.h, A), lane(&w.h, "lane-pause"));
    let (reached, resume) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    *super::super::bk_watch::PAUSE.lock().unwrap() =
        Some(("lane-pause".into(), reached.clone(), resume.clone()));
    let opening = std::thread::spawn(move || open_stream(&b, "/grpc"));
    assert!(wait_for(Duration::from_secs(5), || reached.load(Ordering::SeqCst)));
    let tagging = std::thread::spawn(move || tag_as(&a, "src", "base-app"));
    std::thread::sleep(Duration::from_millis(300));
    resume.store(true, Ordering::SeqCst);
    let c = opening.join().unwrap();
    assert!(wait_for(Duration::from_secs(5), || w
        .h
        .engine
        .saw("POST", "/images/src/tag")
        == 1));
    release.store(true, Ordering::SeqCst);
    assert_eq!(tagging.join().unwrap(), 201);
    w.end(&c, "lane-pause");
    *super::super::bk_watch::PAUSE.lock().unwrap() = None;
    assert_eq!(
        w.reports(),
        [rep("base-app:1", "sha256:a1", "sha256:src", true)]
    );
}

/// While a stream reads its first list, streams that begin are not remembered by
/// name (only that one began, which makes its reports ambiguous).
#[test]
fn streams_beginning_during_the_first_list_are_not_remembered_by_name() {
    let w = World::new("bk-pending");
    let b = lane(&w.h, B);
    w.st.lock().unwrap().list_delay = Some(Duration::from_millis(800));
    let opening = std::thread::spawn(move || open_stream(&b, "/grpc"));
    assert!(wait_for(Duration::from_secs(5), || w
        .h
        .engine
        .saw("GET", "/images/json")
        == 1));
    for i in 0..20 {
        let ws = format!("gone{i}");
        let s = lane(&w.h, &ws);
        let c = open_stream(&s, "/grpc");
        w.h.svc.forget_scope(&ws).unwrap();
        w.end(&c, &ws);
    }
    assert_eq!(w.h.svc.bk_others(), 0);
    let c = opening.join().unwrap();
    w.build("base-app:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!(
        w.reports(),
        [rep("base-app:1", "sha256:a1", "sha256:lane", true)]
    );
}

/// A name too long for a tag is said to be unwatched, never skipped in silence; an
/// untagged image (`<none>:<none>`) is not a name.
#[test]
fn a_name_too_long_to_watch_is_reported_and_an_untagged_image_is_not() {
    let w = World::new("bk-longname");
    w.st.lock()
        .unwrap()
        .add("<none>:<none>", "sha256:dangling", false);
    let b = lane(&w.h, B);
    let c = open_stream(&b, "/grpc");
    w.end(&c, B);
    w.quiet();
    let long = format!("{}:{}", "r".repeat(200), "t".repeat(100));
    w.st.lock().unwrap().add(&long, "sha256:long", true);
    let c = open_stream(&b, "/grpc");
    w.end(&c, B);
    assert_eq!(w.unchecked(), 1);
    assert!(w.h.svc.tag_events()[0].detail.contains("too long to watch"));
}

/// At the cap "unable to check" is the first to go, as the docs say (not the oldest
/// report).
#[test]
fn unable_to_check_goes_first_at_the_cap() {
    let w = World::new("bk-cap-unchecked");
    let b = lane(&w.h, B);
    for i in 0..64 {
        let tag = format!("t{i:02}:1");
        w.build(&tag, &format!("sha256:t{i:02}"));
        w.h.svc.ledger.set_tag(A, &tag).unwrap();
    }
    let c = open_stream(&b, "/grpc");
    for i in 0..63 {
        w.build(&format!("t{i:02}:1"), "sha256:lane");
    }
    w.end(&c, B);
    w.st.lock().unwrap().fail_list = true;
    let c = open_stream(&b, "/grpc");
    w.end(&c, B);
    w.st.lock().unwrap().fail_list = false;
    assert_eq!((w.unchecked(), w.reports().len()), (1, 63));
    let c = open_stream(&b, "/grpc");
    w.build("t63:1", "sha256:lane");
    w.end(&c, B);
    assert_eq!((w.unchecked(), w.reports().len()), (0, 64));
    assert_eq!(w.reports()[0].0, "t00:1");
}

/// Reports say when several builds ran at once (the workspace named may not be the
/// one that moved the tag), in a field and in the text.
#[test]
fn a_report_says_when_builds_overlapped() {
    let w = World::new("bk-overlap");
    let b = lane(&w.h, B);
    let cb = open_stream(&b, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&cb, B);
    let alone = w.h.svc.tag_events().pop().unwrap();
    assert!(
        !alone.overlapped && !alone.detail.contains("Several builds"),
        "{alone:?}"
    );

    let w = World::new("bk-overlap2");
    let (b, c3) = (lane(&w.h, B), lane(&w.h, "lane-c"));
    let cb = open_stream(&b, "/grpc");
    let cc = open_stream(&c3, "/grpc");
    w.build("base-app:1", "sha256:lane");
    w.end(&cc, "lane-c");
    w.end(&cb, B);
    let together = w.h.svc.tag_events().pop().unwrap();
    assert!(
        together.overlapped && together.detail.contains("Several builds ran at once"),
        "{together:?}"
    );
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
    assert_eq!(events[0]["kind"], "changed");
    assert_eq!(events[0]["owner"], A);
    assert_eq!(events[0]["previous"], "sha256:a1");
    assert_eq!(events[0]["current"], "sha256:lane");
    assert_eq!(events[0]["ambiguous"], false);
    assert_eq!(events[0]["overlapped"], false);
    assert!(
        events[0]["detail"]
            .as_str()
            .unwrap()
            .contains("docker tag sha256:a1 base-app:1")
    );
    for (who, sock) in [
        ("a lane's job", b.clone()),
        ("a base job", as_attempt("base", "job1")),
        ("a base shell", as_attempt("base", "shell")),
        ("a lane's status-named attempt", as_attempt(B, "status")),
    ] {
        let (status, body) = call(&sock, "GET", "/_marsh/tag-events", None);
        assert_eq!(status, 403, "{who} read the events: {body}");
    }
    // The ambiguity flag travels too.
    let a = lane(&w.h, A);
    let c = open_stream(&b, "/grpc");
    assert_eq!(tag_as(&a, "src", "base-app"), 201);
    w.end(&c, B);
    let (_, body) = call(&status_read, "GET", "/_marsh/tag-events", None);
    let answer: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        answer["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["ambiguous"] == true && e["current"] == "sha256:src"),
        "{body}"
    );
    // So does the overlap flag.
    let c3 = lane(&w.h, "lane-c");
    let cc = open_stream(&c3, "/grpc");
    let c = open_stream(&b, "/grpc");
    w.build("postgres:16", "sha256:lane");
    w.end(&c, B);
    w.end(&cc, "lane-c");
    let (_, body) = call(&status_read, "GET", "/_marsh/tag-events", None);
    let answer: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        answer["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["tag"] == "postgres:16" && e["overlapped"] == true),
        "{body}"
    );
    // The route takes no parameters, nor does it answer other methods.
    for (method, target) in [
        ("GET", "/_marsh/tag-events?since=1"),
        ("POST", "/_marsh/tag-events"),
    ] {
        let (status, _) = call(&status_read, method, target, None);
        assert!(
            status == 403 || status == 405 || status == 400,
            "{method} {target} answered {status}"
        );
    }
    assert_eq!(w.h.engine.saw("GET", "/_marsh"), 0);
}
