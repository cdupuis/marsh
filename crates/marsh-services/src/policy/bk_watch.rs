//! Detection of an image tag a `BuildKit` stream moved (DA1-02, DA1-04).
//!
//! `/grpc` and `/session` are relayed unread, so the tag a `docker buildx build
//! -t` names is not seen. Instead of preventing it, the agent keeps, per tag a
//! workspace may not move, the image the tag *legitimately* has (`Bk::legit`), and
//! when a stream of that workspace ends it puts a changed tag back to that image
//! and raises an event, unless a REST request or a build of the tag's owner could
//! explain the change (then the event is raised and nothing is restored). Nothing
//! is ever deleted, and a list that cannot be read lets the stream run unwatched,
//! with an event.
//!
//! The legitimate image is read from the engine only when no stream is running
//! (nothing can then have moved the tag but a REST request, which is the owner's
//! or a pull), under the tag lock, and is forgotten again as soon as a REST
//! request touches the name or a stream of its owner begins. A stream that begins
//! while others run uses what is recorded, never what the tag is now, so an
//! overwrite that is already there is not taken for the tag's state.
//!
//! Not prevention: while a stream runs, another workspace's tag may point at
//! the stream's image, and a change made after the stream ended is not seen.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use super::{Scope, Services};
use crate::ledger::now;

/// Protected tags watched per stream.
const MAX_WATCHED: usize = 256;
/// Legitimate images remembered.
const MAX_LEGIT: usize = 4096;
/// Events kept for `Services::tag_events`.
const MAX_EVENTS: usize = 64;

/// What the agent saw and did about a tag a `BuildKit` stream changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagEvent {
    pub at: u64,
    /// The workspace whose stream ran.
    pub workspace: String,
    /// The tag; empty for an event about the whole stream.
    pub tag: String,
    pub kind: TagEventKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagEventKind {
    /// The tag was moved back to its image.
    Restored,
    /// The tag changed and was left as it is (or could not be moved back).
    NotRestored,
    /// The stream could not be checked, wholly or in part.
    Unchecked,
}

impl std::fmt::Display for TagEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BuildKit stream of workspace {}: ", self.workspace)?;
        match self.kind {
            TagEventKind::Restored => write!(f, "image tag {} changed; restored: ", self.tag),
            TagEventKind::NotRestored => {
                write!(f, "image tag {} changed; not restored: ", self.tag)
            }
            TagEventKind::Unchecked => write!(f, "not fully checked: "),
        }?;
        f.write_str(&self.detail)
    }
}

/// The image a tag legitimately has, and whose it is (`None`: a name on a
/// pulled image that nobody recorded).
struct Legit {
    image: String,
    owner: Option<(String, u64)>,
}

/// A tag some running stream watches: refs, and the latest REST request that
/// held its name (sequence, workspace) since it was first watched.
struct Watching {
    refs: usize,
    touched: Option<(u64, String)>,
}

/// Shared state of the detection, under its own lock (taken after `tag_res`).
#[derive(Default)]
pub(super) struct Bk {
    epoch: u64,
    next_stream: u64,
    /// Streams running (until their check is done): id to workspace and start.
    active: HashMap<u64, (String, u64)>,
    /// Per workspace, the epoch its latest stream ended, kept only while a
    /// stream that began before it still runs.
    last_end: HashMap<String, u64>,
    legit: HashMap<String, Legit>,
    watching: HashMap<String, Watching>,
    events: VecDeque<TagEvent>,
}

impl Bk {
    fn tick(&mut self) -> u64 {
        self.epoch += 1;
        self.epoch
    }

    /// A REST request of `ws` holds these names: what was recorded about them is
    /// no longer known to be right.
    pub(super) fn touch(&mut self, tags: &[String], ws: &str) {
        for tag in tags {
            self.legit.remove(tag);
            let at = self.epoch + 1;
            if let Some(w) = self.watching.get_mut(tag) {
                w.touched = Some((at, ws.to_owned()));
                self.epoch = at;
            }
        }
    }

    /// Did `owner` have a stream running at any time since `start`?
    fn busy_since(&self, owner: &str, start: u64) -> bool {
        self.active.values().any(|(w, _)| w == owner)
            || self.last_end.get(owner).is_some_and(|end| *end > start)
    }

    pub(super) fn forget(&mut self, workspace: &str) {
        self.last_end.remove(workspace);
        self.legit
            .retain(|_, l| l.owner.as_ref().is_none_or(|(o, _)| o != workspace));
    }

    fn push_event(&mut self, ev: TagEvent) {
        self.events.push_back(ev);
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }
}

/// A tag the stream's workspace may not move, as the stream began.
struct Watched {
    tag: String,
    /// The image the tag legitimately has, or, when that is not known, the one
    /// it had when the stream began (then `Bk::legit` has no such entry).
    image: String,
    /// The recorded owner and its claim (`TagRec::claim`); `None`: a name on a
    /// pulled image that nobody recorded.
    owner: Option<(String, u64)>,
}

/// What a check found: raised once the tag lock is released.
type Finding = (String, TagEventKind, String);

/// One running `BuildKit` stream: ends with [`Watch::finish`], or silently when
/// dropped.
pub(super) struct Watch {
    svc: Arc<Services>,
    id: u64,
    ws: String,
    start: u64,
    tags: Vec<Watched>,
    left: bool,
}

#[cfg(test)]
thread_local! {
    /// Set while this thread holds the tag lock for a restore.
    static HOLDING_TAGS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl Services {
    pub(super) fn lock_bk(&self) -> std::sync::MutexGuard<'_, Bk> {
        self.bk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The latest events, oldest first (at most 64).
    #[must_use]
    pub fn tag_events(&self) -> Vec<TagEvent> {
        self.lock_bk().events.iter().cloned().collect()
    }

    /// Sizes of the state kept: running streams, legitimate images, watched
    /// tags, workspaces with a stream end.
    #[cfg(test)]
    pub(super) fn bk_sizes(&self) -> [usize; 4] {
        let bk = self.lock_bk();
        [
            bk.active.len(),
            bk.legit.len(),
            bk.watching.len(),
            bk.last_end.len(),
        ]
    }

    /// Fill the table of legitimate images with names no tag has.
    #[cfg(test)]
    pub(super) fn bk_fill_legit(&self, n: usize) {
        let mut bk = self.lock_bk();
        for i in 0..n {
            bk.legit.insert(
                format!("filler{i}:1"),
                Legit {
                    image: "sha256:x".into(),
                    owner: None,
                },
            );
        }
    }

    fn raise(&self, workspace: &str, tag: &str, kind: TagEventKind, detail: String) {
        #[cfg(test)]
        assert!(
            !HOLDING_TAGS.with(std::cell::Cell::get),
            "an event was raised under the tag lock"
        );
        let ev = TagEvent {
            at: now(),
            workspace: workspace.to_owned(),
            tag: tag.to_owned(),
            kind,
            detail,
        };
        eprintln!("marsh-services: {ev}");
        self.lock_bk().push_event(ev);
    }

    /// Every tagged image the engine has: canonical tag, image ID, pulled.
    fn tagged_images(&self) -> Result<Vec<(String, String, bool)>, String> {
        let (status, body) = self
            .up_request("GET", "/images/json", None)
            .map_err(|e| format!("the engine's image list failed: {e}"))?;
        if status != 200 {
            return Err(format!("the engine's image list answered {status}"));
        }
        let list: Vec<serde_json::Value> = serde_json::from_slice(&body)
            .map_err(|_| "the engine's image list is not readable".to_owned())?;
        let mut out = Vec::new();
        for image in &list {
            let Some(id) = image.get("Id").and_then(|i| i.as_str()) else {
                continue;
            };
            let pulled = image
                .get("RepoDigests")
                .and_then(|d| d.as_array())
                .is_some_and(|d| !d.is_empty());
            let tags = image.get("RepoTags").and_then(|t| t.as_array());
            for tag in tags.into_iter().flatten().filter_map(|t| t.as_str()) {
                if let Ok(tag) = crate::policy::admit::canonical_tag(tag, None) {
                    out.push((tag, id.to_owned(), pulled));
                }
            }
        }
        Ok(out)
    }
}

impl Scope {
    /// A `BuildKit` stream of this workspace is about to run: note the tags it
    /// may not move and what each legitimately is.
    pub(super) fn bk_begin(&self) -> Watch {
        let svc = &self.svc;
        let ws = self.auth.workspace.clone();
        // The tag lock is held across the engine's list: no REST request holds
        // or releases a name meanwhile, so what is read is what the requests
        // that finished left, and every later request touches the name.
        let res = svc.lock_tags();
        let (id, start, clean) = {
            let mut bk = svc.lock_bk();
            let id = bk.next_stream;
            bk.next_stream += 1;
            let start = bk.tick();
            let clean = bk.active.is_empty();
            bk.active.insert(id, (ws.clone(), start));
            // This workspace's own build may move its own tags.
            bk.legit
                .retain(|_, l| l.owner.as_ref().is_none_or(|(o, _)| *o != ws));
            (id, start, clean)
        };
        let mut watch = Watch {
            svc: Arc::clone(svc),
            id,
            ws,
            start,
            tags: Vec::new(),
            left: false,
        };
        let mut findings = Vec::new();
        match svc.tagged_images() {
            Ok(images) => findings = watch.protect(images, &res, clean),
            Err(why) => findings.push((
                String::new(),
                TagEventKind::Unchecked,
                format!("{why}; no tag was recorded, so none can be restored"),
            )),
        }
        drop(res);
        watch.raise_all(findings);
        watch
    }
}

impl Watch {
    fn raise_all(&self, findings: Vec<Finding>) {
        for (tag, kind, detail) in findings {
            self.svc.raise(&self.ws, &tag, kind, detail);
        }
    }

    fn protect(
        &mut self,
        images: Vec<(String, String, bool)>,
        res: &super::TagRes,
        clean: bool,
    ) -> Vec<Finding> {
        let mut found = Vec::new();
        // Names known as pulled ones: a stream's overwrite turns one into what
        // looks like an unrecorded local name, and a later stream must still
        // watch it against the image that was pulled.
        let known: std::collections::HashSet<String> = self
            .svc
            .lock_bk()
            .legit
            .iter()
            .filter(|(_, l)| l.owner.is_none())
            .map(|(tag, _)| tag.clone())
            .collect();
        for (tag, image, pulled) in images {
            let owner = match self.svc.ledger.tag_owner(&tag) {
                Some(rec) if rec.scope == self.ws => continue,
                Some(rec) => Some((rec.scope, rec.claim)),
                None if pulled || known.contains(&tag) => None,
                None => continue,
            };
            // A request holds the name now: its engine call may not be done.
            if res.contains_key(&tag) {
                continue;
            }
            found.push((tag, image, owner));
        }
        // Recorded tags first: they are the ones a lane's own work can collide with.
        found.sort_by(|a, b| (a.2.is_none(), &a.0).cmp(&(b.2.is_none(), &b.0)));
        let mut findings = Vec::new();
        if found.len() > MAX_WATCHED {
            findings.push((
                String::new(),
                TagEventKind::Unchecked,
                format!(
                    "{} protected image tags; only the first {MAX_WATCHED} are watched",
                    found.len()
                ),
            ));
            found.truncate(MAX_WATCHED);
        }
        let mut bk = self.svc.lock_bk();
        for (tag, now_image, owner) in found {
            // What is recorded is used even when the tag differs now: it has
            // been moved already. Else the tag is read as legitimate only when
            // no other stream runs (and so none can have moved it).
            let recorded = bk.legit.get(&tag).filter(|l| l.owner == owner);
            let image = match recorded {
                Some(l) => l.image.clone(),
                None if clean && bk.legit.len() < MAX_LEGIT => {
                    bk.legit.insert(
                        tag.clone(),
                        Legit {
                            image: now_image.clone(),
                            owner: owner.clone(),
                        },
                    );
                    now_image
                }
                None => now_image,
            };
            bk.watching
                .entry(tag.clone())
                .or_insert(Watching {
                    refs: 0,
                    touched: None,
                })
                .refs += 1;
            self.tags.push(Watched { tag, image, owner });
        }
        findings
    }

    /// Unregister the stream (idempotent).
    fn leave(&mut self) {
        if self.left {
            return;
        }
        self.left = true;
        let mut bk = self.svc.lock_bk();
        bk.active.remove(&self.id);
        let end = bk.tick();
        bk.last_end.insert(self.ws.clone(), end);
        // An end is only needed by a stream that began before it.
        match bk.active.values().map(|(_, start)| *start).min() {
            Some(oldest) => bk.last_end.retain(|_, at| *at > oldest),
            None => bk.last_end.clear(),
        }
        for w in &self.tags {
            if let Some(t) = bk.watching.get_mut(&w.tag) {
                t.refs -= 1;
                if t.refs == 0 {
                    bk.watching.remove(&w.tag);
                }
            }
        }
    }

    /// The stream ended: put back what it moved. The stream counts as running
    /// until its check is done, so that none that begins meanwhile takes a tag
    /// it has moved for the tag's state.
    pub(super) fn finish(mut self) {
        let findings = self.check();
        self.leave();
        self.raise_all(findings);
    }

    fn check(&self) -> Vec<Finding> {
        if self.tags.is_empty() {
            return Vec::new();
        }
        let now = match self.svc.tagged_images() {
            Ok(images) => images
                .into_iter()
                .map(|(tag, id, _)| (tag, id))
                .collect::<HashMap<_, _>>(),
            Err(why) => {
                return vec![(
                    String::new(),
                    TagEventKind::Unchecked,
                    format!("{why}; the stream's changes to image tags are unknown"),
                )];
            }
        };
        self.tags
            .iter()
            .filter(|w| now.get(&w.tag) != Some(&w.image))
            .filter_map(|w| self.settle(w))
            .collect()
    }

    /// `w`'s tag is not what it should be: restore it unless something else
    /// explains it.
    fn settle(&self, w: &Watched) -> Option<Finding> {
        let svc = &self.svc;
        // The claim's lock, held across the re-check and the engine call: a
        // request that would change the name waits for the restore.
        let _claims = svc.lock_tags();
        #[cfg(test)]
        let _marked = Marked::new();
        let say = |kind, detail: String| Some((w.tag.clone(), kind, detail));
        let touched = svc
            .lock_bk()
            .watching
            .get(&w.tag)
            .and_then(|t| t.touched.clone())
            .filter(|(at, _)| *at > self.start);
        if let Some((_, by)) = touched {
            // Someone's own request changed it meanwhile. If it was this
            // workspace's own, that and the build cannot be told apart.
            return (by == self.ws).then(|| {
                (
                    w.tag.clone(),
                    TagEventKind::NotRestored,
                    "this workspace also pulled or tagged it during the build, so the build's change cannot be told from it".to_owned(),
                )
            });
        }
        let rec = svc.ledger.tag_owner(&w.tag);
        if rec.as_ref().map(|r| (r.scope.clone(), r.claim)) != w.owner {
            return None;
        }
        if let Some((owner, _)) = &w.owner
            && svc.lock_bk().busy_since(owner, self.start)
        {
            return say(
                TagEventKind::NotRestored,
                format!(
                    "it is workspace {owner}'s, which was building too, so the change may be its own"
                ),
            );
        }
        let known = svc
            .lock_bk()
            .legit
            .get(&w.tag)
            .is_some_and(|l| l.image == w.image);
        if !known {
            return say(
                TagEventKind::NotRestored,
                "other builds were running when this one began, so which image the tag should have is not known".to_owned(),
            );
        }
        match svc.image_info(&w.tag) {
            Ok((_, _, id)) if id.as_deref() == Some(w.image.as_str()) => return None,
            Ok(_) => {}
            Err(r) => return say(TagEventKind::NotRestored, r.msg),
        }
        let owner = w
            .owner
            .as_ref()
            .map_or("a pulled image".to_owned(), |(o, _)| {
                format!("workspace {o}'s")
            });
        let (repo, tag) = w.tag.rsplit_once(':').unwrap_or((&w.tag, "latest"));
        let path = format!("/images/{}/tag?repo={repo}&tag={tag}", w.image);
        match svc.up_request("POST", &path, None) {
            Ok((201, _)) => say(
                TagEventKind::Restored,
                format!(
                    "it is {owner}, and a build moved it; put back on {}",
                    w.image
                ),
            ),
            Ok((status, _)) => say(
                TagEventKind::NotRestored,
                format!("it is {owner}; the engine refused to put it back ({status})"),
            ),
            Err(e) => say(
                TagEventKind::NotRestored,
                format!("it is {owner}; putting it back failed: {e}"),
            ),
        }
    }
}

#[cfg(test)]
struct Marked;

#[cfg(test)]
impl Marked {
    fn new() -> Self {
        HOLDING_TAGS.with(|h| h.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for Marked {
    fn drop(&mut self) {
        HOLDING_TAGS.with(|h| h.set(false));
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.leave();
    }
}
