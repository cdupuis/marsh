//! Detection of an image tag a `BuildKit` stream moved (DA1-02, DA1-04).
//!
//! `/grpc` and `/session` are relayed unread, so the tag a `docker buildx build
//! -t` names is not seen. Instead of preventing it, the agent looks before and
//! after: when a stream of workspace S starts, every tag S may not move is
//! recorded with its image ID (tags recorded to other workspaces, and
//! unrecorded names on pulled images); when it ends, a tag whose image changed
//! is put back and an event is raised, unless a REST request, or a build of the
//! tag's owner, could explain the change (then the event is raised and nothing
//! is restored). Nothing is ever deleted, and a snapshot that cannot be taken
//! lets the stream run unwatched, with an event.
//!
//! Not prevention: while a stream runs, another workspace's tag may point at
//! the stream's image, and a change that is put back and changes again after the
//! stream ended is not seen.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use super::{Scope, Services};
use crate::ledger::now;

/// Protected tags watched per stream.
const MAX_WATCHED: usize = 256;
/// REST tag requests remembered; a stream that outlasts them treats every
/// protected tag as touched.
const MAX_TOUCHES: usize = 4096;
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

/// Shared state of the detection, under its own lock (taken after `tag_res`).
#[derive(Default)]
pub(super) struct Bk {
    epoch: u64,
    /// REST holds on tag names, oldest first.
    touches: VecDeque<(u64, String)>,
    /// The epoch of the newest touch forgotten.
    forgotten: u64,
    next_stream: u64,
    /// Streams running: id to workspace and start epoch.
    active: HashMap<u64, (String, u64)>,
    /// Per workspace, the epoch its latest stream ended.
    last_end: HashMap<String, u64>,
    events: VecDeque<TagEvent>,
}

impl Bk {
    fn tick(&mut self) -> u64 {
        self.epoch += 1;
        self.epoch
    }

    pub(super) fn touch(&mut self, tags: &[String]) {
        for tag in tags {
            let at = self.tick();
            self.touches.push_back((at, tag.clone()));
        }
        while self.touches.len() > MAX_TOUCHES {
            if let Some((at, _)) = self.touches.pop_front() {
                self.forgotten = at;
            }
        }
    }

    fn touched_since(&self, tag: &str, start: u64) -> bool {
        self.forgotten > start || self.touches.iter().any(|(at, t)| *at > start && t == tag)
    }

    /// Did `owner` have a stream running at any time since `start`?
    fn busy_since(&self, owner: &str, start: u64) -> bool {
        self.active.values().any(|(w, _)| w == owner)
            || self.last_end.get(owner).is_some_and(|end| *end > start)
    }

    pub(super) fn forget(&mut self, workspace: &str) {
        self.last_end.remove(workspace);
    }
}

/// A tag the stream's workspace may not move, as the stream began.
struct Watched {
    tag: String,
    image: String,
    /// The recorded owner and its claim (`TagRec::claim`); `None`: a name on a
    /// pulled image that nobody recorded.
    owner: Option<(String, u64)>,
}

/// One running `BuildKit` stream: ends with [`Watch::finish`], or silently when
/// dropped.
pub(super) struct Watch {
    svc: Arc<Services>,
    id: u64,
    ws: String,
    start: u64,
    /// Names a REST request already held when the stream began: its engine
    /// call may land after the snapshot.
    held: HashSet<String>,
    tags: Vec<Watched>,
    left: bool,
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

    fn raise(&self, workspace: &str, tag: &str, kind: TagEventKind, detail: String) {
        let ev = TagEvent {
            at: now(),
            workspace: workspace.to_owned(),
            tag: tag.to_owned(),
            kind,
            detail,
        };
        eprintln!("marsh-services: {ev}");
        let mut bk = self.lock_bk();
        bk.events.push_back(ev);
        while bk.events.len() > MAX_EVENTS {
            bk.events.pop_front();
        }
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
    /// A `BuildKit` stream of this workspace is about to run: record the tags it
    /// may not move.
    pub(super) fn bk_begin(&self) -> Watch {
        let svc = &self.svc;
        let ws = self.auth.workspace.clone();
        // Under the tag lock, so that a request that reserves a name is either in
        // `held` or touches it after `start`.
        let (id, start, held) = {
            let res = svc.lock_tags();
            let mut bk = svc.lock_bk();
            let id = bk.next_stream;
            bk.next_stream += 1;
            let start = bk.tick();
            bk.active.insert(id, (ws.clone(), start));
            (id, start, res.keys().cloned().collect())
        };
        let mut watch = Watch {
            svc: Arc::clone(svc),
            id,
            ws,
            start,
            held,
            tags: Vec::new(),
            left: false,
        };
        match svc.tagged_images() {
            Ok(images) => watch.protect(images),
            Err(why) => svc.raise(
                &watch.ws,
                "",
                TagEventKind::Unchecked,
                format!("{why}; no tag was recorded, so none can be restored"),
            ),
        }
        watch
    }
}

impl Watch {
    fn protect(&mut self, images: Vec<(String, String, bool)>) {
        let mut found = Vec::new();
        for (tag, image, pulled) in images {
            let owner = match self.svc.ledger.tag_owner(&tag) {
                Some(rec) if rec.scope == self.ws => continue,
                Some(rec) => Some((rec.scope, rec.claim)),
                None if pulled => None,
                None => continue,
            };
            found.push(Watched { tag, image, owner });
        }
        // Recorded tags first: they are the ones a lane's own work can collide with.
        found.sort_by(|a, b| (a.owner.is_none(), &a.tag).cmp(&(b.owner.is_none(), &b.tag)));
        if found.len() > MAX_WATCHED {
            self.svc.raise(
                &self.ws,
                "",
                TagEventKind::Unchecked,
                format!(
                    "{} protected image tags; only the first {MAX_WATCHED} are watched",
                    found.len()
                ),
            );
            found.truncate(MAX_WATCHED);
        }
        self.tags = found;
    }

    fn leave(&mut self) -> u64 {
        let mut bk = self.svc.lock_bk();
        bk.active.remove(&self.id);
        let end = bk.tick();
        if !self.left {
            bk.last_end.insert(self.ws.clone(), end);
            self.left = true;
        }
        end
    }

    /// The stream ended: put back what it moved.
    pub(super) fn finish(mut self) {
        self.leave();
        if self.tags.is_empty() {
            return;
        }
        let now = match self.svc.tagged_images() {
            Ok(images) => images
                .into_iter()
                .map(|(tag, id, _)| (tag, id))
                .collect::<HashMap<_, _>>(),
            Err(why) => {
                self.svc.raise(
                    &self.ws,
                    "",
                    TagEventKind::Unchecked,
                    format!("{why}; the stream's changes to image tags are unknown"),
                );
                return;
            }
        };
        for w in &self.tags {
            if now.get(&w.tag) != Some(&w.image) {
                self.settle(w);
            }
        }
    }

    /// `w`'s tag is not what it was: restore it unless something else explains it.
    fn settle(&self, w: &Watched) {
        let svc = &self.svc;
        // The claim's lock, held across the re-check and the engine call: a
        // request that would change the name waits for the restore. (One that
        // holds the name now began after `start`, so it touched it.)
        let _claims = svc.lock_tags();
        if self.held.contains(&w.tag) {
            return;
        }
        if svc.lock_bk().touched_since(&w.tag, self.start) {
            return;
        }
        let rec = svc.ledger.tag_owner(&w.tag);
        let same = rec.as_ref().map(|r| (r.scope.clone(), r.claim)) == w.owner;
        if !same {
            return;
        }
        if let Some((owner, _)) = &w.owner
            && svc.lock_bk().busy_since(owner, self.start)
        {
            svc.raise(
                &self.ws,
                &w.tag,
                TagEventKind::NotRestored,
                format!(
                    "it is workspace {owner}'s, which was building too, so the change may be its own"
                ),
            );
            return;
        }
        match svc.image_info(&w.tag) {
            Ok((_, _, id)) if id.as_deref() == Some(w.image.as_str()) => return,
            Ok(_) => {}
            Err(r) => {
                svc.raise(&self.ws, &w.tag, TagEventKind::NotRestored, r.msg);
                return;
            }
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
            Ok((201, _)) => {
                svc.lock_bk().touch(std::slice::from_ref(&w.tag));
                svc.raise(
                    &self.ws,
                    &w.tag,
                    TagEventKind::Restored,
                    format!(
                        "it is {owner}, and a build moved it; put back on {}",
                        w.image
                    ),
                );
            }
            Ok((status, _)) => svc.raise(
                &self.ws,
                &w.tag,
                TagEventKind::NotRestored,
                format!("it is {owner}; the engine refused to put it back ({status})"),
            ),
            Err(e) => svc.raise(
                &self.ws,
                &w.tag,
                TagEventKind::NotRestored,
                format!("it is {owner}; putting it back failed: {e}"),
            ),
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        if !self.left {
            self.leave();
        }
    }
}
