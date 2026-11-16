//! Report an image tag a `BuildKit` stream moved (DA1-02, DA1-04). Report only:
//! nothing here ever changes the engine.
//!
//! `/grpc` and `/session` are relayed unread, so the tag a `docker buildx build
//! -t` names is not seen, and without reading that traffic a tag that moved cannot
//! be tied to the stream: it may be the tag's owner's own build or request. So when
//! a stream of workspace S begins, the agent notes the image of every tag S may
//! not move (tags recorded to other workspaces, and unrecorded names on pulled
//! images); when it ends, it reads them again and reports each that changed or
//! went, with the command that puts it back. The report says "ambiguous" when the
//! owner had a REST request on the name, or a stream of its own, meanwhile.
//! The only engine request is `GET /images/json`; a list that fails is reported
//! ("unable to check") and never blocks the stream.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
#[cfg(test)]
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use super::{Scope, Services};
use crate::ledger::now;

/// Protected tags noted per stream.
const MAX_WATCHED: usize = 256;
/// Events kept for `Services::tag_events`.
const MAX_EVENTS: usize = 64;

/// What the agent saw: a tag that is not what it was when a stream began, or a
/// stream it could not check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagEvent {
    pub at: u64,
    /// The workspace whose stream ran.
    pub workspace: String,
    pub kind: TagEventKind,
    pub detail: String,
    /// `Changed` only: the tag, its owner (`None`: a pulled name), the image it had
    /// and has now (`None`: it went), and whether the owner's own request or
    /// build could explain it.
    pub tag: String,
    pub owner: Option<String>,
    pub previous: String,
    pub current: Option<String>,
    pub ambiguous: bool,
    /// Other streams ran with this one: the workspace may not be the one that moved the tag.
    pub overlapped: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagEventKind {
    Changed,
    /// The stream could not be checked, wholly or in part.
    Unchecked,
}

impl TagEventKind {
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Changed => "changed",
            Self::Unchecked => "unchecked",
        }
    }
}

impl std::fmt::Display for TagEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BuildKit stream (workspace {}'s, or one that ran with it): {}",
            self.workspace, self.detail
        )
    }
}

/// A running stream's window: the tags it noted, those a REST request held, and
/// the workspaces that had a stream running with it. It exists from before the
/// stream's first image list, so nothing that happens during the list is missed:
/// until the tags are known (`known`), any REST request counts for every tag (`any`).
struct Window {
    ws: String,
    known: bool,
    any: bool,
    tags: HashSet<String>,
    /// The workspaces owning the noted tags: the only overlaps that matter.
    owners: HashSet<String>,
    touched: HashSet<String>,
    others: HashSet<String>,
    /// Another stream was running at some time with this one.
    overlap: bool,
}

/// Shared state, under its own lock (taken after `tag_res`, never across a call out).
#[derive(Default)]
pub(super) struct Bk {
    next: u64,
    seq: u64,
    running: HashMap<u64, Window>,
    events: VecDeque<(u64, TagEvent)>,
}

impl Bk {
    /// A REST request holds these names.
    pub(super) fn touch(&mut self, tags: &[String]) {
        for w in self.running.values_mut() {
            if w.known {
                w.touched
                    .extend(tags.iter().filter(|t| w.tags.contains(*t)).cloned());
            } else {
                w.any = true;
            }
        }
    }

    /// Keep `ev` unless the same change was reported since `since` (several
    /// streams that ran together see one change) or the same "unable to check" is
    /// already there. At the cap the first report of a tag is kept: it holds the
    /// owner's original image.
    fn push(&mut self, ev: TagEvent, since: u64) -> bool {
        let same = |e: &TagEvent| match ev.kind {
            TagEventKind::Changed => {
                (&e.tag, &e.previous, &e.current) == (&ev.tag, &ev.previous, &ev.current)
            }
            TagEventKind::Unchecked => (&e.workspace, &e.detail) == (&ev.workspace, &ev.detail),
        };
        let seen = self.events.iter().any(|(at, e)| {
            e.kind == ev.kind && same(e) && (ev.kind == TagEventKind::Unchecked || *at >= since)
        });
        if seen {
            return false;
        }
        self.seq += 1;
        self.events.push_back((self.seq, ev));
        while self.events.len() > MAX_EVENTS {
            let first_of_tag =
                |i: usize| {
                    !self.events.iter().take(i).any(|(_, p)| {
                        p.kind == TagEventKind::Changed && p.tag == self.events[i].1.tag
                    })
                };
            // A later report of a tag that has several goes first (the first holds
            // the owner's original image), then "unable to check" (never the one
            // just added: it must show up), then the oldest report.
            let last = self.events.len() - 1;
            let drop = (0..=last)
                .find(|&i| self.events[i].1.kind == TagEventKind::Changed && !first_of_tag(i))
                .or_else(|| (0..last).find(|&i| self.events[i].1.kind == TagEventKind::Unchecked))
                .unwrap_or(0);
            self.events.remove(drop);
        }
        true
    }
}

/// A tag the stream's workspace may not move, as it was at the start.
struct Noted {
    tag: String,
    image: String,
    owner: Option<String>,
}

/// One running stream: ends with [`Watch::finish`], or silently when dropped.
pub(super) struct Watch {
    svc: Arc<Services>,
    id: u64,
    ws: String,
    tags: Vec<Noted>,
    began: u64,
}

/// The engine's tagged images (tag, image ID, pulled) and whether a name was left out.
type Listed = (Vec<(String, String, bool)>, bool);

impl Services {
    pub(super) fn lock_bk(&self) -> std::sync::MutexGuard<'_, Bk> {
        self.bk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The latest events, oldest first (at most 64).
    #[must_use]
    pub fn tag_events(&self) -> Vec<TagEvent> {
        self.lock_bk()
            .events
            .iter()
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// Workspaces remembered as overlapping, summed over the running streams (tests).
    #[cfg(test)]
    pub(super) fn bk_others(&self) -> usize {
        self.lock_bk()
            .running
            .values()
            .map(|w| w.others.len())
            .sum()
    }

    /// Streams running (tests).
    #[cfg(test)]
    pub(super) fn bk_running(&self) -> usize {
        self.lock_bk().running.len()
    }

    fn unchecked(&self, workspace: &str, detail: &str) {
        self.raise(
            TagEvent {
                at: now(),
                workspace: workspace.to_owned(),
                kind: TagEventKind::Unchecked,
                detail: format!("unable to check image tags: {detail}"),
                tag: String::new(),
                owner: None,
                previous: String::new(),
                current: None,
                ambiguous: false,
                overlapped: false,
            },
            0,
        );
    }

    fn raise(&self, ev: TagEvent, since: u64) {
        let ev = if self.lock_bk().push(ev.clone(), since) {
            Some(ev)
        } else {
            None
        };
        if let Some(ev) = ev {
            eprintln!("marsh-services: {ev}");
        }
    }

    /// Every tagged image the engine has: canonical tag, image ID, pulled.
    fn tagged_images(&self) -> Result<Listed, String> {
        let (status, body) = self
            .up_request("GET", "/images/json", None)
            .map_err(|e| format!("the engine's image list failed: {e}"))?;
        if status != 200 {
            return Err(format!("the engine's image list answered {status}"));
        }
        let list: Vec<serde_json::Value> = serde_json::from_slice(&body)
            .map_err(|_| "the engine's image list is not readable".to_owned())?;
        let (mut out, mut skipped) = (Vec::new(), false);
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
                match crate::policy::admit::canonical_tag(tag, None) {
                    Ok(tag) => out.push((tag, id.to_owned(), pulled)),
                    // An untagged image is listed as `<none>:<none>`.
                    Err(_) => skipped |= !tag.starts_with("<none>"),
                }
            }
        }
        Ok((out, skipped))
    }
}

impl Scope {
    /// A `BuildKit` stream of this workspace is about to run: note the tags it
    /// may not move.
    pub(super) fn bk_begin(&self) -> Watch {
        let (svc, ws) = (&self.svc, self.auth.workspace.clone());
        // The window first, so nothing during the list is missed; a name a REST
        // request holds now is one it touches.
        let (id, began) = {
            // The tag table stays locked until the window exists: a request that
            // reserves a name either is in `held` or finds the window.
            let res = svc.lock_tags();
            let held: HashSet<String> = res.keys().cloned().collect();
            #[cfg(test)]
            pause_after_held(&ws);
            let mut bk = svc.lock_bk();
            let id = bk.next;
            bk.next += 1;
            let others = bk.running.values().map(|w| w.ws.clone()).collect();
            let overlap = !bk.running.is_empty();
            for w in bk.running.values_mut() {
                w.overlap = true;
                if !w.known {
                    // Who it is does not matter, only that a stream began meanwhile.
                    w.any = true;
                } else if w.owners.contains(&ws) {
                    w.others.insert(ws.clone());
                }
            }
            let began = bk.seq + 1;
            bk.running.insert(
                id,
                Window {
                    ws: ws.clone(),
                    known: false,
                    any: false,
                    tags: HashSet::new(),
                    owners: HashSet::new(),
                    touched: held,
                    others,
                    overlap,
                },
            );
            (id, began)
        };
        let mut tags = Vec::new();
        let listed = svc.tagged_images();
        if let Ok((images, _)) = &listed {
            for (tag, image, pulled) in images {
                let owner = match svc.ledger.tag_owner(tag) {
                    Some(rec) if rec.scope == ws => continue,
                    Some(rec) => Some(rec.scope),
                    None if *pulled => None,
                    None => continue,
                };
                tags.push(Noted {
                    tag: tag.clone(),
                    image: image.clone(),
                    owner,
                });
            }
        }
        // Recorded tags first: they are the ones a lane's own work can collide with.
        tags.sort_by(|a, b| (a.owner.is_none(), &a.tag).cmp(&(b.owner.is_none(), &b.tag)));
        let cut = tags.len().saturating_sub(MAX_WATCHED);
        tags.truncate(MAX_WATCHED);
        if let Some(w) = svc.lock_bk().running.get_mut(&id) {
            w.owners = tags.iter().filter_map(|n| n.owner.clone()).collect();
            w.tags = tags.iter().map(|n| n.tag.clone()).collect();
            w.others.retain(|o| w.owners.contains(o));
            w.known = true;
        }
        match listed {
            Err(why) => svc.unchecked(&ws, &why),
            Ok((_, skipped)) => {
                if cut > 0 {
                    svc.unchecked(
                        &ws,
                        &format!("{cut} protected tags are not watched (only {MAX_WATCHED} are)"),
                    );
                }
                if skipped {
                    svc.unchecked(&ws, "some image names cannot be watched (too long, or not a name the filter accepts)");
                }
            }
        }
        Watch {
            svc: Arc::clone(svc),
            id,
            ws,
            tags,
            began,
        }
    }
}

impl Watch {
    /// The stream ended: report what it may have moved.
    pub(super) fn finish(self) {
        if self.tags.is_empty() {
            return;
        }
        let now_images = match self.svc.tagged_images() {
            Ok((images, _)) => images
                .into_iter()
                .map(|(t, i, _)| (t, i))
                .collect::<HashMap<_, _>>(),
            Err(why) => return self.svc.unchecked(&self.ws, &why),
        };
        let window = self.svc.lock_bk();
        let w = window.running.get(&self.id);
        let found: Vec<TagEvent> = self
            .tags
            .iter()
            .filter(|n| now_images.get(&n.tag) != Some(&n.image))
            .map(|n| {
                let ambiguous = w.is_none_or(|w| {
                    w.any
                        || w.touched.contains(&n.tag)
                        || n.owner.as_ref().is_some_and(|o| w.others.contains(o))
                });
                self.event(
                    n,
                    now_images.get(&n.tag).cloned(),
                    ambiguous,
                    w.is_none_or(|w| w.overlap),
                )
            })
            .collect();
        drop(window);
        for ev in found {
            self.svc.raise(ev, self.began);
        }
    }

    fn event(
        &self,
        n: &Noted,
        current: Option<String>,
        ambiguous: bool,
        overlapped: bool,
    ) -> TagEvent {
        let whose = n.owner.as_ref().map_or("a pulled image's".to_owned(), |o| {
            format!("workspace {o}'s")
        });
        let state = current
            .as_deref()
            .map_or("no longer has the name".to_owned(), |c| {
                format!("now points at {c}")
            });
        let may = if ambiguous {
            " This may be the owner's own change."
        } else {
            ""
        };
        let several = if overlapped {
            " Several builds ran at once: the workspace named may not be the one that moved it."
        } else {
            ""
        };
        let fix = match &n.owner {
            Some(o) => format!(
                "if image {0} still exists, `docker tag {0} {1}` run in workspace {o} puts it back (else rebuild it)",
                n.image, n.tag
            ),
            None => format!(
                "`docker pull {}` fetches the registry's current image, not necessarily {}",
                n.tag, n.image
            ),
        };
        TagEvent {
            at: now(),
            workspace: self.ws.clone(),
            kind: TagEventKind::Changed,
            detail: format!(
                "image tag {} ({whose}) {state}; it was {}.{may}{several} It is not undone: {fix}.",
                n.tag, n.image
            ),
            tag: n.tag.clone(),
            owner: n.owner.clone(),
            previous: n.image.clone(),
            current,
            ambiguous,
            overlapped,
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.svc.lock_bk().running.remove(&self.id);
    }
}

/// Test hook: a stream of this workspace waits here, after it collected the
/// names a request holds and before its window exists.
#[cfg(test)]
pub(super) static PAUSE: Mutex<Option<Pause>> = Mutex::new(None);

/// Workspace, reached flag, resume flag.
#[cfg(test)]
pub(super) type Pause = (String, Arc<AtomicBool>, Arc<AtomicBool>);

#[cfg(test)]
fn pause_after_held(ws: &str) {
    let hook = PAUSE.lock().unwrap().clone();
    if let Some((who, reached, release)) = hook
        && who == ws
    {
        reached.store(true, Ordering::SeqCst);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !release.load(Ordering::SeqCst) && std::time::Instant::now() < until {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}
