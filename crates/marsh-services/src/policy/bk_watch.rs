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
            "BuildKit stream of workspace {}: {}",
            self.workspace, self.detail
        )
    }
}

/// A running stream's window: the tags it noted, those a REST request held, and
/// the workspaces that had a stream running with it.
struct Window {
    ws: String,
    tags: HashSet<String>,
    touched: HashSet<String>,
    others: HashSet<String>,
}

/// Shared state, under its own lock (taken after `tag_res`, never across a call out).
#[derive(Default)]
pub(super) struct Bk {
    next: u64,
    running: HashMap<u64, Window>,
    events: VecDeque<TagEvent>,
}

impl Bk {
    /// A REST request holds these names.
    pub(super) fn touch(&mut self, tags: &[String]) {
        for w in self.running.values_mut() {
            w.touched
                .extend(tags.iter().filter(|t| w.tags.contains(*t)).cloned());
        }
    }

    fn push(&mut self, ev: TagEvent) -> bool {
        let same = |e: &TagEvent| {
            (&e.tag, &e.previous, &e.current, e.kind)
                == (&ev.tag, &ev.previous, &ev.current, ev.kind)
                && e.kind == TagEventKind::Changed
        };
        if self.events.iter().any(same) {
            return false;
        }
        self.events.push_back(ev);
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
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

    /// Streams running (tests).
    #[cfg(test)]
    pub(super) fn bk_running(&self) -> usize {
        self.lock_bk().running.len()
    }

    fn unchecked(&self, workspace: &str, detail: &str) {
        self.raise(TagEvent {
            at: now(),
            workspace: workspace.to_owned(),
            kind: TagEventKind::Unchecked,
            detail: format!("unable to check image tags: {detail}"),
            tag: String::new(),
            owner: None,
            previous: String::new(),
            current: None,
            ambiguous: false,
        });
    }

    fn raise(&self, ev: TagEvent) {
        let ev = if self.lock_bk().push(ev.clone()) {
            Some(ev)
        } else {
            None
        };
        if let Some(ev) = ev {
            eprintln!("marsh-services: {ev}");
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
    /// A `BuildKit` stream of this workspace is about to run: note the tags it
    /// may not move.
    pub(super) fn bk_begin(&self) -> Watch {
        let (svc, ws) = (&self.svc, self.auth.workspace.clone());
        let mut tags = Vec::new();
        let listed = svc.tagged_images();
        if let Ok(images) = &listed {
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
        let id = {
            let mut bk = svc.lock_bk();
            let id = bk.next;
            bk.next += 1;
            // Every stream running now and this one have each other in their window.
            let mine: HashSet<String> = bk.running.values().map(|w| w.ws.clone()).collect();
            for w in bk.running.values_mut() {
                w.others.insert(ws.clone());
            }
            bk.running.insert(
                id,
                Window {
                    ws: ws.clone(),
                    tags: tags.iter().map(|n| n.tag.clone()).collect(),
                    touched: HashSet::new(),
                    others: mine,
                },
            );
            id
        };
        match listed {
            Err(why) => svc.unchecked(&ws, &why),
            Ok(_) if cut > 0 => svc.unchecked(
                &ws,
                &format!("{cut} protected tags are not watched (only {MAX_WATCHED} are)"),
            ),
            Ok(_) => {}
        }
        Watch {
            svc: Arc::clone(svc),
            id,
            ws,
            tags,
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
            Ok(images) => images
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
                let ambiguous = w.is_some_and(|w| {
                    w.touched.contains(&n.tag)
                        || n.owner.as_ref().is_some_and(|o| w.others.contains(o))
                });
                self.event(n, now_images.get(&n.tag).cloned(), ambiguous)
            })
            .collect();
        drop(window);
        for ev in found {
            self.svc.raise(ev);
        }
    }

    fn event(&self, n: &Noted, current: Option<String>, ambiguous: bool) -> TagEvent {
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
        let fix = match &n.owner {
            Some(o) => format!(
                "to put it back, run in workspace {o}: docker tag {} {}",
                n.image, n.tag
            ),
            None => format!("to get it back, run: docker pull {}", n.tag),
        };
        TagEvent {
            at: now(),
            workspace: self.ws.clone(),
            kind: TagEventKind::Changed,
            detail: format!(
                "image tag {} ({whose}) {state}; it was {}.{may} It is not undone: {fix} (`marsh docker status` lists these reports).",
                n.tag, n.image
            ),
            tag: n.tag.clone(),
            owner: n.owner.clone(),
            previous: n.image.clone(),
            current,
            ambiguous,
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.svc.lock_bk().running.remove(&self.id);
    }
}
