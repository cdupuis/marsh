# Services Docker policy

The services agent (`crates/marsh-services`, modules `policy`, `pins` and
`ledger`) runs inside the project's engine container and is the only way a job
reaches the production Docker engine. It is the security boundary of the
services feature: root in the services VM is out of scope, everything a job
can do through the Docker API is not.

The design is `SECURITY-DESIGN.md` B1, B2, A3, A3.1, A4, A5 and A7 in the
Narwhal Fork spike. This page records how the code meets it.

## Request path

1. **Strict parse** (`policy::http`). HTTP/1.0 and 1.1, CRLF only, token header
   names, no obs-fold, exactly one framing, origin-form target, 32 KiB and 100
   fields for a head, strict chunked decoding without extensions or trailers.
   `Expect:` gets 417. Ambiguity is a 400 and a close.
2. **Route allowlist** (`policy::routes`). Percent-escapes, `//`, dot segments
   and non-ASCII in the path are refused, not decoded. One spelling of the API
   version (`/v1.NN`, NN at least 44) or none. Unknown routes are a 403.
3. **Body schema** (`policy::json`, `policy::schema`, `policy::docker`). Bodies
   are parsed strictly (duplicate keys, trailing data, BOM and invalid UTF-8
   are errors), matched against a closed schema (keys are mapped to Docker's
   spelling, unknown keys refused) and re-serialized.
4. **Admission** (`policy::admit`, `policy::create`). Per-route query
   allowlists, scope checks through the ledger, bind pinning, socket
   substitution, reserved labels, resource defaults and limits, loopback
   publishes.
5. **Rebuild and relay** (`policy::endpoint`). The upstream request is built
   from the admitted pieces (method, canonical path, header allowlist, the
   validated body) and sent on a fresh connection to the engine. The client's
   bytes are never forwarded. A connection goes raw only after the engine
   answered `101`, or `200` with a Docker stream content type, on `attach`,
   `exec/start`, `/session` or `/grpc`.
6. **Streams have deadlines.** A raw stream is copied by one poll loop: a byte
   either way resets the idle deadline (`Config::hijack_idle`, 30 minutes), a
   peer that has fully gone (`POLLHUP`; a half-close does not raise it) ends the
   stream at once, writes time out after `HttpLimits::progress` so a client that
   stops reading is cut, and after the client half-closes the engine's output
   is still delivered (`docker exec -i < file`). The slot is freed when the
   stream ends.
7. **Connection caps** (A7). Per attempt (64), per project (256, every workspace
   root of one `Services` counts) and per process (1024, `PROCESS_CONNS`).
8. **Ledger failures are request failures.** Every ledger change is made on a
   copy, written, and only then adopted; an error is a `503`, the engine object
   that was just made is deleted, and no mutating request is admitted until a
   write succeeds again (reads still work). A pin that was mounted but could not
   be recorded is unmounted.
9. **Capture freeze** (CAP-11, S3's hook `Services::freeze_scope`). A freeze waits
   for the state-changing requests already admitted for that workspace (from
   before their body is read until the ledger is updated) and then refuses new
   ones until its guard drops. Waits, attaches, resizes and exec start (long
   lived, or not container state) are not counted; image, build and exec
   routes are refused while frozen but not waited for.

## Pins (A3)

A bind source is resolved beneath a held project-root descriptor with
`openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)`, cloned
with `open_tree(OPEN_TREE_CLONE)`, attached with `move_mount` under
`/var/lib/marsh/binds/<scope>/<id>` and made private. The request is rewritten
to that path. A missing `-v` source is created inside the project, as Docker
would.

**Protected paths.** `.git` and `.marsh` are protected by identity, not by
name: the project folder may be case-insensitive (APFS through virtiofs), so
`.GIT` is `.git`, and a renamed `.git` is still `.git`. The `(st_dev, st_ino)`
of each protected name is recorded in the ledger, per project root, the first
time the agent sees it (when it first opens the root, and at every pin; known
identities are never recorded twice, the earliest 64 are kept). A pin is
protected if its target, or any ancestor, is one of the identities recorded or
visible now. For a directory the ancestors are found by walking up from the
open handle (`..`), so renaming a parent after the open changes nothing; for a
file they are resolved by name. A pin of any of them (or inside) is read-only; a
pin of the project root carries the protected names, and every entry of the root
that is a recorded identity (a `.git` renamed to `.gx`), as read-only sub-mounts.
A root pin makes `.marsh` first (`mkdirat`) so that the `.marsh/checkpoints` and
`.marsh/split/*` created later are covered. A missing `.git` is not created (an
empty one would break `git init`); a repository initialised after a root pin is
made is a residual until the next pin. A bind with `NonRecursive`
(`bind-recursive=disabled`) would drop the sub-mounts and is refused, as is
`private` propagation (only `rprivate`).

Residuals of the identity record (a job with write access to the project can
already write `.git` while it runs; these only affect what survives the job):
- *First sight.* An identity is trusted from the moment the agent first sees
  it. If `.git` is renamed before the agent has ever looked at the project root
  (before the first Docker request of the project), the renamed tree is never
  recorded.
- *Moved deeper.* A recorded tree moved into a subdirectory is protected when
  the pin targets it or lies inside it, but a pin of the subdirectory (or any
  directory above it other than the root) does not carry it as a read-only
  sub-mount: only the root's own entries are scanned. Doing it for every depth
  would walk the whole tree on each pin.
- *Files.* A pin of a file resolves its ancestors by name, after the open, so
  a rename in that window can still hide a protected ancestor from the check.
- *Inode reuse.* A recorded identity whose inode the filesystem later gives to an
  unrelated directory makes that directory read-only when pinned. The shared
  folder's inodes are APFS's, which are not reused in practice.

**Leases.** The ledger records, per container, the pins it made and the pins of
every container it takes volumes from (`VolumesFrom`). A pin is released with
the last holder; the freed record (directory or file) goes with it so the
mountpoint is removed whatever it is. A periodic reconcile does the same for
auto-removed containers and sweeps pin paths no record names. A pin is mounted
and recorded under the read side of one lock and the sweep reads the ledger
under the write side, so it cannot meet a pin that is mounted and not yet
recorded; a pin's age is not consulted (the source folder's modification time
said nothing about the pin).

**Restore** (`engine.rs` `restore_pins` calls `pins::restore_all()` before the
production engine starts; an `Err` fails the boot). Each pin is re-resolved
beneath the reopened project root without following symlinks. A pin that
cannot be recreated is left as a dangling symlink (`/marsh-pin-not-restored`)
and recorded as failed; Docker cannot make an empty directory there, so a
`start` fails, and the filter refuses `start` and `restart` of any container
whose lease holds a failed pin. Removing the container clears it. The
substituted-socket paths are reserved as bound-and-dropped socket files, so
dockerd never creates a directory there. **TODO(E1):** the relay agent must call
`Services::restore_sockets()` once it listens (marked in `engine::bring_up`).

## Socket substitution (A3.1)

A bind of `/var/run/docker.sock` or `/run/docker.sock` becomes a socket the
agent serves under `/run/marsh/sockets/<workspace>/<attempt>/docker.sock` (root
only directory) with the creating attempt's authority. The set of such sockets
is in the ledger and is served again after an engine restart. The job
endpoint path E2 gives every job (`/run/marsh/docker.sock`, DECISIONS 20) is in
`Config::socket_aliases` by default and substitutes like the two standard
spellings.

## Ledger (A4)

Every change takes an exclusive `flock` on `ledger.lock`, reloads the file if
another agent process published since, writes a private temporary file, fsyncs
it, renames it over `ledger.json` and fsyncs the directory. A file that does not
parse is kept as `ledger.json.corrupt-*` (never deleted), the agent boots on the
first complete state in it (or an empty one), and writes `ledger.quarantine`: the
recorded protected identities (`.git`, `.marsh`) cannot be trusted, so binding a
project folder is refused (and restore marks pins failed) until an operator
checks them and removes that file. The serving agent also holds `ledger.serve`
for its lifetime, so a replacement that starts early waits, then fails, rather
than answering from a stale view. A volume create or delete holds the name from its
admission (the claim, or the ownership check) through the engine call to the
ledger record, under the lock every volume claim takes (`vol_lock`): an operation
admitted earlier cannot publish its ownership after a later operation or fence,
and an old delete cannot land after the name was given to another workspace
(`a_delayed_delete_cannot_remove_a_volume_another_workspace_now_owns`,
`a_volume_create_holds_the_name_from_admission_to_the_end_of_its_engine_call`).
The lock is released as soon as the engine's answer is in memory and recorded
(or the call failed and the fence is set), and an admission refusal releases it
before it is written; no reply to the client (an answer, a refusal or an error)
is written, and no rest of a refused request is drained, while the lock is held,
so a client that reads slowly or not at all does not hold up other workspaces'
volume requests
(`a_client_that_does_not_read_its_reply_does_not_block_other_workspaces`,
`a_client_that_does_not_read_a_delete_reply_does_not_block_other_workspaces`,
`a_client_that_never_reads_its_refusals_does_not_block_other_workspaces`,
`a_slow_engine_body_does_not_block_other_workspaces_past_the_deadline`). The
engine calls made inside admission (an inspect, an implicit create) still hold
the lock, bounded by `up_progress`.
Both are made by the agent itself (`exchange`, one absolute `up_progress`
deadline), not through the client's connection: a client that leaves does not
cancel the engine call, ownership is recorded by its result, and a create the
engine does not answer keeps the sender's reservation and fences the name like an
unanswered delete
(`a_volume_create_whose_client_disconnected_still_records_its_owner`,
`a_hung_volume_create_is_bounded_and_fences_the_name`,
`a_connection_takes_the_volume_lock_again_after_a_volume_create`). The volume
create that a container create makes for a named volume (`Binds`, or a `Mounts`
entry of type volume; `ensure_volume`, inside admission under the same lock) is
sent through the same function (`engine_volume_create`), so the two cannot differ
on an unknown outcome: a create sent and not answered keeps the reservation and
fences the name, and only a failed dial gives the reservation back
(`an_unanswered_implicit_volume_create_keeps_the_reservation_and_fences_the_name`,
`a_volume_create_that_was_never_sent_gives_the_reservation_back`,
`an_implicit_volume_create_that_could_not_be_dialed_gives_the_reservation_back`).
The container create itself is streamed and not under the lock, and network
creates are not agent-owned. This was chosen over fencing at the start of every delete and re-checking the
fence after a create's engine call, because that would have to undo a volume the
create may or may not have made; holding the lock needs no undo and fails closed
(the cost is the queue below). The agent
makes the engine call itself, so the client leaving does not end it early
(`a_delete_whose_client_disconnected_still_holds_the_name_until_the_engine_finishes`).
The ledger releases the name only when the engine answers 200, 204 or 404. If a
delete was sent and the engine does not answer (timeout, a reply cut off by the
whole-call deadline `up_progress`, an error after the send), the owner keeps the
name and the name is fenced against OTHER workspaces for `delete_fence`
(5 minutes): their volume creates and container creates with that named volume
(`ensure_volume`) get a 503 (`another_workspace_waits_out_the_fence_of_a_delete_that_was_not_answered`,
`a_container_create_by_another_workspace_honors_the_fence`,
`a_disconnected_delete_that_timed_out_fences_the_name_too`). The workspace that
sent the delete is not refused by its own fence, because a late landing of its
own delete can only remove its own volume
(`the_workspace_that_sent_the_delete_is_not_refused_by_its_own_fence`). The fence
only expires by time. Nothing else ends it: a later delete of the name that
succeeds, an inspect that finds the volume absent and the reconciler dropping the
ledger entry do not show that the earlier request has finished (a request can be
accepted, then wait at the engine while a later one runs first). A delete that was
never sent (the engine could not be dialed) fences nothing
(`a_delete_that_was_never_sent_fences_nothing`). The fence is in memory only: an
agent restart forgets it. It is time-based, so a delete that lands after the fence
expired is not stopped; the engine gives no way to cancel or confirm a request it
has accepted. An in-flight registry holds one entry per volume create attempt, from before the
first byte is sent. An attempt removes only its own entry, when the engine answers
it or the dial failed, so a later answered retry cannot complete an earlier
unanswered attempt
(`an_answered_retry_does_not_complete_an_earlier_unanswered_create`). An attempt
whose outcome is unknown keeps its entry until the time of its timeout plus the
fence time, the same instant the fence ends (one clock, derived once:
`the_registry_outlasts_the_fence_of_an_unknown_create`,
`an_unknown_creates_registry_entry_and_fence_end_together`). A name is in flight
while any entry for it exists. While a name is registered: a reconcile (a prune or the periodic pass) takes the volume
lock before it reads the engine's lists (so it cannot overtake a create, and its
snapshot is never older than one it waited for; the three reads, each bounded by
`up_progress`, run under the lock, so a hung engine delays volume requests by up
to about three deadlines) and keeps the ledger record whatever
its age (`reconcile_keeps_the_owner_of_a_create_that_may_still_land`,
`a_reconcile_during_a_create_that_then_times_out_keeps_the_owner`), and a delete of
the name, by any workspace and the sender too, is refused with a 503 instead of
being answered 404 and releasing the name before the late create lands
(`a_delete_of_a_name_with_a_create_of_unknown_outcome_is_refused`). After the fence
time the usual rules apply again. An engine error on a delete (409, 5xx) is an answer: the owner keeps
the volume and the reply is passed on. The reply to a delete is the engine's
(status line, headers, body; keep-alive when the client asked for it). Every
engine call the agent makes itself ends at one absolute deadline, `up_progress` (30 s)
after it started: the request write (nonblocking, waiting with `poll` for at most
the time left: a blocking write renews its own timeout while the reader makes
progress), the response head, every
read of the body including chunk-size lines, trailers and the terminal chunk
(`a_drip_fed_response_head_obeys_the_whole_call_deadline`,
`a_drip_fed_chunked_reply_obeys_the_whole_call_deadline`,
`a_drip_fed_terminal_chunk_obeys_the_whole_call_deadline`,
`a_slowly_read_request_obeys_the_whole_call_deadline`,
`a_trickling_engine_reply_is_bounded_by_the_whole_call`). This covers
DELETE of a volume against volume claims. Container and network deletes (they
address the engine by the ID the ledger resolved), volume prune and other
label-filtered engine calls are not serialized this way and are not covered.
Volume creates, deletes and named-volume container creates queue behind one lock
for every workspace (not per name), so a hung engine call delays them all until
its answer or the 30 s deadline, and the lock is not fair; a per-name lock would
narrow this and is not done. The engine DELETE that undoes a volume after a
ledger write failed (`undo`) is neither locked nor fenced; it needs a degraded
ledger, which refuses every claim. A ledger that goes corrupt while the agent
runs is not set aside: the ledger degrades and refuses writes until restart.
Enforced by the ledger tests `a_change_is_published_in_the_durable_order`,
`a_corrupt_ledger_quarantines_until_an_operator_clears_it`,
`only_one_agent_serves_a_ledger_at_a_time`, the endpoint tests
`a_second_serving_agent_on_one_ledger_is_refused` and
`a_corrupt_ledger_refuses_project_binds_but_not_other_creates`, the pin test
`restore_recreates_no_pin_while_the_ledger_is_quarantined`,
`a_failed_sync_is_not_acknowledged` (sync errors are honored; no test shows the
real `fsync` is issued), and
`two_ledgers_on_one_file_keep_each_others_records`,
`racing_writers_never_tear_or_lose_the_ledger` and
`an_unparseable_ledger_is_set_aside_not_deleted`.

`ledger.json` on the pool records the owner scope of containers, networks and
volumes, plus pins and substituted sockets. Exec IDs are remembered in memory
only, at most 256 per container (`execs_are_bounded_and_not_persisted`), so a
job's `docker exec` loop cannot grow the file. Every object route
resolves names, short IDs and full IDs inside the caller's scope only and
rewrites to the full ID; other scopes' objects answer exactly like missing
ones. Lists and prunes carry a scope label filter, list responses are filtered
again against the ledger (an engine answer that cannot be parsed is a 502, not
passed on), and events are filtered line by line. Each scope has a default
bridge network, `marsh-scope-<workspace>`, and the engine is always given the
network's full ID (never a name, which Docker resolves after an exact ID).
Container, network and volume names that look like a full ID (64 hex digits) are
refused for the same reason.

Volume ownership is one atomic step: `Ledger::claim_volume` reserves a name for
a scope (`New`, `Own` or `Foreign`), never replaces another scope's claim, and
runs under one lock with the engine's own lookup and create; an engine volume
nobody owns is not adopted. Anonymous volumes (`-v /path`, `Config.Volumes`,
image `VOLUME`s) are rewritten to labelled `volume` mounts, so they appear in the
creator's lists and prunes and only there.

`docker update` is validated on the limits the container would have after the
update (a patch is merged with what the container has now), and `PidsLimit`
0 or -1 and `MemorySwap` -1 are refused; a container that is unlimited now gets
the defaults when it is updated. The restart policy is not changed by an update.
Network create takes no options. `docker commit` may only name a repository under
`<workspace>/` (with or without `docker.io/`). Build `outputs` is a closed
schema (the `moby` exporter; local attributes only; no `push`), rebuilt before
it is forwarded.

**Image tags have an owner on the REST routes; a BuildKit stream that moves one is detected and reported, never undone (DA1-02 is partly fixed).**
Every name a REST request would give an image is reserved first, in one spelling
(`repo:tag`, the default registry and `library/` dropped; a `tag` parameter replaces
a `:tag` in `repo`): `POST /images/<id>/tag`, each build `t`, each name of a
build's `outputs` (a comma-separated list, also checked for the reserved
`marsh`/`nf-` names), and a commit's repository. A pull is refused over a tag
another scope owns and held for its duration (a pull with no tag, which would pull
every tag of the repository, is refused, with or without a trailing colon; a digest
pull, whether `fromImage=name@sha256:..` or the Go SDK's `fromImage=name&tag=sha256:..`,
moves no tag and is not held). A delete is refused when it would remove a tag another
scope owns or is making, or a pulled image's tag, and the names it removes are held
(recording nothing) until the engine has finished, an absent requested name included.
A pull of a name another scope's delete holds is refused, and so is a claim; pulls share
a name with other pulls, and deletes with other deletes. A delete that is not of one of
the image's own tags (an ID, short or full, or a digest) also holds the image by its ID,
and `docker tag` holds its source image the same way (traced from the engine's source, not run against Docker), so a tag put on an image
while an ID delete of it runs, and an ID delete while such a tag is made, refuse each
other; the ID is the one the engine's inspect reports, taken under the lock.
**An ID, short ID or digest delete is never forced** (`DeleteGrant::by_name`; the `force`
parameter is dropped before the request goes upstream). "By name" is decided the way the
engine decides: the engine first checks whether the reference is a prefix of the image's
ID, and then it is an ID delete even if it is also a tag name (a tag named like an ID
prefix, which any workspace can make with `docker tag`), so such a reference is treated as
an ID delete here too, as is a name absent at the inspect (the engine may have an image
under it by the time it runs). A tag can reach the image during the engine call by paths
that name no source image (a cached build, a commit, a pull), which the hold cannot see.
Because the delete is not forced, the engine's own check refuses (409, "referenced in
multiple repositories") to remove an image that has gained a second tag, and removes one
only when its single tag, or none, is what was checked, so no alias is taken away from
its owner and no name freed for takeover. This is the engine's check, not an atomic
step of marsh's: on the classic image store a few microseconds remain between the
engine's conflict check and its removal of the references; the containerd store, which a
fresh Docker 29 data root uses and so the one this engine runs, deletes only the
references it saw in a snapshot and has no such window. (Traced from Docker's source, not
run.) A delete by one of the image's own tag names keeps `force`: it untags only that name
(on both stores), and the engine removes the image only when that was its last reference.
Behaviour change: `docker rmi -f <id>` acts as `docker rmi <id>`, which includes the
common cleanup `docker rmi -f $(docker images -q)` (it prints IDs): every image with several
tags, or used by a stopped container, now fails with the engine's 409; remove such images by
tag name (`docker rmi name1 name2`). An untagged image is deleted by ID as before, unforced.
Compose is not affected: it never sends `force`, removes tagged images by name and dangling
ones by ID (from Compose's source).
A reference that is one of the image's tags untags only that name (so a scope may remove
its own alias of a pulled image); any other reference removes the image, so every tag it
has is checked.

- **Rule** (`Env::reserve_tags`, `ledger::tag_claim`). A scope may create a tag no
  image has, or move its own. It is refused a tag another scope created whose
  image is there, a pulled image's tag (the image has registry digests), and a
  name another scope's request is making or pulling right now (pulls do not block
  other pulls). A record whose image is
  gone holds nothing, so `docker rmi` frees the name at once. A locally built image
  no record covers (its scope was dropped, or it predates the ledger) is adopted.
- **Lifecycle.** The reservation lives in memory while the request runs (all names
  or none; dropping the request's hold releases it, however it ended, and a name is
  held until every request of the workspace for it has ended). The creator is
  recorded as soon as the engine answers 2xx, whether or not the client is still
  there to read the answer, so a refused or failed request leaves no record and a
  successful tag keeps its owner when the client leaves. Caveats: a build whose
  error is inside a 200 stream, or whose client left, records a name whose image
  never appears (the next claimant takes the name, as the image is gone); and if the
  ledger cannot be written at that moment (a failing disk) the tag stays unrecorded
  and a later claimant adopts the local image. Capacity is decided with the
  reservation, under one lock: records plus the new names in flight (this request's
  included) never exceed `MAX_TAGS` (8192). Records go when the engine no longer
  has the image, at the reconcile pass and when the table is full; a record of an image that is there, or of a name
  in flight, is never dropped, and a request that still would not fit is refused.
  The lock covers one engine inspect per name (a multi-name build inspects each),
  at most `up_request`'s 30 s progress timeout per call when the engine hangs; every
  tag claim, pull, delete and request end waits on it meanwhile.
- **Closing a workspace** (a lane is closed, cancelled or removed:
  `Restorer::drop_workspace`). After its containers, volumes and networks are
  removed, `Services::untag_scope` removes the tags the workspace created: for each
  of its records, `DELETE /images/<name>` without `force`, through the filtered
  endpoint as that workspace. That is the call `docker rmi <name>` makes, so it
  untags that name only (an image another tag references stays; an image whose
  last tag it was goes), it holds the name against other workspaces' claims while
  it runs, and it is refused for a tag another workspace owns or is making.
  - **When a record may be trusted.** The cleanup deletes a name only because the
    record says it is still what the workspace tagged, so every way a name stops
    being so retires the record first (no image ID is stored): the owner's own
    `docker rmi` releases it when the engine answers 2xx (`ScopeTagHold::commit`,
    delete holds); a pull of a name the engine does not have drops it
    (`reserve_pull`, so the registry's tag is nobody's but a later claim's); a claim
    of such a name replaces it; and `untag_scope` first drops the records of images
    the engine no longer has (a prune, a delete by ID), the same pass as
    `reconcile`. A pulled image's own name is therefore in the list only if the
    workspace itself pulled it over a name it had recorded and the engine still
    has. Every release names the claim it saw (`TagRec::claim`, a serial from the
    ledger): a delete begun before the workspace claimed the same name again, or
    this cleanup, cannot retire the newer record.
    **Gap:** a build over `/grpc` (not filtered, see below) can put an image under
    a name without any of these seeing it. The detection below reports a protected
    name that moved and changes nothing, so a record can still be a live one of another
    lane (lane A `docker tag x N`, lane B
    `docker build -t N`): closing A would then untag B's image. The damage is a
    rebuildable tag, never a container, volume or data. Storing the source image ID
    at claim time and deleting only a name still on it was considered and not done:
    it would cover `docker tag` only (a build or commit claim has no ID without a
    further inspect after the fact), needs a record field and an inspect per claim
    and per cleanup, and still leaves a window between that inspect and the delete.
  - **Fail closed.** A record goes (`Ledger::release_tag`, only while still the
    closing workspace's and the claim the cleanup saw) after the engine answered
    2xx or 404. Any other answer, or none, keeps it, and `forget_scope` does not
    drop tag records: the name stays the closed workspace's, refused to others
    while its image is there, and the drop reports `image tag <name>` as left. A
    claim cannot be longer than 255 characters (the route's limit, exactly:
    255 is claimed, 256 refused; `reserve_tags`), so no record is a name the
    cleanup could not send.
  - **Retries.** `marsh-daemon` journals a drop with a non-empty `left` and repeats
    it from the services timer (every 5 s), printing `marshd: dropping lane <id>
    left image tag <name>; will retry` on its stderr; an unknown outcome is
    settled by the retry (a delete that did apply answers 404). The outcome of
    each delete is one of `engine_api::Untag`: `Confirmed` (2xx, the engine's 404),
    `Refused` (the engine's own refusal: a 409, the last tag of an image another
    lane's container uses; a 500) and `Unknown` (no answer; **any reply the filter
    made itself**, whatever its status: a full connection cap (429), a hold by
    another workspace (403), the 502 it makes up for a lost engine reply, a 503
    when it could not ask; and, conservatively, a 429 or 502 to 504 from the
    engine). The filter's replies are recognised by their body, which every one of
    them has (`policy::http::refusal_body`, `{"message":"marsh: ..."}`, the only
    place the filter writes a status of its own; pinned by
    `a_refusal_body_is_what_the_cleanup_recognises`). Only `Refused` is counted in
    the record (`TagRec.untag_refused`); after `MAX_UNTAG_REFUSALS` (12, about a
    minute) the record is released and that round's `left` says `<name> (the
    engine refused to untag it N times, last answer C; it stays in the engine, and
    `marsh docker rm` removes it)`, so the next retry finds nothing and the journal
    entry ends. What is given up is a tag that stays in the engine: on a pulled
    image it is again protected and unrecorded. A run of lost replies, busy caps
    or holds never gives up (a real engine that answers 503 for ever is retried
    for ever: fail closed, the old behaviour).
  - **A newer claim during the cleanup.** The drop runs after the lane's
    containers are gone, but a leftover client of the lane can still talk to its
    socket. If the workspace claims a name again while the cleanup's delete of the
    older claim is in flight, the confirmation releases only the older claim; the
    newer record is still the workspace's tag in the engine, so the cleanup reports
    it in `left` and the retry untags it.
  - **Not covered:** tags whose records were lost when the ledger was quarantined
    as corrupt are unrecorded and, on a pulled image, are protected like any pulled
    tag; only `marsh docker rm` (which removes the whole Docker VM) clears them.
    The `Restorer` call (its ordering after the containers, the filtered socket as
    that workspace, the `left` report) is pinned by a Linux-only test
    (`restore::linux::drop_tests`, with an endpoint that is also a small engine); it
    does not run on macOS. The mapping of the engine's answer
    (`engine_api::untag_outcome`) and the relay's forwarding are tested everywhere.
  - Tests (`endpoint_tests.rs`, `ledger.rs`, `engine_api.rs`):
    `closing_a_workspace_untags_its_own_tags_and_frees_the_names`,
    `closing_a_workspace_leaves_a_tag_another_workspace_took`,
    `closing_a_workspace_leaves_a_name_another_workspace_pulled_after_its_rmi`,
    `a_retry_leaves_a_name_pulled_after_an_untag_of_unknown_outcome`,
    `deleting_your_own_tag_releases_its_record`,
    `the_cleanup_starts_by_dropping_records_of_missing_images`,
    `a_tag_longer_than_the_delete_route_allows_is_not_claimed`,
    `only_a_2xx_or_a_404_confirms_an_untag`, `a_failed_untag_keeps_the_claim_until_it_is_confirmed`,
    `a_permanent_refusal_is_given_up_with_a_message`, `the_relays_endpoint_runs_the_cleanup`,
    `a_claim_during_the_untag_is_refused`, `released_and_stale_records_free_the_tag_table`,
    `a_delete_is_confirmed_refused_or_unknown`, `a_busy_project_cap_is_not_counted_as_an_engine_refusal`,
    `a_late_confirmation_of_the_cleanup_reports_a_newer_claim`, `a_lost_engine_reply_is_not_counted_as_a_refusal`,
    `a_late_rmi_answer_keeps_the_same_workspaces_newer_claim`, `pulling_over_your_own_stale_record_releases_it`,
    `dropping_a_workspace_untags_its_tags_after_its_objects` (Linux).
- **A BuildKit stream is detected and reported, never undone** (DA1-02, DA1-04;
  `bk_watch.rs`). The default `docker build -t` and `docker buildx build -t` send no
  `POST /build`: they use `/grpc` and `/session` only (recorded e3 traffic,
  `e3/corpus/cli.jsonl`), and the tag names are inside the opaque BuildKit solve,
  which is not decoded (no HTTP/2 or protobuf reader). A REST `/build` (the legacy
  builder, `DOCKER_BUILDKIT=0`, or a hand-made call) is covered by the rules above.
  Without reading that traffic a tag that moved cannot be tied to the stream (it may
  be the tag's owner's own build or request), so an earlier design that put the tag
  back was dropped: a wrong restore, one that undoes a legitimate change of the owner,
  is worse than the gap. The agent only reports:
  1. **A stream begins** (`/grpc` or `/session` after the engine's 101, before any
     byte is relayed). The stream's window opens first: it counts every REST request
     that holds a name from then on, the names held at that moment, and the
     workspaces that have a stream running. Then the agent lists the engine's images
     as itself (`GET /images/json`, its only engine request) and notes the image ID
     of every tag the stream's workspace may not move: tags the ledger records to
     another workspace and unrecorded names on an image with a registry digest
     (`postgres:16`), at most 256, recorded ones first (more is an "unable to check"
     event). A tag recorded to the stream's workspace, and an unrecorded name on a
     local image, are its to move. Any REST request during the list counts for every
     tag, and streams that begin during it are all remembered until it is done (then
     only owners of noted tags are kept, so a long stream cannot accumulate
     workspaces). Image names the agent cannot make into a tag (over the 255 characters a tag may
     have, as a long pulled name can, or not a name the filter accepts, such as an
     IPv6 registry host) are not watched, and that is an "unable
     to check" event, not a silent skip; a list that fails is one too, and the stream
     runs (fail open). No lock is held across the list, but the tag table is locked briefly before
     it (to read the held names and open the window, as one step): a claim of another
     workspace that holds it across an engine inspect delays the start of a build by
     up to the engine's progress timeout (30 s) for each claim ahead of it (claims queue
     on the table), on top of the list's own time.
  2. **A stream ends** (the relay's pump returns, whoever closed it). The names are
     read again and each that has another image, or has gone, is reported once:
     time, tag, owner (`None`: a pulled name), previous and current image ID, a
     workspace, and **ambiguous** when the owner had a REST request on the name (any
     workspace's, for a pulled name), or a stream of its own running at the start or
     beginning during the window, or when that cannot be told (a request in the
     engine at the start, or during the first list): the text then says "this may be
     the owner's own change". Ambiguity errs towards true. The workspace is that of
     the stream that ended and saw it, which with overlapping streams is not
     necessarily the one that moved the tag ("workspace X's, or one that ran with
     it"). With overlapping streams the report carries `overlapped` and says so; the same change
     seen by streams that ran together is reported once; the
     same change after the user put the tag back, by a later stream, is reported
     again.
  3. **The text is the recovery**: if the previous image still exists,
     `docker tag <previous id> <name>` run in the owner's workspace puts it back (else
     rebuild it); a pulled name: `docker pull <name>` fetches the registry's current
     image, not necessarily the previous one. The text says the change is not undone.
     Events are a line on the agent's standard error and an entry of
     `Services::tag_events()` (the last 64). "Unable to check" is kept once per
     workspace and cause. At the cap the list gives up, in this order, a later report of
     a tag that has several (the first report of a tag is kept: it holds the owner's
     original image), then "unable to check" (never the one just added), then the oldest
     report; a tag's only report goes only when nothing else can. Nothing
     expires: a report stays until the agent restarts, even after the owner put the tag
     back, and a repeated "unable to check" for the same workspace and cause is never
     shown again. Not persisted.
  Not done: **the overwrite is detected after the stream, not prevented**: while the
  build runs, and from its export until its stream ends, the other workspace's tag
  points at the lane's image (a `docker run` of it then runs the lane's image), and
  nothing puts it back by itself; the report comes when the stream ends and says only
  "changed", with the ambiguity flag; a tag moved and moved back between the two
  reads is not seen; a tag a `/grpc` build creates is not recorded to anyone, so
  another workspace's build may take it, unseen (only tags created over REST, and
  pulled names, are protected); a lane's own build of a name whose image is also a
  pulled image's (a no-op `FROM alpine` build) counts as a pulled name and is
  reported; a pulled name stops being watched once a local image holds it (the watch
  looks at the registry digests of the image at the stream's start), so a second
  overwrite of it is silent; a name created after a stream began is not watched by it;
  a long-lived stream is checked only when it ends, and the two image lists a stream
  takes (the first before the client gets the engine's 101, so a slow engine delays
  a build's start) cost time and memory; the cache,
  `buildx prune`/`du` and history stay as exposed as before (below). Tests: the
  `bk_watch_tests` module of `endpoint_tests.rs`, each rule above removed once with a
  test failing.
- Names are not forced under `<workspace>/` (that would refuse `docker build -t app`
  and Compose's default names); the cost is that two workspaces cannot both build the
  same tag over REST, such as an `image:` plus `build:` stack.

Unit and endpoint tests: `every_path_that_names_an_image_*`,
`one_workspace_cannot_move_a_tag_*`, `a_foreign_pull_is_refused`,
`a_pull_of_every_tag_is_refused`, `an_active_pull_keeps_its_name_but_not_against_pulls`,
`a_foreign_delete_is_refused`, `deleting_your_own_alias_of_a_pulled_image_is_allowed`,
`a_client_that_disconnects_keeps_the_ownership_of_its_tag`,
`requests_in_flight_reserve_capacity_in_the_tag_table`,
`a_digest_pull_in_either_encoding_is_allowed`, `a_short_image_id_cannot_delete_a_foreign_tag`,
`a_delete_holds_its_name_until_the_engine_finishes`, `a_pull_waits_for_another_workspaces_delete_of_its_name`,
`a_delete_of_an_absent_name_waits_for_a_build_of_it`, `a_tag_cannot_be_put_on_an_image_while_it_is_being_deleted_by_id`,
`an_id_delete_waits_for_a_tag_being_put_on_the_image`,
`an_id_delete_is_never_forced_and_a_named_one_keeps_force`,
`a_cached_build_alias_survives_a_forced_id_delete_and_cannot_be_taken`,
`an_untagged_image_is_deleted_by_id_under_its_image_hold`,
`a_tag_named_like_the_id_prefix_cannot_force_delete_the_image`, `an_absent_id_looking_name_is_not_forced`,
`reconcile_sheds_stale_tag_records_but_not_held_or_live_ones`, `a_tag_is_free_again_after_its_image_is_deleted`,
`a_failed_or_refused_request_leaves_no_claim`, `an_active_build_keeps_its_tag`,
`racing_workspaces_get_a_new_tag_once`, `a_full_tag_table_drops_records_of_missing_images_only`.

## Compatibility notes

- Docker (API 1.44+) ignores a body on `start`, `stop`, `kill` and the other
  action routes, and dockerode sends `{}`; such bodies are read (bounded) and
  dropped, never forwarded.
- dockerode (Testcontainers) repeats create-body fields in the query string and
  puts `name` in the body. Both are ignored by Docker and dropped here; any
  other unknown query key is refused.
- Testcontainers mounts the job's own `DOCKER_HOST` path into Ryuk.
  `Config::socket_aliases` lists such caller-endpoint paths (for example
  `/run/marsh/docker.sock`) to substitute like `/var/run/docker.sock`; or the
  job sets `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock`.
- Compose and Testcontainers address networks by name in `NetworkMode`,
  `EndpointsConfig` and `Links`; they are rewritten to the full IDs the ledger
  resolved, and the engine reports the names back as usual.
- **TODO (E5):** `Config::registry_allow` itself defaults to allow-all; the engine
  sets it from `EngineConfig` (`engine-up --registry-allow`, written to
  `/run/marsh-svc/engine-config.json`; default Docker Hub plus `ghcr.io`, see
  `docs/design/services-engine.md`). The default is E5's decision; the agent only
  enforces the list it is given.

## Engine requirements (for S2)

The production `daemon.json` must set `"ip": "127.0.0.1"` (so `-P` publishes on
loopback) and keep the BuildKit entitlements off. The engine container needs
cgroup v2 delegation as in `docker:dind`'s entrypoint, or containers with the
default memory, CPU and PID limits fail to start. `pins::restore_all()` must run
before the production dockerd. (Done by S2/S2c: `engine-up`, break modes
`engine-ip-any` and `engine-cgroup-no-delegate`; `Services::restore_sockets()`
runs in the relay agent once it listens: TODO(E1).)

## Break modes

Every check in `policy` and `pins` calls `crate::breaks::break_mode`, which asks
`marsh_contracts::break_mode` (the `test-breaks` feature forwards to
`marsh-contracts/test-breaks`, so H2's release guards apply) and the modes the
daemon hands the agent in its argv. Each mode removes one defense, so that the
scenario that names it fails at the named check:

| Mode | Defect | Scenario and check |
|---|---|---|
| `filter-off` | no inspection at all | SEC-01 c1 |
| `filter-no-upgrade` | hijack never honoured | EP-04 c1 |
| `filter-case-sensitive` | keys that differ in case are forwarded as written | SEC-02 c1 (W-case) |
| `filter-lenient-json` | unparseable JSON fails open | SEC-02 c1 (duplicate keys) |
| `filter-raw-after-upgrade-header` | any `Upgrade` header makes the stream raw | SEC-03 c1 |
| `filter-forward-original-bytes` | the client's head is forwarded | SEC-23 c1 |
| `filter-no-resolve` | bind sources opened by plain path | SEC-04 c2 |
| `bind-no-pin` | resolved path rewritten, not pinned | SEC-04 c1 |
| `bind-repin-unchecked` | pins recreated by plain path | SEC-14 c1 |
| `bind-pin-leak` | pins never unmounted | SEC-14 c2 |
| `protected-subpin-off` | `.git` and `.marsh` not read-only | SEC-05 c3 |
| `lane-authority-off` | no scope checks, lists and events unfiltered | SEC-05 c1, RST-11 c1 |
| `scope-reference-check-off` | inspect by full ID skips the scope check | SEC-16 c1 |
| `reserved-labels-allowed` | `dev.marsh.*` accepted from clients | SEC-16 c2 |
| `socket-substitute-raw` | docker.sock binds pass unchanged | SEC-15 c1 |
| `socket-refuse` | docker.sock binds refused | SUPA-01 c1 |
| `services-resource-limit-off` | no default limits | SEC-20 c1 |
| `publish-nonloopback` | published ports keep their host IP | EP-10 c2 |
| `capture-api-gate-off` | state changes allowed while a scope is frozen | CAP-11 c1 |
| `freeze-no-wait` | a freeze does not wait for admitted requests | freeze.sh (late body), unit `a_freeze_waits_for_*` |
| `ledger-persist-ignore` | a failed ledger write is logged and acknowledged | ledger.sh, unit `a_ledger_write_failure_*` |
| `volume-claim-racy` | the loser of a volume race replaces the owner | volumes.sh, unit `concurrent_claims_*` |
| `bind-nonrecursive-allowed` | `bind-recursive=disabled` accepted | protected.sh, unit `non_recursive_bind_mounts_*` |
| `protected-by-name` | `.git`/`.marsh` recognised by spelling | protected.sh (`.GIT`, `.Marsh`) |
| `protected-marsh-late-off` | `.marsh` not made at a root pin | protected.sh (`late`) |
| `pin-allow-xdev` | resolve without `NO_XDEV` | pins.sh (tmpfs inside the project) |
| `pin-inherit-off` | `VolumesFrom` pins not leased | pins.sh (`volumes-from`), unit |
| `pin-file-leak` | a file pin's mountpoint is not removed | pins.sh (`file pin`) |
| `restore-fail-open` | an unrestorable pin is left absent | pins.sh (`failed restore`) |
| `protected-identity-off` | recorded `.git`/`.marsh` identities ignored (only the names found now count) | HF1 `protected-identity` |
| `sweep-pins-by-source-age` | the sweep as it was: ledger read before the directory, "old" is the source folder's mtime | HF1 `sweep-race` |
| `slow-pin-record` | 200 ms between mounting a pin and recording it (widens the window the sweep must respect) | HF1 `sweep-race` |
| `fault-pin-orphan` | a pin is mounted and never recorded (the agent died in between) | HF1 `sweep-orphan` |
| `hold-pin-before-ledger` | harness barrier between mounting and recording | HF1 `sweep-race` |
| `ports-list-all` | a `tcp` open lists every container in the engine (the check as it was) | PERF-05 (b) |
| `update-limits-unmerged` | update validated on the patch alone | limits.sh, unit `update_limits_are_validated_*` |
| `commit-any-repo` | commit into any repository | sec01.sh, unit `commits_go_only_*` |
| `anon-volume-unlabeled` | anonymous volumes get no scope label | volumes.sh, unit |
| `project-cap-per-root` | the project cap counted per workspace root | unit `the_project_cap_counts_*` |
| `hijack-deadlines-off` | raw streams without deadlines or peer checks | unit `a_silent_hijacked_stream_*` and two more |
| `list-fail-open` | an unfilterable list is passed on | unit `a_list_that_cannot_be_filtered_*` |
| `scope-default-network-off` | the scope's default network is Docker's shared bridge | EP-10 c1 |
| `restart-update-allowed`, `network-mtu-allowed`, `private-propagation-allowed`, `fullid-name-allowed`, `outputs-open`, `network-name-forwarded` | the schema or reference tightening it names | sec01.sh / limits.sh and the unit table |

`e3/breaks.sh` runs the end-to-end rows and requires each to trip its own
witness and nothing else; `e3/witness.sh` runs the in-process rows
(`E3_TEST_BREAKS`, read only by the unit-test build) and requires the same.

## Known limits

- BuildKit gRPC (`/grpc`, `/session`) is relayed, not parsed (DECISIONS 21):
  cache mount IDs are not scoped (same-project cross-workspace cache sharing is
  accepted), and a remote context or frontend requested over gRPC is not seen
  here; the VM's policy and firewall govern it. Entitlements are denied by the
  engine's `daemon.json`.
- **`/grpc` is the whole BuildKit `Control` service** (RR3 DA1-04): Solve, but also
  `Prune`, `DiskUsage` and the build-history calls (`ListenBuildHistory`,
  `UpdateBuildHistory`), none of them scoped. So the REST refusal of
  `POST /build/prune` is not a refusal of pruning, and one scope can read or delete
  another's build records (build arguments, logs). Unit
  `grpc_is_relayed_unread_so_the_build_prune_refusal_does_not_cover_it`. Narrowing
  it needs an HTTP/2 proxy with an HPACK decoder in front of the stream, to allow
  `Control/Solve` and `Control/Status` of the scope's own build only; refusing
  `/grpc` outright would break plain `docker build` too, not only `buildx`: the
  recorded e3 traffic (`e3/corpus/cli.jsonl`) shows both use `/grpc` and `/session`
  and send no REST `/build`. Neither is done. This is also the piece DA1-02 (image
  tag ownership) needs: the tag names of a normal build are inside the same stream,
  so gating `/grpc` is one piece of follow-up work for both (until then a tag a
  stream moved is detected and reported, see "A BuildKit stream is detected and
  reported, never undone" above). The behaviors above
  are BuildKit's and were traced from its API, not run through the filter.
- **A `/grpc` push is a residual** (DECISIONS 21): a BuildKit solve may export to
  a registry (`type=image,push=true`) inside the opaque gRPC stream, where the
  `outputs` query check does not see it. Refusing it would need parsing the
  h2c/gRPC `Control.Solve` request, which D21 moves out of E3; the egress is
  limited to what the engine's network policy lets the project's VM reach.
- **A build fetches from the engine's own network namespace** (RR3 DA1-03). The
  `Dockerfile` and context are streamed unread, so `FROM`, `# syntax=`, `cachefrom`
  and `ADD <url>` are fetched by dockerd/BuildKit outside the Internet gate and the
  registry allowlist (only a pull, a create and, on the REST `/build` route alone, a
  `BUILDKIT_SYNTAX` build argument are checked; the default `docker build` and
  `buildx` go over `/grpc` and `/session` and get no frontend check). Every scope publishes on `127.0.0.1` of that namespace (and a port published on
  another loopback address, `127.0.0.2`, is reachable the same way), so a
  build can GET another scope's published HTTP service. Loopback is not blocked: the
  agent's relay dials `127.0.0.1` there for `tcp` channels, so a plain `OUTPUT` rule
  would cut the ports too. Closing it needs a per-scope builder or a cgroup-scoped
  `OUTPUT` rule for the build processes. The classic builder (`version=1`) is still
  admitted and pulls `FROM` in dockerd itself.
- The agent's argv carries break modes only in `test-breaks` builds (DECISIONS 22).
- Images are shared by every scope of a project: any scope may run an image
  another created. Only the tag names are owned, and only on the REST routes
  (above); a BuildKit build over `/grpc`, which is what `docker build` and `docker
  buildx build` use, can still name any tag, and is detected afterwards (above).
- Network and volume names are global in the engine; a name used by another
  scope is refused.
