---------------------------- MODULE KitInstall ----------------------------
(* The VM of a `marsh kit install` that failed (issue #194), and the per-  *)
(* Kit lifecycle locks, install records and ownership map that keep it     *)
(* reachable by `marsh workers reset NAME|all` without ever removing a VM  *)
(* the daemon cannot prove is its own. A DESIGN model: it fixes the        *)
(* protocol the code must follow (docs/model/README.md, "Kit install").    *)
(*                                                                         *)
(* Stock SBX is a name -> VM table (A1: names are random and the daemon's, *)
(* A2: a create is atomic on its name; a second create under a name whose *)
(* create is pending is refused). A create returns ok, fails with a VM     *)
(* listed, fails with none, fails although it lands later (FailedMayLand), *)
(* or times out; what did not land may land at any later time (Land) or   *)
(* never. The ownership map gives each name a state: free, live (an intent *)
(* or a recorded VM: the daemon's) or retired (forgotten after its VM was *)
(* removed; never assigned again). A VM listed under a live name is the    *)
(* daemon's (an intent is adopted at the next listing); one under a        *)
(* retired name is classified foreign and is never removed. `kit` is the  *)
(* Kit identity a name was assigned for (the key of its lock).             *)
(*                                                                         *)
(* Install records are per attempt and persisted with the ownership map   *)
(* (the design's choice; recordsInMemory shows why). The quarantine and    *)
(* the uncertain-create marks are in memory. A daemon Restart (crash,      *)
(* upgrade, or the end of `marsh stop --force`) ends every process, frees  *)
(* every lock and drops the in-memory state; stock creates already         *)
(* submitted go on and may land.                                           *)
(*                                                                         *)
(* Processes: the install process (installs serialize on registry_install; *)
(* one attempt after another, each a new id): prepare, submit, reply,      *)
(* publish (register the command), the Kit lock held throughout; a job     *)
(* preparing the registered command C's Kit VM; `workers reset NAME` (H)   *)
(* or `all`; a Kit switch of C to the other Kit; single-step background    *)
(* recovery and VM GC (under the VM's Kit lock); `marsh reset` teardown    *)
(* (only at quiescence: lifecycle admission); `marsh stop --force`: it     *)
(* closes admission, cancels the install's create (its reply becomes a    *)
(* timeout, the VM may still land), drains every request, tears down and  *)
(* restarts. A process that holds one lock and waits for no other takes,   *)
(* uses and releases it in one step; the install keeps its lock across    *)
(* steps but waits for nothing; reset and the switch take two and have a   *)
(* wait state, so TLC sees every wait-for cycle (NoDeadlock).              *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS NN,            \* number of VM names (1..NN)
          MaxAttempts,   \* install attempts of H
          MaxJobs, MaxResets, MaxSwitches, MaxTeardowns, MaxStops, MaxRestarts,
          MaxLate,       \* creates that time out or fail and land later
          FailedMayLand, \* a create stock reported failed may still land
          InstallKits,   \* the Kits an attempt may install H from
          Actors,        \* which of "job", "sw", "rcv", "gc", "td", "stop", "restart" act
          Bug

None == "none"
Kits == {"a", "b"}
KitOrder == <<"a", "b">>        \* the lock key order
H == "h"                         \* the command `marsh kit install` installs
C == "c"                         \* a registered command (switched by Switch)
Cmds == {C, H}
NameIds == 1..NN
NameSeq == [j \in 1..NN |-> j]
Att == 1..MaxAttempts
Procs == {"inst", "job", "rst", "sw"}
Live == "live"
Active == {"running", "settled"}

Bugs == {"none", "lateLandingLost", "oldAttemptErasesNew", "recoveryKeepsRecord",
         "resetAllSnapshotRace", "nameBeforeRecovery", "lockPerVm", "jobPathStaleName",
         "switchAbba", "removeUnowned", "recoveryNoLock", "resetIgnoresRecords",
         "forgetFailedIntent", "restartLosesUncertainty", "recordsInMemory",
         "forceStopForgetsIntents", "resetNoop", "resetNoLock", "noReplan",
         "switchKeepsRecord", "narrowResetAll",
         "lockOnly", "revalidateOnly"}    \* the last two are positive: one safeguard each
ASSUME Bug \in Bugs /\ InstallKits \subseteq Kits
ASSUME Actors \subseteq {"job", "sw", "rcv", "gc", "td", "stop", "restart"}

(* Each control is a deviation of the reviewed code (or a tempting fix)   *)
(* set against the clean design; one that needs two names both (README).  *)
EarlyDecide    == Bug = "resetAllSnapshotRace"                      \* install recovers, decides, records before its Kit lock
ResetSnapshot  == Bug \in {"oldAttemptErasesNew", "resetAllSnapshotRace"} \* reset plans before its locks
ForgetByName   == Bug = "oldAttemptErasesNew"                       \* reset forgets every record of a command it targeted
EndAlways      == Bug = "lateLandingLost"                            \* reset ends a record although its intent stays
KeepOnRecovery == Bug \in {"recoveryKeepsRecord", "lockPerVm"}       \* recovery removes the VM, keeps its records
StaleCheck     == Bug = "recoveryKeepsRecord"                        \* reset refuses "recorded VM changed"
NameBeforeRec  == Bug \in {"nameBeforeRecovery", "removeUnowned"}    \* install decides before its own recovery
NoRevalidate   == Bug \in {"resetAllSnapshotRace", "nameBeforeRecovery", "jobPathStaleName", "removeUnowned",
                          "recoveryNoLock", "resetNoLock", "noReplan", "lockOnly"} \* create under the decided name unchecked
RecoveryNoLock == Bug \in {"recoveryNoLock", "revalidateOnly"}       \* recovery of an unnamed VM takes no Kit lock
ResetNoLock    == Bug \in {"resetNoLock", "revalidateOnly"}          \* reset takes no Kit lock
NoReplan       == Bug = "noReplan"                                   \* reset acts on locks taken for an older plan
NoRunSkip      == Bug \in {"resetNoLock", "noReplan"}               \* reset ignores running records (main: no records)
PerVmLocks     == Bug = "lockPerVm"                                  \* reset takes one lock per target VM
JobEarly       == Bug = "jobPathStaleName"                           \* job decides its name before lock and recovery
Abba           == Bug = "switchAbba"                                 \* switch holds the old Kit lock, then takes the new
RemoveUnowned  == Bug = "removeUnowned"                              \* reset removes a recorded VM the map does not own
IgnoreRecords  == Bug = "resetIgnoresRecords"                        \* reset NAME targets the registered VM only (#194)
ForgetFailed   == Bug \in {"forgetFailedIntent", "restartLosesUncertainty"} \* a reported failure, nothing listed, no
                                                                    \* in-memory uncertainty: the intent is forgotten
RecordsVolatile == Bug = "recordsInMemory"                           \* install records do not survive a restart
StopForgets    == Bug = "forceStopForgetsIntents"                    \* the forced stop's teardown forgets absent intents
ResetNoop      == Bug = "resetNoop"                                  \* a reset that is not refused removes nothing
SwitchKeepsRec == Bug = "switchKeepsRecord"                          \* the switch retires the old VM, keeps its records
NarrowAll      == Bug = "narrowResetAll"                             \* reset all = commands' VMs + records + quarantined

VARIABLES
  st,        \* [NameIds -> "free" | "live" | "retired"] ownership map (persisted)
  kit,       \* [NameIds -> Kits \cup {None}] the Kit a name was assigned for
  stock,     \* [NameIds -> BOOLEAN] stock lists a VM under the name
  inflight,  \* [NameIds -> BOOLEAN] ghost: a submitted create has not landed (may never)
  mk,        \* [NameIds -> 0..MaxAttempts] ghost: the install attempt that created it (0: job/switch)
  unsure,    \* [NameIds -> BOOLEAN] in memory: a create under it returned with no verdict (ForgetFailed only)
  quar,      \* quarantined names (in memory)
  rec,       \* [Att -> [st : "none"|"running"|"settled"|"ended", vm : 0..NN]] install records (persisted)
  reg,       \* [Cmds -> Kits \cup {None}] registered commands
  owner,     \* [Kits -> Procs \cup {None}] Kit lock holder
  pc,        \* [Procs -> step]
  iAtt, iK, iN,          \* install: current attempt, its Kit, its name
  jK, jN, jRuns,         \* job (jobPathStaleName: decided before the lock)
  rMode, rL, rT, rHad, rRuns, \* reset: mode, locks still to take, snapshot targets, snapshot had a record
  sFrom, sTo, sL, sRuns, \* switch
  tdRuns, stopping, stops, restarts, lates,
  bad,       \* ghost: a VM was removed although the map did not prove it the daemon's
  rstBad     \* ghost: a reset that was not refused left a target listed under a live name

vars == <<st, kit, stock, inflight, mk, unsure, quar, rec, reg, owner, pc, iAtt, iK, iN,
          jK, jN, jRuns, rMode, rL, rT, rHad, rRuns, sFrom, sTo, sL, sRuns, tdRuns,
          stopping, stops, restarts, lates, bad, rstBad>>
world == <<st, kit, stock, inflight, mk, unsure, quar, rec, bad>>
iVars == <<iAtt, iK, iN>>
jVars == <<jK, jN, jRuns>>
rVars == <<rMode, rL, rT, rHad, rRuns>>
sVars == <<sFrom, sTo, sL, sRuns>>
eVars == <<tdRuns, stopping, stops, restarts, lates, rstBad>>

NoRec == [st |-> "none", vm |-> 0]

TypeOK ==
  /\ st \in [NameIds -> {"free", Live, "retired"}]
  /\ kit \in [NameIds -> Kits \cup {None}]
  /\ stock \in [NameIds -> BOOLEAN] /\ inflight \in [NameIds -> BOOLEAN]
  /\ unsure \in [NameIds -> BOOLEAN] /\ mk \in [NameIds -> 0..MaxAttempts]
  /\ quar \subseteq NameIds
  /\ rec \in [Att -> [st : {"none", "running", "settled", "ended"}, vm : 0..NN]]
  /\ reg \in [Cmds -> Kits \cup {None}]
  /\ owner \in [Kits -> Procs \cup {None}]
  /\ bad \in BOOLEAN /\ rstBad \in BOOLEAN /\ stopping \in BOOLEAN

Init ==
  /\ st = [n \in NameIds |-> "free"] /\ kit = [n \in NameIds |-> None]
  /\ stock = [n \in NameIds |-> FALSE] /\ inflight = [n \in NameIds |-> FALSE]
  /\ mk = [n \in NameIds |-> 0] /\ unsure = [n \in NameIds |-> FALSE]
  /\ quar = {} /\ rec = [i \in Att |-> NoRec]
  /\ reg = [c \in Cmds |-> IF c = C THEN "b" ELSE None]
  /\ owner = [k \in Kits |-> None]
  /\ pc = [p \in Procs |-> "idle"]
  /\ iAtt = 0 /\ iK = "a" /\ iN = 0
  /\ jK = "a" /\ jN = 0 /\ jRuns = 0
  /\ rMode = "all" /\ rL = <<>> /\ rT = {} /\ rHad = FALSE /\ rRuns = 0
  /\ sFrom = "a" /\ sTo = "a" /\ sL = <<>> /\ sRuns = 0
  /\ tdRuns = 0 /\ stopping = FALSE /\ stops = 0 /\ restarts = 0 /\ lates = 0
  /\ bad = FALSE /\ rstBad = FALSE

---------------------------------------------------------------------------
(* The daemon's state as a record, so that one step can compose effects.  *)
W0 == [st |-> st, kit |-> kit, stock |-> stock, inflight |-> inflight, mk |-> mk,
       unsure |-> unsure, quar |-> quar, rec |-> rec, bad |-> bad]
SetW(W) == /\ st' = W.st /\ kit' = W.kit /\ stock' = W.stock /\ inflight' = W.inflight
           /\ mk' = W.mk /\ unsure' = W.unsure /\ quar' = W.quar /\ rec' = W.rec
           /\ bad' = W.bad

Min(S) == CHOOSE x \in S : \A y \in S : x <= y
SortKits(S) == SelectSeq(KitOrder, LAMBDA k : k \in S)
Quiescent == \A p \in Procs : pc[p] = "idle"
Held(p) == {k \in Kits : owner[k] = p}
Release(p) == owner' = [k \in Kits |-> IF owner[k] = p THEN None ELSE owner[k]]
Acts(a) == a \in Actors /\ ~stopping

\* The name the map records for Kit k, never assigning one (0: none).
LookupW(W, k) == IF \E n \in NameIds : W.st[n] = Live /\ W.kit[n] = k
                 THEN CHOOSE n \in NameIds : W.st[n] = Live /\ W.kit[n] = k ELSE 0
\* `vm_name`/`assign`: the recorded name, else a fresh one persisted as an intent.
AssignW(W, k) ==
  LET l == LookupW(W, k)
      free == {n \in NameIds : W.st[n] = "free"}
  IN IF l # 0 THEN [n |-> l, w |-> W]
     ELSE IF free = {} THEN [n |-> 0, w |-> W]
     ELSE LET f == Min(free) IN [n |-> f, w |-> [W EXCEPT !.st[f] = Live, !.kit[f] = k]]

EndRecs(W, S, states) ==
  [W EXCEPT !.rec = [i \in Att |-> IF W.rec[i].vm \in S /\ W.rec[i].st \in states
                                   THEN [W.rec[i] EXCEPT !.st = "ended"] ELSE W.rec[i]]]
Settle(W, i) == IF W.rec[i].st = "running" THEN [W EXCEPT !.rec[i].st = "settled"] ELSE W

\* Fenced removal of the VMs of S (`remove_owned_vm`): gone, the names
\* retired, their quarantines and the records naming them (in `states`) end.
RemoveW(W, S, states) ==
  EndRecs([W EXCEPT !.stock = [n \in NameIds |-> IF n \in S THEN FALSE ELSE W.stock[n]],
                    !.st = [n \in NameIds |-> IF n \in S THEN "retired" ELSE W.st[n]],
                    !.quar = W.quar \ S,
                    !.bad = W.bad \/ (\E n \in S : W.st[n] # Live)], S, states)

\* Recovery of a quarantined name: its VM removed if listed under a live
\* name (one under a retired name is foreign: refused); an absent intent is
\* kept (its create may still land) with its records; the quarantine ends.
Recovery(W, n) ==
  IF W.stock[n] /\ W.st[n] = Live THEN RemoveW(W, {n}, IF KeepOnRecovery THEN {} ELSE Active)
  ELSE IF W.stock[n] THEN W
  ELSE [W EXCEPT !.quar = W.quar \ {n}]

RecoverCur(W, k, ok) ==
  LET cur == LookupW(W, k) IN
  IF ok /\ cur # 0 /\ cur \in W.quar THEN Recovery(W, cur) ELSE W

\* A create under n that stock reported failed, nothing listed afterwards:
\* quarantined, intent and records kept (it may still land). ForgetFailed:
\* the intent and records end unless the in-memory mark says uncertain.
FailedW(W, n) ==
  IF ForgetFailed /\ W.st[n] = Live /\ ~W.unsure[n] /\ ~W.stock[n]
  THEN EndRecs([W EXCEPT !.st[n] = "retired", !.quar = W.quar \ {n}], {n}, Active)
  ELSE [W EXCEPT !.quar = W.quar \cup {n}]
TimedOutW(W, n) ==
  [W EXCEPT !.quar = W.quar \cup {n}, !.unsure[n] = IF ForgetFailed THEN TRUE ELSE W.unsure[n]]

Outs == {"ok", "failVm", "failNoVm"}
          \cup (IF lates < MaxLate THEN {"timeout"} \cup (IF FailedMayLand THEN {"failLands"} ELSE {})
                ELSE {})

\* One whole `sbx create` (job, switch): under n by `who` with outcome o,
\* after a fresh listing; a listed VM is reused (ours, not quarantined) or
\* refused; a create still pending makes stock refuse this one (A2).
Create(W, n, who, o) ==
  IF W.stock[n] THEN [w |-> W, ok |-> W.st[n] = Live /\ n \notin W.quar, made |-> FALSE]
  ELSE IF W.inflight[n] THEN [w |-> FailedW(W, n), ok |-> FALSE, made |-> FALSE]
  ELSE CASE o = "ok" ->
              \* `adopt_created` -> `record` takes back even a just-retired name.
              [w |-> [W EXCEPT !.stock[n] = TRUE, !.mk[n] = who, !.st[n] = Live], ok |-> TRUE, made |-> FALSE]
         [] o = "failVm" ->
              [w |-> [W EXCEPT !.stock[n] = TRUE, !.mk[n] = who, !.quar = W.quar \cup {n}], ok |-> FALSE, made |-> FALSE]
         [] o = "failNoVm" -> [w |-> FailedW(W, n), ok |-> FALSE, made |-> FALSE]
         [] o = "failLands" ->
              [w |-> FailedW([W EXCEPT !.inflight[n] = TRUE, !.mk[n] = who], n), ok |-> FALSE, made |-> TRUE]
         [] o = "timeout" ->
              [w |-> TimedOutW([W EXCEPT !.inflight[n] = TRUE, !.mk[n] = who], n), ok |-> FALSE, made |-> TRUE]
Late(made) == lates' = lates + (IF made THEN 1 ELSE 0)

---------------------------------------------------------------------------
(* `marsh kit install H REF`. Clean: Kit lock first; under it recovery,   *)
(* the name, the record (attempt id, name); the submit re-validates the    *)
(* name (still a live entry of this Kit, else it decides again and re-    *)
(* points the record); the reply settles it; publication registers H and  *)
(* ends the record, the lock held until then. A forced stop aborts before *)
(* the submit or the publication, and turns the reply into a timeout.     *)

\* resetAllSnapshotRace (round 2): recovery (which takes the Kit lock for
\* itself), the name and the record before the install's own Kit lock.
InstDecideEarly ==
  /\ EarlyDecide /\ ~stopping /\ pc["inst"] = "idle" /\ iAtt < MaxAttempts /\ reg[H] = None
  /\ \E k \in InstallKits, ok \in BOOLEAN :
       LET a == AssignW(RecoverCur(W0, k, ok), k) IN
       /\ owner[k] = None /\ a.n # 0
       /\ SetW([a.w EXCEPT !.rec[iAtt + 1] = [st |-> "running", vm |-> a.n]])
       /\ iK' = k /\ iN' = a.n
  /\ iAtt' = iAtt + 1
  /\ pc' = [pc EXCEPT !["inst"] = "wait"]
  /\ UNCHANGED <<reg, owner, jVars, rVars, sVars, eVars>>

InstPrep ==
  /\ ~stopping
  /\ IF EarlyDecide THEN pc["inst"] = "wait"
     ELSE pc["inst"] = "idle" /\ iAtt < MaxAttempts /\ reg[H] = None
  /\ \E k \in (IF EarlyDecide THEN {iK} ELSE InstallKits), ok \in BOOLEAN :
       LET i == IF EarlyDecide THEN iAtt ELSE iAtt + 1
           cur == LookupW(W0, k)
           W1 == IF EarlyDecide THEN W0 ELSE RecoverCur(W0, k, ok)
           post == AssignW(W1, k)
           early == EarlyDecide \/ (NameBeforeRec /\ cur # 0)
           n == IF EarlyDecide THEN iN ELSE IF early THEN cur ELSE post.n
           W2 == IF early THEN W1 ELSE post.w
       IN /\ owner[k] = None /\ n # 0
          /\ SetW(IF EarlyDecide THEN W2 ELSE [W2 EXCEPT !.rec[i] = [st |-> "running", vm |-> n]])
          /\ owner' = [owner EXCEPT ![k] = "inst"]
          /\ iAtt' = i /\ iK' = k /\ iN' = n
  /\ pc' = [pc EXCEPT !["inst"] = "create"]
  /\ UNCHANGED <<reg, jVars, rVars, sVars, eVars>>

\* Ends the install without its lock (and, for "wait", holding none).
InstEnd(W) == /\ SetW(Settle(W, iAtt)) /\ Release("inst") /\ pc' = [pc EXCEPT !["inst"] = "idle"]

InstSubmit ==
  /\ pc["inst"] = "create" /\ ~stopping
  /\ LET i == iAtt
         k == iK
         redo == ~(st[iN] = Live /\ kit[iN] = k) /\ ~NoRevalidate
         a == IF redo THEN AssignW(W0, k) ELSE [n |-> iN, w |-> W0]
         n == a.n
         Wr == IF redo THEN [a.w EXCEPT !.rec[i] = [st |-> "running", vm |-> n]] ELSE a.w
     IN /\ n # 0
        /\ iN' = n
        /\ IF Wr.stock[n] THEN    \* reuse a listed VM, or refuse it (quarantined, foreign)
             IF Wr.st[n] = Live /\ n \notin Wr.quar
             THEN SetW(Wr) /\ pc' = [pc EXCEPT !["inst"] = "publish"] /\ UNCHANGED owner
             ELSE InstEnd(Wr)
           ELSE IF Wr.inflight[n] THEN InstEnd(FailedW(Wr, n))      \* A2: refused, a definite failure
           ELSE /\ SetW([Wr EXCEPT !.inflight[n] = TRUE, !.mk[n] = i])
                /\ pc' = [pc EXCEPT !["inst"] = "flight"] /\ UNCHANGED owner
  /\ UNCHANGED <<reg, iAtt, iK, jVars, rVars, sVars, eVars>>

\* The reply of the submitted create. Its create may have landed meanwhile
\* (inflight is then FALSE), and the VM may even be gone again: a reply
\* never lands a VM a second time, and `adopt_created` fails on an absent VM.
InstReply ==
  /\ pc["inst"] = "flight"
  /\ LET n == iN
         pending == inflight[n]
         outs == IF stopping THEN {"timeout"}           \* cancelled: the call is killed
                 ELSE IF ~pending
                 THEN IF stock[n] THEN {"ok", "failVm", "timeout"} ELSE {"failVm", "timeout"}
                 ELSE {"ok", "failVm", "failNoVm"}
                      \cup (IF lates < MaxLate
                            THEN {"timeout"} \cup (IF FailedMayLand THEN {"failLands"} ELSE {}) ELSE {})
     IN \E o \in outs :
        /\ Late(o \in {"timeout", "failLands"} /\ pending /\ ~stopping)
        /\ CASE o = "ok" ->
                  /\ SetW([W0 EXCEPT !.stock[n] = TRUE, !.inflight[n] = FALSE, !.st[n] = Live])
                  /\ pc' = [pc EXCEPT !["inst"] = "publish"] /\ UNCHANGED owner
             [] o = "failVm" ->
                  InstEnd([W0 EXCEPT !.stock[n] = (stock[n] \/ pending), !.inflight[n] = FALSE,
                                     !.quar = quar \cup {n}])
             [] o = "failNoVm" -> InstEnd(FailedW([W0 EXCEPT !.inflight[n] = FALSE], n))
             [] o = "failLands" -> InstEnd(FailedW(W0, n))
             [] o = "timeout" -> InstEnd(TimedOutW(W0, n))
  /\ UNCHANGED <<reg, iVars, jVars, rVars, sVars, tdRuns, stopping, stops, restarts, rstBad>>

InstPublish ==
  /\ pc["inst"] = "publish" /\ ~stopping
  /\ SetW([W0 EXCEPT !.rec[iAtt].st = "ended"])
  /\ reg' = [reg EXCEPT ![H] = iK]
  /\ Release("inst")
  /\ pc' = [pc EXCEPT !["inst"] = "idle"]
  /\ UNCHANGED <<iVars, jVars, rVars, sVars, eVars>>

\* A forced stop: before the submit, before the publication, or waiting.
InstAbort ==
  /\ stopping /\ pc["inst"] \in {"wait", "create", "publish"}
  /\ InstEnd(W0)
  /\ UNCHANGED <<reg, iVars, jVars, rVars, sVars, eVars>>

---------------------------------------------------------------------------
(* A job of the registered command C prepares its Kit's VM (the job path: *)
(* `prepare_one_unnoted`): one step under the Kit lock, as the install's. *)

JobDecideEarly ==    \* jobPathStaleName: the name before the lock and the recovery
  /\ JobEarly /\ Acts("job") /\ pc["job"] = "idle" /\ jRuns < MaxJobs /\ reg[C] # None
  /\ LET a == AssignW(W0, reg[C]) IN
       /\ a.n # 0 /\ SetW(a.w) /\ jK' = reg[C] /\ jN' = a.n
  /\ jRuns' = jRuns + 1
  /\ pc' = [pc EXCEPT !["job"] = "wait"]
  /\ UNCHANGED <<reg, owner, iVars, rVars, sVars, eVars>>

JobRun ==
  /\ Acts("job")
  /\ IF JobEarly THEN pc["job"] = "wait" ELSE pc["job"] = "idle" /\ jRuns < MaxJobs /\ reg[C] # None
  /\ LET k == IF JobEarly THEN jK ELSE reg[C] IN
     /\ owner[k] = None
     /\ \E ok \in BOOLEAN, o \in Outs :
          LET W1 == RecoverCur(W0, k, ok)
              post == AssignW(W1, k)
              n0 == IF JobEarly THEN jN ELSE post.n
              W2 == IF JobEarly THEN W1 ELSE post.w
              redo == ~(W2.st[n0] = Live /\ W2.kit[n0] = k) /\ ~NoRevalidate
              a == IF redo THEN AssignW(W2, k) ELSE [n |-> n0, w |-> W2]
              res == Create(a.w, a.n, 0, o)
          IN /\ n0 # 0 /\ a.n # 0 /\ SetW(res.w) /\ Late(res.made)
  /\ jRuns' = IF JobEarly THEN jRuns ELSE jRuns + 1
  /\ pc' = [pc EXCEPT !["job"] = "idle"]
  /\ UNCHANGED <<reg, owner, iVars, jK, jN, rVars, sVars, tdRuns, stopping, stops, restarts, rstBad>>

JobAbort ==
  /\ stopping /\ pc["job"] = "wait"
  /\ pc' = [pc EXCEPT !["job"] = "idle"]
  /\ UNCHANGED <<world, reg, owner, iVars, jVars, rVars, sVars, eVars>>

---------------------------------------------------------------------------
(* `marsh workers reset NAME|all`. Clean: from the state, the Kits it may *)
(* touch (no name decided); their locks in key order; then, under them,   *)
(* the plan, started over if it needs a lock not taken. `all` targets     *)
(* every live name and every name a record names; NAME (H) the VM its     *)
(* registered Kit has and the names its settled records name. A listed VM *)
(* under a live name is removed and its name retired; an absent intent is *)
(* kept with its records (its create may still land); a listed VM under a *)
(* retired name is foreign and refuses the reset. A record ends with its  *)
(* name.                                                                   *)

RecVMs == {rec[i].vm : i \in {j \in Att : rec[j].st = "settled"}}
RunVMs == {rec[i].vm : i \in {j \in Att : rec[j].st = "running"}}
Targets(m) ==
  IF m = "all"
  THEN IF NarrowAll
       THEN ({LookupW(W0, reg[c]) : c \in {d \in Cmds : reg[d] # None}} \ {0}) \cup RecVMs \cup quar
       ELSE {n \in NameIds : st[n] = Live} \cup RecVMs
  ELSE (IF IgnoreRecords THEN {} ELSE RecVMs)
         \cup (IF reg[H] # None /\ LookupW(W0, reg[H]) # 0 THEN {LookupW(W0, reg[H])} ELSE {})
NeedKits(m) ==
  ({kit[t] : t \in Targets(m) \cup RunVMs} \ {None})
    \cup (IF m = "all" THEN {reg[c] : c \in {d \in Cmds : reg[d] # None}}
          ELSE IF reg[H] # None THEN {reg[H]} ELSE {})
\* One lock per target VM, in name order (lockPerVm).
PerVm(T) == LET s == SelectSeq(NameSeq, LAMBDA n : n \in T) IN [j \in 1..Len(s) |-> kit[s[j]]]

\* Why a reset with these targets is refused, other than a running install.
Refuses(T) ==
  \/ \E t \in T : stock[t] /\ st[t] # Live /\ ~RemoveUnowned
  \/ StaleCheck /\ \E i \in Att : rec[i].st = "settled" /\ rec[i].vm # LookupW(W0, kit[rec[i].vm])

RstStart ==
  /\ ~stopping /\ pc["rst"] = "idle" /\ rRuns < MaxResets
  /\ \E m \in {"name", "all"} :
       LET T == IF ResetSnapshot /\ m = "all" THEN Targets(m) \ RunVMs ELSE Targets(m) IN
       \* `reset NAME` of a name no command or record knows: "not found", nothing done.
       /\ m = "all" \/ reg[H] # None \/ \E i \in Att : rec[i].st \in Active
       /\ ~(ResetSnapshot /\ m = "name" /\ RunVMs # {})   \* refused "still running" at the snapshot
       /\ rMode' = m /\ rT' = T
       /\ rHad' = (ForgetByName /\ T \cap RecVMs # {})
       /\ rL' = IF ResetNoLock THEN <<>> ELSE IF PerVmLocks THEN PerVm(T) ELSE SortKits(NeedKits(m))
  /\ pc' = [pc EXCEPT !["rst"] = "lock"]
  /\ UNCHANGED <<world, reg, owner, iVars, jVars, rRuns, sVars, eVars>>

RstLock ==
  /\ pc["rst"] = "lock" /\ rL # <<>>
  /\ owner[Head(rL)] = None          \* a Mutex is not reentrant: held by rst itself, it waits forever
  /\ owner' = [owner EXCEPT ![Head(rL)] = "rst"]
  /\ rL' = Tail(rL)
  /\ UNCHANGED <<world, reg, pc, iVars, jVars, rMode, rT, rHad, rRuns, sVars, eVars>>

Planned == ResetSnapshot \/ PerVmLocks \/ ResetNoLock \/ NoReplan

RstReplan ==
  /\ pc["rst"] = "lock" /\ rL = <<>> /\ ~Planned
  /\ ~(NeedKits(rMode) \subseteq Held("rst"))
  /\ Release("rst")
  /\ rL' = SortKits(NeedKits(rMode))
  /\ UNCHANGED <<world, reg, pc, iVars, jVars, rMode, rT, rHad, rRuns, sVars, eVars>>

RstAct ==
  /\ pc["rst"] = "lock" /\ rL = <<>>
  /\ Planned \/ NeedKits(rMode) \subseteq Held("rst")
  /\ LET T0 == IF ResetSnapshot \/ PerVmLocks THEN rT ELSE Targets(rMode)
         busy == ~ResetSnapshot /\ ~NoRunSkip /\ rMode = "name" /\ RunVMs # {}
         T == IF rMode = "all" /\ ~ResetSnapshot /\ ~NoRunSkip THEN T0 \ RunVMs ELSE T0
         Rm == {t \in T : stock[t] /\ (st[t] = Live \/ RemoveUnowned)}
         W1 == RemoveW(W0, Rm, {"settled"})
         W2 == [W1 EXCEPT !.quar = W1.quar \ T]
         Gone == {t \in T : W2.st[t] # Live}
         W3 == IF rHad THEN [W2 EXCEPT !.rec = [i \in Att |-> IF W2.rec[i].st \in Active
                                                THEN [W2.rec[i] EXCEPT !.st = "ended"] ELSE W2.rec[i]]]
               ELSE IF EndAlways THEN EndRecs(W2, T, {"settled"})
               ELSE EndRecs(W2, Gone, {"settled"})
         W4 == IF ResetNoop THEN W0 ELSE W3
     IN IF busy \/ Refuses(T) THEN UNCHANGED <<world, rstBad>>
        ELSE /\ SetW(W4)
             /\ rstBad' = (rstBad \/ \E t \in T : W4.stock[t] /\ W4.st[t] = Live)
  /\ Release("rst")
  /\ rRuns' = rRuns + 1
  /\ pc' = [pc EXCEPT !["rst"] = "idle"]
  /\ UNCHANGED <<reg, iVars, jVars, rMode, rL, rT, rHad, sVars, tdRuns, stopping, stops, restarts, lates>>

---------------------------------------------------------------------------
(* A Kit switch of C (update, install/uninstall, move to shipped Kits):   *)
(* clean, both Kit locks in key order; prepare the new Kit's VM (recovery, *)
(* name, create: any outcome; a failure leaves C where it was), move C,   *)
(* retire the old Kit's VM unless H still names that Kit.                 *)

Other(k) == IF k = "a" THEN "b" ELSE "a"

SwStart ==
  /\ Acts("sw") /\ pc["sw"] = "idle" /\ sRuns < MaxSwitches /\ reg[C] # None
  /\ sFrom' = reg[C] /\ sTo' = Other(reg[C])
  /\ sL' = IF Abba THEN <<reg[C], Other(reg[C])>> ELSE SortKits({reg[C], Other(reg[C])})
  /\ pc' = [pc EXCEPT !["sw"] = "lock"]
  /\ UNCHANGED <<world, reg, owner, iVars, jVars, rVars, sRuns, eVars>>

SwLock ==
  /\ pc["sw"] = "lock" /\ sL # <<>>
  /\ owner[Head(sL)] = None
  /\ owner' = [owner EXCEPT ![Head(sL)] = "sw"]
  /\ sL' = Tail(sL)
  /\ UNCHANGED <<world, reg, pc, iVars, jVars, rVars, sFrom, sTo, sRuns, eVars>>

SwAct ==
  /\ pc["sw"] = "lock" /\ sL = <<>>
  /\ \E ok \in BOOLEAN, o \in Outs :
       LET W1 == RecoverCur(W0, sTo, ok)
           a == AssignW(W1, sTo)
           res == Create(a.w, a.n, 0, o)
           old == LookupW(res.w, sFrom)
           retire == res.ok /\ reg[H] # sFrom /\ old # 0 /\ res.w.stock[old]
       IN /\ a.n # 0
          /\ SetW(IF retire THEN RemoveW(res.w, {old}, IF SwitchKeepsRec THEN {} ELSE Active) ELSE res.w)
          /\ reg' = IF res.ok THEN [reg EXCEPT ![C] = sTo] ELSE reg
          /\ Late(res.made)
  /\ Release("sw")
  /\ sRuns' = sRuns + 1
  /\ pc' = [pc EXCEPT !["sw"] = "idle"]
  /\ UNCHANGED <<iVars, jVars, rVars, sFrom, sTo, sL, tdRuns, stopping, stops, restarts, rstBad>>

---------------------------------------------------------------------------
(* Single-step actors and the environment.                                 *)

\* Automatic recovery (background pass), under the VM's Kit lock (its key).
\* recoveryNoLock: main takes the lock only when a command names the VM.
RecoverBg ==
  /\ Acts("rcv")
  /\ \E n \in quar :
       /\ owner[kit[n]] = None \/ (RecoveryNoLock /\ ~\E c \in Cmds : reg[c] = kit[n])
       /\ SetW(Recovery(W0, n))
  /\ UNCHANGED <<reg, owner, pc, iVars, jVars, rVars, sVars, eVars>>

\* VM garbage collection: a recorded, unquarantined VM, under its Kit lock
\* (more permissive than the code, which keeps running VMs: safety only).
Gc ==
  /\ Acts("gc")
  /\ \E n \in NameIds :
       /\ st[n] = Live /\ stock[n] /\ n \notin quar /\ owner[kit[n]] = None
       /\ SetW(RemoveW(W0, {n}, Active))
  /\ UNCHANGED <<reg, owner, pc, iVars, jVars, rVars, sVars, eVars>>

\* Remove every VM listed under a live name; intents stay (a VM that lands
\* later is adopted and owned).
TeardownW(W) ==
  LET W1 == RemoveW(W, {n \in NameIds : W.st[n] = Live /\ W.stock[n]}, Active) IN
  IF StopForgets THEN EndRecs([W1 EXCEPT !.st = [n \in NameIds |-> IF W1.st[n] = Live THEN "retired" ELSE W1.st[n]]],
                              NameIds, Active)
  ELSE W1

\* `marsh reset` (and a plain `marsh stop`): lifecycle admission
\* (`begin_lifecycle_request`) refuses while any request or background pass
\* is in flight, an install's included: only at quiescence.
Teardown ==
  /\ Acts("td") /\ tdRuns < MaxTeardowns /\ Quiescent
  /\ SetW(TeardownW(W0))
  /\ tdRuns' = tdRuns + 1
  /\ UNCHANGED <<reg, owner, pc, iVars, jVars, rVars, sVars, stopping, stops, restarts, lates, rstBad>>

\* A daemon restart's effect: every process ends and every lock is free; the
\* quarantine and uncertainty marks (in memory) are lost; the ownership map,
\* its intents and the install records (persisted) stay, a running record
\* settled; submitted stock creates go on.
RestartVars(W) ==
  /\ SetW([W EXCEPT !.quar = {}, !.unsure = [n \in NameIds |-> FALSE],
                    !.rec = [i \in Att |-> IF W.rec[i].st = "running"
                                           THEN [W.rec[i] EXCEPT !.st = IF RecordsVolatile THEN "ended" ELSE "settled"]
                                           ELSE IF RecordsVolatile /\ W.rec[i].st = "settled"
                                           THEN [W.rec[i] EXCEPT !.st = "ended"] ELSE W.rec[i]]])
  /\ owner' = [k \in Kits |-> None]
  /\ pc' = [p \in Procs |-> "idle"]
  /\ rL' = <<>> /\ sL' = <<>>

\* A crash or an upgrade handover, at any time.
Restart ==
  /\ "restart" \in Actors /\ restarts < MaxRestarts
  /\ RestartVars(W0)
  /\ restarts' = restarts + 1 /\ stopping' = FALSE
  /\ UNCHANGED <<reg, iVars, jVars, rMode, rT, rHad, rRuns, sFrom, sTo, sRuns, tdRuns, stops, lates, rstBad>>

\* `marsh stop --force`: admission closes (no new request, background pass
\* or install; plain `marsh stop`/`reset` stay refused while one runs); the
\* install's create is cancelled (InstReply), its other steps abort (InstAbort).
StopBegin ==
  /\ Acts("stop") /\ stops < MaxStops
  /\ stopping' = TRUE /\ stops' = stops + 1
  /\ UNCHANGED <<world, reg, owner, pc, iVars, jVars, rVars, sVars, tdRuns, restarts, lates, rstBad>>

\* Every request has drained: teardown, then the daemon ends (restart).
StopEnd ==
  /\ stopping /\ Quiescent
  /\ RestartVars(TeardownW(W0))
  /\ stopping' = FALSE
  /\ UNCHANGED <<reg, iVars, jVars, rMode, rT, rHad, rRuns, sFrom, sTo, sRuns, tdRuns, stops, restarts, lates, rstBad>>

\* Environment: a create that did not report lands (stock: A2, it was absent).
Land(n) ==
  /\ inflight[n]
  /\ stock' = [stock EXCEPT ![n] = TRUE]
  /\ inflight' = [inflight EXCEPT ![n] = FALSE]
  /\ unsure' = [unsure EXCEPT ![n] = FALSE]
  /\ UNCHANGED <<st, kit, mk, quar, rec, bad, reg, owner, pc, iVars, jVars, rVars, sVars, eVars>>

Next ==
  \/ InstDecideEarly \/ InstPrep \/ InstSubmit \/ InstReply \/ InstPublish \/ InstAbort
  \/ JobDecideEarly \/ JobRun \/ JobAbort
  \/ RstStart \/ RstLock \/ RstReplan \/ RstAct
  \/ SwStart \/ SwLock \/ SwAct
  \/ RecoverBg \/ Gc \/ Teardown \/ Restart \/ StopBegin \/ StopEnd
  \/ \E n \in NameIds : Land(n)

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Properties.                                                             *)

\* (a) Every removal is fenced: the map proved the VM the daemon's.
NoForeignRemoval == ~bad

\* (b1) No daemon VM is ever classified foreign: every listed VM is under a
\* live name (`marsh reset`/`stop` remove every one of them).
EveryDaemonVMOwned == \A n \in NameIds : stock[n] => st[n] = Live

\* (b2) Once quiescent, `reset NAME` targets every listed VM an install
\* attempt created, under a live name (so it removes it: ResetRemovesTargets).
EveryDaemonVMReachable ==
  Quiescent => \A n \in NameIds : (stock[n] /\ mk[n] # 0) => n \in Targets("name") /\ st[n] = Live

\* (b3) Once quiescent, `reset all` targets every listed VM (any creator).
EveryDaemonVMResettable == Quiescent => \A n \in NameIds : stock[n] => n \in Targets("all")

\* (c) A settled record never outlives the ownership entry it names.
NoOrphanRecord == Quiescent => \A i \in Att : rec[i].st = "settled" => st[rec[i].vm] = Live

\* (d) No wait-for cycle among Kit locks (a Mutex is not reentrant).
WaitFor(p) ==
  IF p = "rst" /\ pc["rst"] = "lock" /\ rL # <<>> THEN Head(rL)
  ELSE IF p = "sw" /\ pc["sw"] = "lock" /\ sL # <<>> THEN Head(sL)
  ELSE None
Nxt(p) == IF p \in Procs /\ WaitFor(p) # None /\ owner[WaitFor(p)] # None
          THEN owner[WaitFor(p)] ELSE None
NoDeadlock == \A p \in Procs : Nxt(p) # p /\ Nxt(Nxt(p)) # p /\ Nxt(Nxt(Nxt(p))) # p

\* (e1) Safety, not progress: once quiescent, neither reset would be refused
\* by a stale state (a foreign target, "recorded VM changed").
NoStaleRefusal == Quiescent => ~Refuses(Targets("name")) /\ ~Refuses(Targets("all"))

\* (e2) A reset that is not refused leaves none of its targets listed under a
\* live name.
ResetRemovesTargets == ~rstBad
=============================================================================
