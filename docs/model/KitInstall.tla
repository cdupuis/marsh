---------------------------- MODULE KitInstall ----------------------------
(* The VM of a `marsh kit install` that failed (issue #194), and the per-  *)
(* Kit lifecycle locks, install records and ownership map that keep it     *)
(* reachable by `marsh workers reset NAME|all` without ever removing a VM  *)
(* the daemon cannot prove is its own. A DESIGN model: it fixes the        *)
(* protocol the code must follow (docs/model/README.md, "Kit install").    *)
(*                                                                         *)
(* Stock SBX is a name -> VM table (A1: names are random and the daemon's, *)
(* A2: a create is atomic on name uniqueness). A create is submitted and   *)
(* returns ok, fails with a VM left behind, fails with none, or times out; *)
(* a timed-out create may land at any later time (Land) or never. The      *)
(* ownership map gives each name a state: free (never assigned), live (an  *)
(* intent or a recorded VM: the daemon's) or retired (forgotten after its  *)
(* VM was removed: not the daemon's any more). A VM listed under a live    *)
(* name is the daemon's (an intent is adopted at the next listing); one    *)
(* under a retired name is classified foreign and is never removed.        *)
(* `kit` is the Kit identity a name was assigned for (kept when retired:   *)
(* the key of its lock). Records are per install attempt.                  *)
(*                                                                         *)
(* Processes: one install process (installs serialize on registry_install; *)
(* one attempt after another, each a new attempt id), a job preparing the  *)
(* registered command C's Kit VM, `workers reset NAME` (H) or `all`, a Kit *)
(* switch of C to the other Kit, and three single-step actors: automatic   *)
(* recovery of a quarantined VM, VM garbage collection (both under the     *)
(* VM's Kit lock), and scope teardown (`marsh reset`/`stop`, which takes  *)
(* no Kit lock but runs only when nothing else does: lifecycle admission). *)
(* A process that holds at most one lock and waits for none takes, uses    *)
(* and releases it in one step; only reset and the switch, which take two, *)
(* have a waiting state, so TLC sees every wait-for cycle (NoDeadlock).    *)
(* No daemon restart: records and quarantines are in memory (README gap).  *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS NN,            \* number of VM names (1..NN)
          MaxAttempts,   \* install attempts of H
          MaxJobs, MaxResets, MaxSwitches, MaxTeardowns,
          MaxLate,       \* creates that may time out (and land later)
          InstallKits,   \* the Kits an attempt may install H from
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
         "switchAbba", "removeUnowned", "recoveryNoLock", "failedCreateKeepsRecord"}
ASSUME Bug \in Bugs /\ InstallKits \subseteq Kits

(* Each control is the deviation of the code that a review found, set    *)
(* against the clean design; a control that needs two deviations names   *)
(* both (README "Kit install").                                           *)
EarlyDecide    == Bug \in {"resetAllSnapshotRace"}                  \* install decides and records before its Kit lock
ResetSnapshot  == Bug \in {"oldAttemptErasesNew", "resetAllSnapshotRace"} \* reset plans before its locks
ForgetByName   == Bug = "oldAttemptErasesNew"                       \* reset ends every record of the command
EndAlways      == Bug = "lateLandingLost"                            \* reset ends a record although the create may still land
KeepOnRecovery == Bug \in {"recoveryKeepsRecord", "lockPerVm"}       \* recovery removes the VM, keeps its records
StaleCheck     == Bug = "recoveryKeepsRecord"                        \* reset refuses "recorded VM changed"
NameBeforeRec  == Bug \in {"nameBeforeRecovery", "removeUnowned"}    \* install decides before its own recovery
NoRevalidate   == Bug \in {"resetAllSnapshotRace", "nameBeforeRecovery", "jobPathStaleName", "removeUnowned",
                          "recoveryNoLock"}                          \* create under the decided name unchecked
KeepFailed     == Bug = "failedCreateKeepsRecord"                    \* a create over with no VM keeps intent and record
RecoveryNoLock == Bug = "recoveryNoLock"                             \* background recovery of an unnamed VM takes no Kit lock
PerVmLocks     == Bug = "lockPerVm"                                  \* reset takes one lock per target VM
JobEarly       == Bug = "jobPathStaleName"                           \* job decides its name before lock and recovery
Abba           == Bug = "switchAbba"                                 \* switch holds the old Kit lock, then takes the new
RemoveUnowned  == Bug = "removeUnowned"                              \* reset removes a recorded VM the map does not own

VARIABLES
  st,        \* [NameIds -> "free" | "live" | "retired"] ownership map
  kit,       \* [NameIds -> Kits \cup {None}] the Kit a name was assigned for
  stock,     \* [NameIds -> BOOLEAN] stock lists a VM under the name
  inflight,  \* [NameIds -> BOOLEAN] ghost: a submitted create has not landed (may never)
  mk,        \* [NameIds -> 0..MaxAttempts] ghost: the install attempt that created it (0: job/switch)
  unsure,    \* [NameIds -> BOOLEAN] a create under the name returned with no verdict, nothing seen since
  quar,      \* quarantined names (in memory)
  rec,       \* [Att -> [st : "none"|"running"|"settled"|"ended", vm : 0..NN]] install records
  reg,       \* [Cmds -> Kits \cup {None}] registered commands
  owner,     \* [Kits -> Procs \cup {None}] Kit lock holder
  pc,        \* [Procs -> step]
  iAtt, iK, iN,          \* install: current attempt, its Kit, its decided name
  jK, jN, jRuns,         \* job (jobPathStaleName: decided before the lock)
  rMode, rL, rT, rRuns,  \* reset: mode, locks still to take, snapshot targets
  sFrom, sTo, sL, sRuns, \* switch
  tdRuns, lates,
  bad        \* ghost: a VM was removed although the map did not prove it the daemon's

vars == <<st, kit, stock, inflight, mk, unsure, quar, rec, reg, owner, pc, iAtt, iK, iN,
          jK, jN, jRuns, rMode, rL, rT, rRuns, sFrom, sTo, sL, sRuns, tdRuns, lates, bad>>
world == <<st, kit, stock, inflight, mk, unsure, quar, rec, bad>>
locals == <<iAtt, iK, iN, jK, jN, jRuns, rMode, rL, rT, rRuns, sFrom, sTo, sL, sRuns, tdRuns>>

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
  /\ bad \in BOOLEAN

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
  /\ rMode = "all" /\ rL = <<>> /\ rT = {} /\ rRuns = 0
  /\ sFrom = "a" /\ sTo = "a" /\ sL = <<>> /\ sRuns = 0
  /\ tdRuns = 0 /\ lates = 0 /\ bad = FALSE

---------------------------------------------------------------------------
(* The daemon's state as a record, so that one step can compose effects.  *)
W0 == [st |-> st, kit |-> kit, stock |-> stock, inflight |-> inflight, mk |-> mk,
       unsure |-> unsure, quar |-> quar, rec |-> rec, bad |-> bad]
SetW(W) == /\ st' = W.st /\ kit' = W.kit /\ stock' = W.stock /\ inflight' = W.inflight
           /\ mk' = W.mk /\ unsure' = W.unsure /\ quar' = W.quar /\ rec' = W.rec
           /\ bad' = W.bad

Min(S) == CHOOSE x \in S : \A y \in S : x <= y
SortKits(S) == SelectSeq(KitOrder, LAMBDA k : k \in S)

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

\* Fenced removal of the VMs of S (`remove_owned_vm`): gone, the names
\* retired, their quarantines and the records naming them (in `states`) end.
RemoveW(W, S, states) ==
  EndRecs([W EXCEPT !.stock = [n \in NameIds |-> IF n \in S THEN FALSE ELSE W.stock[n]],
                    !.st = [n \in NameIds |-> IF n \in S THEN "retired" ELSE W.st[n]],
                    !.quar = W.quar \ S,
                    !.bad = W.bad \/ (\E n \in S : W.st[n] # Live)], S, states)

\* Recovery of a quarantined name: its VM removed if listed under a live
\* name (one under a retired name is foreign: refused, the quarantine stays);
\* an absent intent is kept (its create may still land) with its records;
\* the quarantine ends.
Recovery(W, n) ==
  IF W.stock[n] /\ W.st[n] = Live THEN RemoveW(W, {n}, IF KeepOnRecovery THEN {} ELSE Active)
  ELSE IF W.stock[n] THEN W
  ELSE [W EXCEPT !.quar = W.quar \ {n}]

\* Inside a preparation: the Kit's current VM, if quarantined, is recovered
\* when that is verifiably safe (ok).
RecoverCur(W, k, ok) ==
  LET cur == LookupW(W, k) IN
  IF ok /\ cur # 0 /\ cur \in W.quar THEN Recovery(W, cur) ELSE W

\* One `sbx create` under n by `who` with outcome o, after a fresh listing.
\* A listed VM is reused (the daemon's and not quarantined) or refused; a
\* create still in flight makes stock refuse this one (A2). A create stock
\* reported failed, with nothing listed afterwards, is over: its intent and
\* records end (unless an earlier create under the name may still land).
Create(W, n, who, o) ==
  IF W.stock[n] THEN [w |-> W, ok |-> W.st[n] = Live /\ n \notin W.quar, made |-> FALSE]
  ELSE IF W.inflight[n] THEN [w |-> [W EXCEPT !.quar = W.quar \cup {n}], ok |-> FALSE, made |-> FALSE]
  ELSE CASE o = "ok" ->
              \* `adopt_created` -> `record` takes back even a just-retired name.
              [w |-> [W EXCEPT !.stock[n] = TRUE, !.mk[n] = who, !.st[n] = Live],
               ok |-> TRUE, made |-> TRUE]
         [] o = "failVm" ->
              [w |-> [W EXCEPT !.stock[n] = TRUE, !.mk[n] = who, !.quar = W.quar \cup {n}],
               ok |-> FALSE, made |-> TRUE]
         [] o = "failNoVm" ->
              [w |-> IF W.st[n] = Live /\ ~W.unsure[n] /\ ~KeepFailed
                     THEN EndRecs([W EXCEPT !.st[n] = "retired", !.quar = W.quar \ {n}], {n}, Active)
                     ELSE W,
               ok |-> FALSE, made |-> FALSE]
         [] o = "timeout" ->
              [w |-> [W EXCEPT !.inflight[n] = TRUE, !.mk[n] = who, !.unsure[n] = TRUE,
                               !.quar = W.quar \cup {n}],
               ok |-> FALSE, made |-> TRUE]

Outs == IF lates < MaxLate THEN {"ok", "failVm", "failNoVm", "timeout"} ELSE {"ok", "failVm", "failNoVm"}
Late(o, res) == lates' = lates + (IF o = "timeout" /\ res.made THEN 1 ELSE 0)

Quiescent == \A p \in Procs : pc[p] = "idle"
Held(p) == {k \in Kits : owner[k] = p}
Release(p) == owner' = [k \in Kits |-> IF owner[k] = p THEN None ELSE owner[k]]

---------------------------------------------------------------------------
(* `marsh kit install H REF`. Clean: Kit lock first; under it recovery,   *)
(* then the name, then the record (attempt id, name), then the create,    *)
(* which re-validates the name (still a live intent of this Kit, else it  *)
(* decides again and re-points its record); success registers H and ends *)
(* the record; a failure settles it.                                       *)

\* resetAllSnapshotRace (round 2): recovery (which takes the Kit lock for
\* itself), the name and the record before the install's own Kit lock.
InstDecideEarly ==
  /\ EarlyDecide /\ pc["inst"] = "idle" /\ iAtt < MaxAttempts /\ reg[H] = None
  /\ \E k \in InstallKits, ok \in BOOLEAN :
       LET a == AssignW(RecoverCur(W0, k, ok), k) IN
       /\ owner[k] = None /\ a.n # 0
       /\ SetW([a.w EXCEPT !.rec[iAtt + 1] = [st |-> "running", vm |-> a.n]])
       /\ iK' = k /\ iN' = a.n
  /\ iAtt' = iAtt + 1
  /\ pc' = [pc EXCEPT !["inst"] = "wait"]
  /\ UNCHANGED <<reg, owner, jK, jN, jRuns, rMode, rL, rT, rRuns, sFrom, sTo, sL, sRuns, tdRuns, lates>>

InstPrep ==
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
  /\ UNCHANGED <<reg, jK, jN, jRuns, rMode, rL, rT, rRuns, sFrom, sTo, sL, sRuns, tdRuns, lates>>

InstCreate ==
  /\ pc["inst"] = "create"
  /\ \E o \in Outs :
       LET i == iAtt
           k == iK
           stale == ~(st[iN] = Live /\ kit[iN] = k)
           redo == stale /\ ~NoRevalidate
           a == IF redo THEN AssignW(W0, k) ELSE [n |-> iN, w |-> W0]
           n == a.n
           Wr == IF redo THEN [a.w EXCEPT !.rec[i] = [st |-> "running", vm |-> n]] ELSE a.w
           res == Create(Wr, n, i, o)
           W3 == IF res.ok THEN [res.w EXCEPT !.rec[i].st = "ended"]
                 ELSE IF res.w.rec[i].st = "running" THEN [res.w EXCEPT !.rec[i].st = "settled"]
                 ELSE res.w
       IN /\ n # 0
          /\ SetW(W3)
          /\ reg' = IF res.ok THEN [reg EXCEPT ![H] = k] ELSE reg
          /\ Late(o, res)
  /\ Release("inst")
  /\ pc' = [pc EXCEPT !["inst"] = "idle"]
  /\ UNCHANGED locals

---------------------------------------------------------------------------
(* A job of the registered command C prepares its Kit's VM (the job path: *)
(* `prepare_one_unnoted`): one step under the Kit lock, as the install's. *)

JobDecideEarly ==    \* jobPathStaleName: the name before the lock and the recovery
  /\ JobEarly /\ pc["job"] = "idle" /\ jRuns < MaxJobs /\ reg[C] # None
  /\ LET a == AssignW(W0, reg[C]) IN
       /\ a.n # 0 /\ SetW(a.w) /\ jK' = reg[C] /\ jN' = a.n
  /\ jRuns' = jRuns + 1
  /\ pc' = [pc EXCEPT !["job"] = "wait"]
  /\ UNCHANGED <<reg, owner, iAtt, iK, iN, rMode, rL, rT, rRuns, sFrom, sTo, sL, sRuns, tdRuns, lates>>

JobRun ==
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
          IN /\ n0 # 0 /\ a.n # 0 /\ SetW(res.w) /\ Late(o, res)
  /\ jRuns' = IF JobEarly THEN jRuns ELSE jRuns + 1
  /\ pc' = [pc EXCEPT !["job"] = "idle"]
  /\ UNCHANGED <<reg, owner, iAtt, iK, iN, jK, jN, rMode, rL, rT, rRuns, sFrom, sTo, sL, sRuns, tdRuns>>

---------------------------------------------------------------------------
(* `marsh workers reset NAME|all`. Clean: from the state, the Kits it may *)
(* touch (no name decided); their locks in key order; then, under them,   *)
(* the plan, started over if it needs a lock not taken. `all` targets     *)
(* every live name of the map and the VMs records name; NAME (H) the VM   *)
(* its registered Kit has and the VMs its settled records name. Each      *)
(* target is retired through the fence: a listed VM under a live name is  *)
(* removed and its name retired; an absent intent is kept (its create may *)
(* still land; the record stays its handle); a listed VM under a retired  *)
(* name is foreign and refuses the reset. A record ends with its name.    *)

RecVMs == {rec[i].vm : i \in {j \in Att : rec[j].st = "settled"}}
RunVMs == {rec[i].vm : i \in {j \in Att : rec[j].st = "running"}}
Targets(m) ==
  IF m = "all" THEN {n \in NameIds : st[n] = Live} \cup RecVMs
  ELSE RecVMs \cup (IF reg[H] # None /\ LookupW(W0, reg[H]) # 0 THEN {LookupW(W0, reg[H])} ELSE {})
NeedKits(m) ==
  {kit[t] : t \in Targets(m) \cup RunVMs}
    \cup (IF m = "all" THEN {reg[c] : c \in {d \in Cmds : reg[d] # None}}
          ELSE IF reg[H] # None THEN {reg[H]} ELSE {})
\* One lock per target VM, in name order (lockPerVm).
PerVm(T) == LET s == SelectSeq(NameSeq, LAMBDA n : n \in T) IN [j \in 1..Len(s) |-> kit[s[j]]]

\* Why a reset with these targets is refused (independent of a running install).
Refuses(T) ==
  \/ \E t \in T : stock[t] /\ st[t] # Live /\ ~RemoveUnowned
  \/ StaleCheck /\ \E i \in Att : rec[i].st = "settled" /\ rec[i].vm # LookupW(W0, kit[rec[i].vm])

RstStart ==
  /\ pc["rst"] = "idle" /\ rRuns < MaxResets
  /\ \E m \in {"name", "all"} :
       LET T == IF ResetSnapshot /\ m = "all" THEN Targets(m) \ RunVMs ELSE Targets(m) IN
       /\ ~(ResetSnapshot /\ m = "name" /\ RunVMs # {})   \* refused "still running" at the snapshot
       /\ rMode' = m /\ rT' = T
       /\ rL' = IF PerVmLocks THEN PerVm(T) ELSE SortKits(NeedKits(m))
  /\ pc' = [pc EXCEPT !["rst"] = "lock"]
  /\ UNCHANGED <<world, reg, owner, iAtt, iK, iN, jK, jN, jRuns, rRuns, sFrom, sTo, sL, sRuns, tdRuns, lates>>

RstLock ==
  /\ pc["rst"] = "lock" /\ rL # <<>>
  /\ owner[Head(rL)] = None          \* a Mutex is not reentrant: held by rst itself, it waits forever
  /\ owner' = [owner EXCEPT ![Head(rL)] = "rst"]
  /\ rL' = Tail(rL)
  /\ UNCHANGED <<world, reg, pc, iAtt, iK, iN, jK, jN, jRuns, rMode, rT, rRuns, sFrom, sTo, sL, sRuns, tdRuns, lates>>

RstReplan ==
  /\ pc["rst"] = "lock" /\ rL = <<>>
  /\ ~ResetSnapshot /\ ~PerVmLocks
  /\ ~(NeedKits(rMode) \subseteq Held("rst"))
  /\ Release("rst")
  /\ rL' = SortKits(NeedKits(rMode))
  /\ UNCHANGED <<world, reg, pc, iAtt, iK, iN, jK, jN, jRuns, rMode, rT, rRuns, sFrom, sTo, sL, sRuns, tdRuns, lates>>

RstAct ==
  /\ pc["rst"] = "lock" /\ rL = <<>>
  /\ ResetSnapshot \/ PerVmLocks \/ NeedKits(rMode) \subseteq Held("rst")
  /\ LET T0 == IF ResetSnapshot \/ PerVmLocks THEN rT ELSE Targets(rMode)
         busy == ~ResetSnapshot /\ rMode = "name" /\ RunVMs # {}
         T == IF rMode = "all" /\ ~ResetSnapshot THEN T0 \ RunVMs ELSE T0
         Rm == {t \in T : stock[t] /\ (st[t] = Live \/ RemoveUnowned)}
         W1 == RemoveW(W0, Rm, {"settled"})
         W2 == [W1 EXCEPT !.quar = W1.quar \ T]
         Gone == {t \in T : W2.st[t] # Live}
         W3 == IF ForgetByName THEN [W2 EXCEPT !.rec = [i \in Att |-> IF W2.rec[i].st \in Active
                                                       THEN [W2.rec[i] EXCEPT !.st = "ended"] ELSE W2.rec[i]]]
               ELSE IF EndAlways THEN EndRecs(W2, T, {"settled"})
               ELSE EndRecs(W2, Gone, {"settled"})
     IN IF busy \/ Refuses(T) THEN UNCHANGED world ELSE SetW(W3)
  /\ Release("rst")
  /\ rRuns' = rRuns + 1
  /\ pc' = [pc EXCEPT !["rst"] = "idle"]
  /\ UNCHANGED <<reg, iAtt, iK, iN, jK, jN, jRuns, rMode, rL, rT, sFrom, sTo, sL, sRuns, tdRuns, lates>>

---------------------------------------------------------------------------
(* A Kit switch of C (update, install/uninstall, move to shipped Kits):   *)
(* clean, both Kit locks in key order; prepare the new Kit's VM (recovery, *)
(* name, create), move C, retire the old Kit's VM unless H still names it. *)

Other(k) == IF k = "a" THEN "b" ELSE "a"

SwStart ==
  /\ pc["sw"] = "idle" /\ sRuns < MaxSwitches /\ reg[C] # None
  /\ sFrom' = reg[C] /\ sTo' = Other(reg[C])
  /\ sL' = IF Abba THEN <<reg[C], Other(reg[C])>> ELSE SortKits({reg[C], Other(reg[C])})
  /\ pc' = [pc EXCEPT !["sw"] = "lock"]
  /\ UNCHANGED <<world, reg, owner, iAtt, iK, iN, jK, jN, jRuns, rMode, rL, rT, rRuns, sRuns, tdRuns, lates>>

SwLock ==
  /\ pc["sw"] = "lock" /\ sL # <<>>
  /\ owner[Head(sL)] = None
  /\ owner' = [owner EXCEPT ![Head(sL)] = "sw"]
  /\ sL' = Tail(sL)
  /\ UNCHANGED <<world, reg, pc, iAtt, iK, iN, jK, jN, jRuns, rMode, rL, rT, rRuns, sFrom, sTo, sRuns, tdRuns, lates>>

SwAct ==
  /\ pc["sw"] = "lock" /\ sL = <<>>
  /\ \E ok \in BOOLEAN :
       LET W1 == RecoverCur(W0, sTo, ok)
           a == AssignW(W1, sTo)
           res == Create(a.w, a.n, 0, "ok")
           old == LookupW(res.w, sFrom)
           retire == res.ok /\ reg[H] # sFrom /\ old # 0 /\ res.w.stock[old]
       IN /\ a.n # 0
          /\ SetW(IF retire THEN RemoveW(res.w, {old}, Active) ELSE res.w)
          /\ reg' = IF res.ok THEN [reg EXCEPT ![C] = sTo] ELSE reg
  /\ Release("sw")
  /\ sRuns' = sRuns + 1
  /\ pc' = [pc EXCEPT !["sw"] = "idle"]
  /\ UNCHANGED <<iAtt, iK, iN, jK, jN, jRuns, rMode, rL, rT, rRuns, sFrom, sTo, sL, tdRuns, lates>>

---------------------------------------------------------------------------
(* Single-step actors.                                                     *)

\* Automatic recovery (background pass), under the VM's Kit lock (its key).
\* recoveryNoLock: main takes the lock only when a command names the VM.
RecoverBg ==
  /\ \E n \in quar :
       /\ owner[kit[n]] = None \/ (RecoveryNoLock /\ ~\E c \in Cmds : reg[c] = kit[n])
       /\ SetW(Recovery(W0, n))
  /\ UNCHANGED <<reg, owner, pc, locals, lates>>

\* VM garbage collection: a recorded, unquarantined VM, under its Kit lock.
Gc ==
  /\ \E n \in NameIds :
       /\ st[n] = Live /\ stock[n] /\ n \notin quar /\ owner[kit[n]] = None
       /\ SetW(RemoveW(W0, {n}, Active))
  /\ UNCHANGED <<reg, owner, pc, locals, lates>>

\* `marsh reset` / `marsh stop`: every recorded Kit VM; intents stay (a late
\* VM is adopted). Lifecycle admission (`begin_lifecycle_request`) refuses
\* while any request or background pass is in flight: only at quiescence.
Teardown ==
  /\ tdRuns < MaxTeardowns /\ Quiescent
  /\ SetW(RemoveW(W0, {n \in NameIds : st[n] = Live /\ stock[n]}, Active))
  /\ tdRuns' = tdRuns + 1
  /\ UNCHANGED <<reg, owner, pc, iAtt, iK, iN, jK, jN, jRuns, rMode, rL, rT, rRuns,
                 sFrom, sTo, sL, sRuns, lates>>

\* Environment: a create that did not report lands (stock: A2, it was absent).
Land(n) ==
  /\ inflight[n]
  /\ stock' = [stock EXCEPT ![n] = TRUE]
  /\ inflight' = [inflight EXCEPT ![n] = FALSE]
  /\ unsure' = [unsure EXCEPT ![n] = FALSE]
  /\ UNCHANGED <<st, kit, mk, quar, rec, bad, reg, owner, pc, locals, lates>>

Next ==
  \/ InstDecideEarly \/ InstPrep \/ InstCreate
  \/ JobDecideEarly \/ JobRun
  \/ RstStart \/ RstLock \/ RstReplan \/ RstAct
  \/ SwStart \/ SwLock \/ SwAct
  \/ RecoverBg \/ Gc \/ Teardown
  \/ \E n \in NameIds : Land(n)

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Properties.                                                             *)

\* (a) Every removal is fenced: the map proved the VM the daemon's.
NoForeignRemoval == ~bad

\* (b1) No daemon VM is ever classified foreign: every listed VM is under a
\* live name, so `reset all`, `marsh reset` and GC can remove it.
EveryDaemonVMOwned == \A n \in NameIds : stock[n] => st[n] = Live

\* (b2) Once quiescent, a listed VM an install attempt created is reachable
\* by the install's name: a settled record names it, or H is registered and
\* it is H's Kit VM.
EveryDaemonVMReachable ==
  Quiescent =>
    \A n \in NameIds :
      (stock[n] /\ mk[n] # 0) =>
        \/ \E i \in Att : rec[i].st = "settled" /\ rec[i].vm = n
        \/ reg[H] # None /\ LookupW(W0, reg[H]) = n

\* (c) No settled record outlives its VM: it names a live name whose VM is
\* listed, or whose create returned without a verdict and may still land.
NoOrphanRecord ==
  Quiescent =>
    \A i \in Att : rec[i].st = "settled" =>
      /\ st[rec[i].vm] = Live
      /\ stock[rec[i].vm] \/ unsure[rec[i].vm]

\* (d) No wait-for cycle among Kit locks (a Mutex is not reentrant).
WaitFor(p) ==
  IF p = "rst" /\ pc["rst"] = "lock" /\ rL # <<>> THEN Head(rL)
  ELSE IF p = "sw" /\ pc["sw"] = "lock" /\ sL # <<>> THEN Head(sL)
  ELSE None
Nxt(p) == IF p \in Procs /\ WaitFor(p) # None /\ owner[WaitFor(p)] # None
          THEN owner[WaitFor(p)] ELSE None
NoDeadlock == \A p \in Procs : Nxt(p) # p /\ Nxt(Nxt(p)) # p /\ Nxt(Nxt(Nxt(p))) # p

\* (e) Once quiescent, neither reset is refused: one then removes every VM it
\* targets (fenced removal of each listed target under a live name).
ResetNeverStuck == Quiescent => ~Refuses(Targets("name")) /\ ~Refuses(Targets("all"))
=============================================================================
