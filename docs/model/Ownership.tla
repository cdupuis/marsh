---------------------------- MODULE Ownership ----------------------------
(* Stock-SBX VM ownership for one daemon (one selected home).             *)
(*                                                                         *)
(* Stock SBX is modeled as a name -> VM table that independent actors can  *)
(* change at any time (stop, remove, same-name create with a new UUID).    *)
(* The daemon keeps a persisted ownership map name -> UUID, a cached view  *)
(* refreshed by one inventory (`sbx ls`) only when the view is invalid     *)
(* (cold start, after a lifecycle change, after a failure), and a          *)
(* persisted create intent (the chosen name) written before `sbx create`.  *)
(* A later inventory adopts an intent whose name is present and never      *)
(* drops one whose name is absent: the create is not atomic (the `sbx` CLI *)
(* child outlives the daemon, as may the request inside sandboxd), so no   *)
(* timer proves it cannot land after any inventory (`CreateSubmit`, then   *)
(* `CreateLand` at any later point). The next use of the name submits      *)
(* again under it; by A2 stock refuses a create under a name whose create  *)
(* is still in progress, so no second one is in flight (`~inflight`).      *)
(*                                                                         *)
(* Assumption A1: host `sbx` is trusted; host VM names are a prefix plus  *)
(* a random id chosen by this daemon, so no other actor creates a VM under *)
(* such a name (no EnvCreate on HostNames). Stock operations may therefore *)
(* be name-addressed.                                                      *)
(* Assumption A2: stock create is atomic on name uniqueness.               *)
(* Assumption A3: inventory is accurate at observation time.               *)
EXTENDS Naturals

CONSTANTS HostNames,   \* names the host daemon owns (shell VM, kit VMs)
          MaxU,        \* bound on UUIDs ever allocated (finite model)
          Bug

Bugs == {"none", "noIntent", "nameReuse", "dropAbsent"}
ASSUME Bug \in Bugs

Names == HostNames
UU == 1..MaxU
NoVM == [u |-> 0, run |-> FALSE]
Intents == {"none", "want", "sent"}

VARIABLES
  stock,     \* [Names -> VM record]  stock SBX truth (u = 0: absent)
  nextU,     \* next fresh UUID
  maker,     \* ghost: [UU -> creator] "none" | "host" | "ext"
  own,       \* host persisted ownership map name -> UUID (0 = none)
  intent,    \* host persisted create intent
  inflight,  \* ghost: an `sbx create` was submitted and has not landed yet
  view,      \* cached inventory
  viewOk,    \* cached inventory valid?
  hostBad    \* ghost: host affected a VM it does not own

vars == <<stock, nextU, maker, own, intent, inflight, view, viewOk, hostBad>>

TypeOK ==
  /\ stock \in [Names -> [u : 0..MaxU, run : BOOLEAN]]
  /\ nextU \in 1..(MaxU + 1)
  /\ own \in [Names -> 0..MaxU]
  /\ intent \in [Names -> Intents]
  /\ inflight \in [Names -> BOOLEAN]
  /\ viewOk \in BOOLEAN

Init ==
  /\ stock = [n \in Names |-> NoVM]
  /\ nextU = 1
  /\ maker = [u \in UU |-> "none"]
  /\ own = [n \in Names |-> 0]
  /\ intent = [n \in Names |-> "none"]
  /\ inflight = [n \in Names |-> FALSE]
  /\ view = [n \in Names |-> NoVM]
  /\ viewOk = FALSE
  /\ hostBad = FALSE

\* Stock operations are name-addressed for every owned name (A1) ...
CondOk(n, u) == u # 0 /\ stock[n].u # 0
\* ... and land on whatever VM holds the name.
Landed(n) == stock[n].u

HostEffect(n) == hostBad' = (hostBad \/ maker[Landed(n)] # "host")

---------------------------------------------------------------------------
(* Environment: stock SBX and other clients.                               *)

EnvStop(n) ==
  /\ stock[n].u # 0 /\ stock[n].run
  /\ stock' = [stock EXCEPT ![n].run = FALSE]
  /\ UNCHANGED <<nextU, maker, own, intent, inflight, view, viewOk, hostBad>>

EnvRemove(n) ==
  /\ stock[n].u # 0
  /\ stock' = [stock EXCEPT ![n] = NoVM]
  /\ UNCHANGED <<nextU, maker, own, intent, inflight, view, viewOk, hostBad>>

EnvCreate(n) ==
  \* A1: random daemon-chosen names. Bug "nameReuse" drops A1.
  /\ n \notin HostNames \/ Bug = "nameReuse"
  /\ stock[n].u = 0 /\ nextU <= MaxU
  /\ stock' = [stock EXCEPT ![n] = [u |-> nextU, run |-> TRUE]]
  /\ maker' = [maker EXCEPT ![nextU] = "ext"]
  /\ nextU' = nextU + 1
  /\ UNCHANGED <<own, intent, inflight, view, viewOk, hostBad>>

---------------------------------------------------------------------------
(* Host daemon.                                                            *)

Inventory ==
  /\ ~viewOk
  /\ view' = stock /\ viewOk' = TRUE
  /\ UNCHANGED <<stock, nextU, maker, own, intent, inflight, hostBad>>

\* Use a running target VM (open worker transport / exec / mount).
Use(n) ==
  LET t == own[n] IN
  /\ n \in HostNames /\ viewOk
  /\ t # 0 /\ view[n].u = t /\ view[n].run
  /\ IF stock[n].run /\ CondOk(n, t)
       THEN /\ HostEffect(n) /\ UNCHANGED viewOk
       ELSE /\ viewOk' = FALSE /\ UNCHANGED hostBad   \* failure -> re-inventory
  /\ UNCHANGED <<stock, nextU, maker, own, intent, inflight, view>>

StartVM(n) ==
  /\ n \in HostNames /\ viewOk
  /\ own[n] # 0 /\ view[n].u = own[n] /\ ~view[n].run
  /\ IF CondOk(n, own[n])
       THEN /\ stock' = [stock EXCEPT ![n].run = TRUE] /\ HostEffect(n)
       ELSE UNCHANGED <<stock, hostBad>>
  /\ viewOk' = FALSE
  /\ UNCHANGED <<nextU, maker, own, intent, inflight, view>>

\* Absent name: persist intent (chosen random name) before creating.
CreateBegin(n) ==
  /\ n \in HostNames /\ viewOk /\ view[n].u = 0 /\ intent[n] \in {"none", "sent"} /\ ~inflight[n]
  /\ intent' = [intent EXCEPT ![n] = "want"]
  /\ own' = [own EXCEPT ![n] = 0]
  /\ UNCHANGED <<stock, nextU, maker, inflight, view, viewOk, hostBad>>

\* `sbx create` is submitted: the CLI child runs on its own (it outlives a
\* daemon restart) and lands whenever stock gets to it.
CreateSubmit(n) ==
  /\ n \in HostNames /\ intent[n] = "want"
  /\ intent' = [intent EXCEPT ![n] = "sent"]
  /\ inflight' = [inflight EXCEPT ![n] = TRUE]
  /\ viewOk' = FALSE
  /\ UNCHANGED <<stock, nextU, maker, own, view, hostBad>>

\* The submitted create takes effect, at any later point, also after a
\* restart. The next inventory adopts the intent by its random name.
CreateLand(n) ==
  /\ n \in HostNames /\ inflight[n] /\ nextU <= MaxU
  /\ IF stock[n].u = 0
       THEN /\ stock' = [stock EXCEPT ![n] = [u |-> nextU, run |-> TRUE]]
            /\ maker' = [maker EXCEPT ![nextU] = "host"]
            /\ nextU' = nextU + 1
       ELSE UNCHANGED <<stock, maker, nextU>>
  /\ inflight' = [inflight EXCEPT ![n] = FALSE]
  /\ viewOk' = FALSE
  /\ UNCHANGED <<own, intent, view, hostBad>>

Record(n) ==
  /\ n \in HostNames /\ intent[n] = "sent" /\ viewOk
  /\ IF view[n].u # 0
       THEN /\ own' = [own EXCEPT ![n] = view[n].u]  \* adopt by our random name
            /\ intent' = [intent EXCEPT ![n] = "none"]
       ELSE /\ UNCHANGED own
            \* Absent: the intent stays, whatever the time. Bug "dropAbsent"
            \* drops it, as a startup timer once did.
            /\ IF Bug = "dropAbsent"
                 THEN intent' = [intent EXCEPT ![n] = "none"]
                 ELSE UNCHANGED intent
  /\ UNCHANGED <<stock, nextU, maker, inflight, view, viewOk, hostBad>>

\* Daemon restart: the cached view is lost; the persisted map and intents
\* are kept. Bug "noIntent" keeps intents only in memory.
Restart ==
  /\ viewOk' = FALSE
  /\ intent' = IF Bug = "noIntent" THEN [n \in Names |-> "none"] ELSE intent
  /\ UNCHANGED <<stock, nextU, maker, own, inflight, view, hostBad>>

\* Stop/remove an owned VM by its recorded UUID (incl. operator Retire).
Remove(n) ==
  LET t == own[n] IN
  /\ n \in HostNames /\ viewOk /\ t # 0 /\ view[n].u = t
  /\ IF CondOk(n, t)
       THEN /\ stock' = [stock EXCEPT ![n] = NoVM] /\ HostEffect(n)
       ELSE UNCHANGED <<stock, hostBad>>
  /\ own' = [own EXCEPT ![n] = 0]
  /\ viewOk' = FALSE
  /\ UNCHANGED <<nextU, maker, intent, inflight, view>>

---------------------------------------------------------------------------
Next ==
  \/ \E n \in Names : EnvStop(n) \/ EnvRemove(n) \/ EnvCreate(n)
  \/ Inventory \/ Restart
  \/ \E n \in Names : Use(n) \/ StartVM(n) \/ CreateBegin(n) \/ CreateSubmit(n) \/ CreateLand(n)
                      \/ Record(n) \/ Remove(n)

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Inventory)

---------------------------------------------------------------------------
(* Safety *)
NoForeignEffect   == ~hostBad
OwnedAreOurs      == \A n \in Names : own[n] # 0 => maker[own[n]] = "host"
\* No created-but-unowned leak: every host-made VM is recorded or intended.
NoLeak            == \A n \in HostNames :
                       (stock[n].u # 0 /\ maker[stock[n].u] = "host")
                         => (own[n] = stock[n].u \/ intent[n] # "none")
=============================================================================
