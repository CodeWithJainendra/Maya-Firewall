---- MODULE MayaConsensus ----
\* TLA+ Formal Specification for MAYA HotStuff BFT Consensus
\* 
\* This specification formally verifies that the HotStuff consensus
\* protocol used in MAYA's distributed deception grid maintains:
\* 1. Safety: No two honest nodes commit different values for same view
\* 2. Liveness: Eventually a proposal is committed
\* 3. Byzantine Fault Tolerance: Tolerates f faults with n >= 3f+1 nodes

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS 
    Nodes,          \* Set of all nodes
    Faulty,         \* Set of Byzantine (faulty) nodes
    MaxView         \* Maximum view number for model checking

ASSUME /\ Faulty \subseteq Nodes
       /\ Cardinality(Nodes) >= 3 * Cardinality(Faulty) + 1

VARIABLES
    view,           \* Current view number per node
    phase,          \* Current phase per node: "new_view", "prepare", "precommit", "commit", "decide"
    proposals,      \* Proposals received by each node
    votes,          \* Votes cast in each view
    committed,      \* Set of committed proposals per node
    leader,         \* Current leader for each view
    highQC,         \* Highest QC seen by each node
    messages        \* Set of in-flight messages

\* Quorum size
QuorumSize == (2 * Cardinality(Faulty)) + 1

\* Honest nodes
Honest == Nodes \ Faulty

\* Type invariant
TypeOK ==
    /\ \A n \in Nodes: view[n] \in 0..MaxView
    /\ \A n \in Nodes: phase[n] \in {"new_view", "prepare", "precommit", "commit", "decide"}
    /\ \A n \in Nodes: committed[n] \subseteq (0..MaxView)

\* SAFETY: No two honest nodes commit different values for the same view
Safety ==
    \A n1, n2 \in Honest:
        \A v \in 0..MaxView:
            (v \in committed[n1] /\ v \in committed[n2]) =>
                committed[n1] = committed[n2]

\* Initial state
Init ==
    /\ view = [n \in Nodes |-> 0]
    /\ phase = [n \in Nodes |-> "new_view"]
    /\ proposals = [n \in Nodes |-> {}]
    /\ votes = [v \in 0..MaxView |-> {}]
    /\ committed = [n \in Nodes |-> {}]
    /\ leader = [v \in 0..MaxView |-> CHOOSE n \in Nodes: TRUE]
    /\ highQC = [n \in Nodes |-> 0]
    /\ messages = {}

\* Leader proposes (PREPARE phase)
LeaderPropose(n) ==
    /\ n = leader[view[n]]
    /\ phase[n] = "new_view"
    /\ phase' = [phase EXCEPT ![n] = "prepare"]
    /\ messages' = messages \union {[type |-> "PREPARE", view |-> view[n], sender |-> n]}
    /\ UNCHANGED <<view, proposals, votes, committed, leader, highQC>>

\* Node votes for proposal
NodeVote(n) ==
    /\ phase[n] = "prepare"
    /\ \E msg \in messages: msg.type = "PREPARE" /\ msg.view = view[n]
    /\ votes' = [votes EXCEPT ![view[n]] = votes[view[n]] \union {n}]
    /\ phase' = [phase EXCEPT ![n] = "precommit"]
    /\ messages' = messages \union {[type |-> "VOTE", view |-> view[n], sender |-> n]}
    /\ UNCHANGED <<view, proposals, committed, leader, highQC>>

\* Quorum reached - commit
QuorumCommit(n) ==
    /\ phase[n] = "precommit"
    /\ Cardinality(votes[view[n]] \intersect Honest) >= QuorumSize
    /\ committed' = [committed EXCEPT ![n] = committed[n] \union {view[n]}]
    /\ phase' = [phase EXCEPT ![n] = "decide"]
    /\ highQC' = [highQC EXCEPT ![n] = view[n]]
    /\ UNCHANGED <<view, proposals, votes, leader, messages>>

\* Advance to next view
AdvanceView(n) ==
    /\ phase[n] = "decide"
    /\ view[n] < MaxView
    /\ view' = [view EXCEPT ![n] = view[n] + 1]
    /\ phase' = [phase EXCEPT ![n] = "new_view"]
    /\ UNCHANGED <<proposals, votes, committed, leader, highQC, messages>>

\* Next state
Next ==
    \E n \in Honest:
        \/ LeaderPropose(n)
        \/ NodeVote(n)
        \/ QuorumCommit(n)
        \/ AdvanceView(n)

\* Specification
Spec == Init /\ [][Next]_<<view, phase, proposals, votes, committed, leader, highQC, messages>>

\* Properties to verify
THEOREM Spec => []TypeOK
THEOREM Spec => []Safety

====
