//! HotStuff BFT Consensus Protocol Implementation.
//! High-throughput leader-based BFT consensus for distributed decoy coordination.
//!
//! HotStuff phases: PREPARE → PRE-COMMIT → COMMIT → DECIDE

use anyhow::Result;
use dashmap::DashMap;
use maya_core::types::ConsensusProposal;
use maya_crypto::KeyManager;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{debug, info};

/// HotStuff message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HotStuffMessage {
    /// NEW-VIEW: Sent by replicas to new leader
    NewView {
        view_number: u64,
        sender: String,
        justify: Option<QuorumCertificate>,
    },
    /// PREPARE: Leader proposes a block
    Prepare {
        view_number: u64,
        proposal: ConsensusProposal,
        justify: Option<QuorumCertificate>,
    },
    /// VOTE: Replica votes for a proposal
    Vote {
        view_number: u64,
        proposal_hash: String,
        sender: String,
        signature: Vec<u8>,
    },
    /// DECIDE: Final decision
    Decide {
        view_number: u64,
        proposal_hash: String,
        qc: QuorumCertificate,
    },
}

/// Quorum Certificate — proof that 2f+1 nodes agreed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub view_number: u64,
    pub proposal_hash: String,
    pub votes: Vec<VoteRecord>,
    pub phase: HotStuffPhase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRecord {
    pub node_id: String,
    pub signature: Vec<u8>,
}

/// HotStuff protocol phases.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HotStuffPhase {
    Prepare,
    PreCommit,
    Commit,
    Decide,
}

/// HotStuff BFT Consensus Engine.
pub struct HotStuffEngine {
    /// This node's ID
    node_id: String,
    /// Current view number
    view_number: u64,
    /// Quorum size (2f + 1)
    quorum_size: u32,
    /// Total nodes
    total_nodes: u32,
    /// Current leader
    current_leader: String,
    /// Ordered list of all node ids in the grid (sorted, includes self).
    /// Used to derive the round-robin leader for a given view so that every
    /// node independently computes the same leader.
    nodes: Vec<String>,
    /// Key manager for signing
    _key_manager: Arc<KeyManager>,
    /// Pending proposals
    pending: DashMap<String, ConsensusProposal>,
    /// Committed proposals
    committed: DashMap<String, ConsensusProposal>,
    /// Vote collector
    votes: DashMap<String, Vec<VoteRecord>>,
    /// Highest QC seen
    highest_qc: Option<QuorumCertificate>,
}

impl HotStuffEngine {
    pub fn new(node_id: &str, quorum_size: u32, total_nodes: u32) -> Self {
        let mut km = KeyManager::new(node_id);
        let _ = km.generate_identity();

        info!(
            node = node_id,
            quorum = quorum_size,
            total = total_nodes,
            "⚡ HotStuff BFT Consensus Engine initialized"
        );

        Self {
            node_id: node_id.to_string(),
            view_number: 0,
            quorum_size,
            total_nodes,
            current_leader: node_id.to_string(), // Bootstrap as leader
            nodes: vec![node_id.to_string()],
            _key_manager: Arc::new(km),
            pending: DashMap::new(),
            committed: DashMap::new(),
            votes: DashMap::new(),
            highest_qc: None,
        }
    }

    /// Register the full peer set so leader rotation can round-robin across
    /// every node. `peer_ids` are the *other* nodes' ids; this node is added
    /// automatically. The combined list is sorted and de-duplicated so that
    /// all nodes derive the same leader for any given view.
    pub fn with_peers(mut self, peer_ids: Vec<String>) -> Self {
        let mut nodes = peer_ids;
        nodes.push(self.node_id.clone());
        nodes.sort();
        nodes.dedup();
        self.total_nodes = nodes.len() as u32;
        self.nodes = nodes;
        self.current_leader = self.leader_for_view(self.view_number);
        self
    }

    /// Deterministic round-robin leader for a given view.
    fn leader_for_view(&self, view: u64) -> String {
        if self.nodes.is_empty() {
            return self.node_id.clone();
        }
        let idx = (view % self.nodes.len() as u64) as usize;
        self.nodes[idx].clone()
    }

    /// Am I the leader for the current view?
    pub fn is_leader(&self) -> bool {
        self.current_leader == self.node_id
    }

    /// Propose a new block (leader only).
    pub fn propose(&self, proposal: ConsensusProposal) -> Result<HotStuffMessage> {
        if !self.is_leader() {
            return Err(anyhow::anyhow!(
                "Not the leader for view {}",
                self.view_number
            ));
        }

        let hash = self.hash_proposal(&proposal);
        self.pending.insert(hash.clone(), proposal.clone());

        info!(
            view = self.view_number,
            hash = %hash[..16],
            "📋 HotStuff PREPARE: Proposing block"
        );

        Ok(HotStuffMessage::Prepare {
            view_number: self.view_number,
            proposal,
            justify: self.highest_qc.clone(),
        })
    }

    /// Handle an incoming vote.
    ///
    /// Votes are deduplicated by `node_id`: each node contributes at most one
    /// vote toward a given proposal's quorum. Without this, a single faulty or
    /// malicious node — or a replayed vote message — could push `quorum_size`
    /// copies of its own vote and fabricate a `QuorumCertificate` on its own,
    /// defeating the 2f+1 *distinct*-node guarantee that BFT safety rests on.
    pub fn handle_vote(&self, vote: HotStuffMessage) -> Option<QuorumCertificate> {
        if let HotStuffMessage::Vote {
            view_number,
            proposal_hash,
            sender,
            signature,
        } = vote
        {
            let record = VoteRecord {
                node_id: sender,
                signature,
            };

            let mut votes = self.votes.entry(proposal_hash.clone()).or_default();

            // Reject a repeat vote from a node that already voted for this
            // proposal — quorum must be reached by distinct nodes.
            if votes.iter().any(|v| v.node_id == record.node_id) {
                debug!(
                    node = %record.node_id,
                    hash = %&proposal_hash[..16.min(proposal_hash.len())],
                    "⚠️  Duplicate vote ignored"
                );
                return None;
            }
            votes.push(record);

            // Check if quorum reached (distinct votes only).
            if votes.len() >= self.quorum_size as usize {
                let qc = QuorumCertificate {
                    view_number,
                    proposal_hash: proposal_hash.clone(),
                    votes: votes.clone(),
                    phase: HotStuffPhase::Prepare,
                };

                info!(
                    view = view_number,
                    votes = votes.len(),
                    "✅ HotStuff QUORUM REACHED"
                );

                return Some(qc);
            }
        }
        None
    }

    /// Commit a proposal (after quorum).
    pub fn commit(&self, proposal_hash: &str) -> Result<()> {
        if let Some((_, proposal)) = self.pending.remove(proposal_hash) {
            info!(
                hash = %proposal_hash[..16.min(proposal_hash.len())],
                "🔒 HotStuff COMMITTED"
            );
            self.committed.insert(proposal_hash.to_string(), proposal);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Proposal not found"))
        }
    }

    /// Advance to the next view and rotate the leader (round-robin).
    pub fn advance_view(&mut self) {
        self.view_number += 1;
        self.current_leader = self.leader_for_view(self.view_number);
        debug!(
            view = self.view_number,
            leader = %self.current_leader,
            "🔄 View advanced"
        );
    }

    /// Hash a proposal.
    fn hash_proposal(&self, proposal: &ConsensusProposal) -> String {
        let data = serde_json::to_vec(proposal).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        hex::encode(hasher.finalize())
    }

    /// Get committed count.
    pub fn committed_count(&self) -> usize {
        self.committed.len()
    }

    /// Get current view.
    pub fn current_view(&self) -> u64 {
        self.view_number
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(hash: &str, sender: &str) -> HotStuffMessage {
        HotStuffMessage::Vote {
            view_number: 0,
            proposal_hash: hash.to_string(),
            sender: sender.to_string(),
            signature: vec![],
        }
    }

    #[test]
    fn quorum_reached_by_distinct_nodes() {
        let engine = HotStuffEngine::new("n0", 3, 3);
        let h = "deadbeefdeadbeef";
        assert!(engine.handle_vote(vote(h, "a")).is_none());
        assert!(engine.handle_vote(vote(h, "b")).is_none());
        let qc = engine.handle_vote(vote(h, "c"));
        assert!(qc.is_some(), "three distinct votes should form a quorum");
        assert_eq!(qc.unwrap().votes.len(), 3);
    }

    #[test]
    fn duplicate_votes_cannot_forge_quorum() {
        let engine = HotStuffEngine::new("n0", 3, 3);
        let h = "cafef00dcafef00d";
        // One node votes three times — must never reach a 3-node quorum.
        assert!(engine.handle_vote(vote(h, "attacker")).is_none());
        assert!(engine.handle_vote(vote(h, "attacker")).is_none());
        assert!(engine.handle_vote(vote(h, "attacker")).is_none());
        // Only the single distinct vote is actually recorded.
        assert_eq!(engine.votes.get(h).unwrap().len(), 1);
    }

    #[test]
    fn leader_rotates_round_robin_on_view_change() {
        // nodes sorted = [a, b, c]; this node is "b".
        let mut engine =
            HotStuffEngine::new("b", 2, 3).with_peers(vec!["a".to_string(), "c".to_string()]);
        assert_eq!(engine.current_leader, "a"); // view 0
        assert!(!engine.is_leader());

        engine.advance_view(); // view 1 -> b
        assert_eq!(engine.current_leader, "b");
        assert!(engine.is_leader());

        engine.advance_view(); // view 2 -> c
        assert_eq!(engine.current_leader, "c");
        assert!(!engine.is_leader());

        engine.advance_view(); // view 3 wraps -> a
        assert_eq!(engine.current_leader, "a");
    }

    #[test]
    fn advance_view_increments_view_number() {
        let mut engine = HotStuffEngine::new("n0", 1, 1);
        assert_eq!(engine.current_view(), 0);
        engine.advance_view();
        assert_eq!(engine.current_view(), 1);
        // Single-node grid: leader stays self.
        assert!(engine.is_leader());
    }
}
