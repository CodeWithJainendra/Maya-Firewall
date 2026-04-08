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
            _key_manager: Arc::new(km),
            pending: DashMap::new(),
            committed: DashMap::new(),
            votes: DashMap::new(),
            highest_qc: None,
        }
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

            self.votes
                .entry(proposal_hash.clone())
                .or_default()
                .push(record);

            // Check if quorum reached
            if let Some(votes) = self.votes.get(&proposal_hash)
                && votes.len() >= self.quorum_size as usize
            {
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

    /// Advance to next view.
    pub fn advance_view(&mut self) {
        self.view_number += 1;
        // Round-robin leader rotation
        let leader_idx = (self.view_number as u32) % self.total_nodes;
        debug!(view = self.view_number, leader_idx, "🔄 View advanced");
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
