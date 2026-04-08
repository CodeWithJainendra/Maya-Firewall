//! Session tracking for attacker interactions.
//! Maintains state across an attacker's entire engagement with the MAYA grid.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use maya_core::types::{AttackPhase, DecoyId, SessionId};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;

/// A single command executed by the attacker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRecord {
    pub timestamp: DateTime<Utc>,
    pub command: String,
    pub response_size: usize,
    pub latency_ms: u64,
    /// Time between this command and the previous one (typing speed indicator)
    pub inter_command_ms: Option<u64>,
}

/// Complete record of an attacker's interaction session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: SessionId,
    pub attacker_ip: IpAddr,
    pub attacker_port: u16,
    pub decoy_id: DecoyId,
    pub started_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub attack_phase: AttackPhase,
    pub commands: Vec<CommandRecord>,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub credentials_attempted: Vec<CredentialAttempt>,
    pub files_uploaded: Vec<FileRecord>,
    pub files_downloaded: Vec<FileRecord>,
    pub lateral_movement_attempts: Vec<LateralMovement>,
    pub is_active: bool,
}

/// Credential pair attempted by attacker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAttempt {
    pub timestamp: DateTime<Utc>,
    pub username: String,
    pub password: String,
    pub service: String,
    pub success: bool, // Always true in MAYA (we let them in)
}

/// File transferred during session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub timestamp: DateTime<Utc>,
    pub filename: String,
    pub sha256: String,
    pub size: u64,
    pub direction: String, // "upload" or "download"
}

/// Lateral movement attempt within the deception grid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovement {
    pub timestamp: DateTime<Utc>,
    pub source_decoy: DecoyId,
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub method: String, // "ssh", "psexec", "wmi", etc.
}

/// Session manager — tracks all active and historical sessions.
pub struct SessionManager {
    /// Active sessions indexed by session ID
    active: Arc<DashMap<SessionId, SessionRecord>>,
    /// Completed sessions (for analysis)
    completed: Arc<DashMap<SessionId, SessionRecord>>,
    /// Index: attacker IP -> session IDs
    ip_index: Arc<DashMap<IpAddr, Vec<SessionId>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            active: Arc::new(DashMap::new()),
            completed: Arc::new(DashMap::new()),
            ip_index: Arc::new(DashMap::new()),
        }
    }

    /// Create a new session for an attacker.
    pub fn create_session(
        &self,
        attacker_ip: IpAddr,
        attacker_port: u16,
        decoy_id: DecoyId,
    ) -> SessionId {
        let session_id = SessionId::new();
        let now = Utc::now();

        let record = SessionRecord {
            id: session_id.clone(),
            attacker_ip,
            attacker_port,
            decoy_id,
            started_at: now,
            last_activity: now,
            ended_at: None,
            attack_phase: AttackPhase::InitialAccess,
            commands: Vec::new(),
            total_bytes_sent: 0,
            total_bytes_received: 0,
            credentials_attempted: Vec::new(),
            files_uploaded: Vec::new(),
            files_downloaded: Vec::new(),
            lateral_movement_attempts: Vec::new(),
            is_active: true,
        };

        self.active.insert(session_id.clone(), record);
        self.ip_index
            .entry(attacker_ip)
            .or_default()
            .push(session_id.clone());

        session_id
    }

    /// Record a command execution in a session.
    pub fn record_command(
        &self,
        session_id: &SessionId,
        command: String,
        response_size: usize,
        latency_ms: u64,
    ) {
        if let Some(mut session) = self.active.get_mut(session_id) {
            let inter_command_ms = session
                .commands
                .last()
                .map(|prev| (Utc::now() - prev.timestamp).num_milliseconds().max(0) as u64);

            session.commands.push(CommandRecord {
                timestamp: Utc::now(),
                command,
                response_size,
                latency_ms,
                inter_command_ms,
            });
            session.last_activity = Utc::now();
        }
    }

    /// Record a credential attempt.
    pub fn record_credential(
        &self,
        session_id: &SessionId,
        username: String,
        password: String,
        service: String,
    ) {
        if let Some(mut session) = self.active.get_mut(session_id) {
            session.credentials_attempted.push(CredentialAttempt {
                timestamp: Utc::now(),
                username,
                password,
                service,
                success: true, // MAYA always lets them in
            });
            session.last_activity = Utc::now();
        }
    }

    /// Record a file upload (potential malware).
    pub fn record_file_upload(
        &self,
        session_id: &SessionId,
        filename: String,
        sha256: String,
        size: u64,
    ) {
        if let Some(mut session) = self.active.get_mut(session_id) {
            session.files_uploaded.push(FileRecord {
                timestamp: Utc::now(),
                filename,
                sha256,
                size,
                direction: "upload".to_string(),
            });
            session.last_activity = Utc::now();
            session.total_bytes_received += size;
        }
    }

    /// Update the attack phase for a session.
    pub fn update_phase(&self, session_id: &SessionId, phase: AttackPhase) {
        if let Some(mut session) = self.active.get_mut(session_id) {
            session.attack_phase = phase;
            session.last_activity = Utc::now();
        }
    }

    /// End a session and move it to completed.
    pub fn end_session(&self, session_id: &SessionId) {
        if let Some((_, mut session)) = self.active.remove(session_id) {
            session.ended_at = Some(Utc::now());
            session.is_active = false;
            self.completed.insert(session_id.clone(), session);
        }
    }

    /// Get active session count.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Get all sessions for an IP.
    pub fn sessions_for_ip(&self, ip: &IpAddr) -> Vec<SessionId> {
        self.ip_index.get(ip).map(|v| v.clone()).unwrap_or_default()
    }

    /// Get a session record (active or completed).
    pub fn get_session(&self, session_id: &SessionId) -> Option<SessionRecord> {
        self.active
            .get(session_id)
            .map(|s| s.clone())
            .or_else(|| self.completed.get(session_id).map(|s| s.clone()))
    }

    /// Export all completed sessions as JSON.
    pub fn export_completed(&self) -> Vec<SessionRecord> {
        self.completed
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
