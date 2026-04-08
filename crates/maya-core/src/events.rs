//! Event system for MAYA — lock-free, high-throughput event bus.
//!
//! All MAYA subsystems communicate through typed events.
//! Uses `tokio::sync::broadcast` for fan-out event distribution.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use tokio::sync::broadcast;
use tracing::warn;
use uuid::Uuid;

use crate::types::*;

/// Maximum events in the broadcast channel buffer.
const EVENT_CHANNEL_CAPACITY: usize = 10_000;
/// Maximum in-memory replay entries retained by default.
const DEFAULT_REPLAY_CAPACITY: usize = 50_000;

/// Durable event record with ordering metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub sequence: u64,
    pub recorded_at: DateTime<Utc>,
    pub event: MayaEvent,
}

/// Configuration for EventBus durability and replay.
#[derive(Debug, Clone)]
pub struct EventBusConfig {
    pub channel_capacity: usize,
    pub replay_capacity: usize,
    pub audit_log_path: Option<PathBuf>,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            channel_capacity: EVENT_CHANNEL_CAPACITY,
            replay_capacity: DEFAULT_REPLAY_CAPACITY,
            audit_log_path: None,
        }
    }
}

/// All possible events in the MAYA system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MayaEvent {
    // ── Network Events ───────────────────────────────────────
    /// New connection detected
    ConnectionDetected {
        source_ip: IpAddr,
        source_port: u16,
        dest_port: u16,
        protocol: Protocol,
        timestamp: DateTime<Utc>,
    },

    /// Port scan detected
    ScanDetected {
        source_ip: IpAddr,
        scan_type: ScanType,
        ports_scanned: Vec<u16>,
        severity: Severity,
        scan_speed_pps: f64,
        timestamp: DateTime<Utc>,
    },

    /// Brute force attempt
    BruteForceDetected {
        source_ip: IpAddr,
        service: String,
        attempts: u32,
        timestamp: DateTime<Utc>,
    },

    // ── Deception Events ─────────────────────────────────────
    /// Decoy spawned
    DecoySpawned {
        decoy_id: DecoyId,
        decoy_type: DecoyType,
        ip_addr: IpAddr,
        services: Vec<u16>,
    },

    /// Decoy destroyed
    DecoyDestroyed { decoy_id: DecoyId, reason: String },

    /// Attacker engaged with decoy
    AttackerEngaged {
        session_id: SessionId,
        attacker_ip: IpAddr,
        decoy_id: DecoyId,
        engagement_level: EngagementLevel,
    },

    /// Attacker executed a command in decoy
    CommandExecuted {
        session_id: SessionId,
        command: String,
        command_label: Option<String>,
        severity: Option<Severity>,
        decoy_id: DecoyId,
        decoy_type: Option<DecoyType>,
        metadata: std::collections::HashMap<String, serde_json::Value>,
        timestamp: DateTime<Utc>,
    },

    // ── AI Events ────────────────────────────────────────────
    /// AI generated a response for deception
    AiResponseGenerated {
        session_id: SessionId,
        prompt_type: String,
        response_length: usize,
        latency_ms: u64,
    },

    // ── Sandbox Events ───────────────────────────────────────
    /// Malware sample captured
    MalwareCaptured {
        sample_id: Uuid,
        sha256: String,
        file_size: u64,
        session_id: SessionId,
    },

    /// Malware analysis completed
    MalwareAnalyzed {
        sample_id: Uuid,
        c2_servers: Vec<String>,
        family: Option<String>,
    },

    // ── Profiler Events ──────────────────────────────────────
    /// Attacker attributed to APT group
    AttackerAttributed {
        session_id: SessionId,
        attribution: Attribution,
    },

    /// Behavioral anomaly detected
    BehavioralAnomaly {
        session_id: SessionId,
        anomaly_type: String,
        confidence: f64,
    },

    // ── Alert Events ─────────────────────────────────────────
    /// New alert generated
    AlertGenerated { alert: Alert },

    // ── Consensus Events ─────────────────────────────────────
    /// Consensus reached on a proposal
    ConsensusReached { proposal_id: Uuid, view_number: u64 },

    // ── System Events ────────────────────────────────────────
    /// System health check
    HealthCheck {
        component: String,
        status: String,
        timestamp: DateTime<Utc>,
    },

    /// Grid-wide statistics
    GridStats {
        active_decoys: u32,
        active_sessions: u32,
        trapped_attackers: u32,
        malware_captured: u32,
        timestamp: DateTime<Utc>,
    },
}

/// The central event bus for MAYA.
///
/// All subsystems publish and subscribe to events through this bus.
/// Uses lock-free broadcast channels for maximum throughput.
pub struct EventBus {
    sender: broadcast::Sender<MayaEvent>,
    sequence: AtomicU64,
    replay: RwLock<VecDeque<EventRecord>>,
    replay_capacity: usize,
    audit_log: Option<Mutex<BufWriter<File>>>,
}

impl EventBus {
    /// Create a new event bus.
    pub fn new() -> Self {
        Self::with_config(EventBusConfig::default())
            .expect("default event bus configuration should not fail")
    }

    /// Create an event bus with durability configuration.
    pub fn with_config(config: EventBusConfig) -> std::io::Result<Self> {
        let replay_capacity = config.replay_capacity.max(1);
        let (sender, _) = broadcast::channel(config.channel_capacity.max(1));

        let audit_log = match config.audit_log_path {
            Some(path) => Some(Mutex::new(open_audit_log(&path)?)),
            None => None,
        };

        Ok(Self {
            sender,
            sequence: AtomicU64::new(0),
            replay: RwLock::new(VecDeque::with_capacity(replay_capacity.min(1024))),
            replay_capacity,
            audit_log,
        })
    }

    /// Create an event bus with append-only JSONL audit log enabled.
    pub fn with_audit_log(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Self::with_config(EventBusConfig {
            audit_log_path: Some(path.as_ref().to_path_buf()),
            ..EventBusConfig::default()
        })
    }

    /// Publish an event to all subscribers.
    pub fn publish(
        &self,
        event: MayaEvent,
    ) -> Result<usize, Box<broadcast::error::SendError<MayaEvent>>> {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let record = EventRecord {
            sequence,
            recorded_at: Utc::now(),
            event: event.clone(),
        };

        {
            let mut replay = self.replay.write().expect("event replay lock poisoned");
            replay.push_back(record.clone());
            while replay.len() > self.replay_capacity {
                replay.pop_front();
            }
        }

        if let Some(audit_log) = &self.audit_log {
            let mut writer = audit_log.lock().expect("audit log lock poisoned");
            if let Err(err) = append_audit_record(&mut writer, &record) {
                warn!(error = %err, sequence, "failed to append event to audit log");
            }
        }

        self.sender.send(event).map_err(Box::new)
    }

    /// Subscribe to receive events.
    pub fn subscribe(&self) -> broadcast::Receiver<MayaEvent> {
        self.sender.subscribe()
    }

    /// Get the number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    /// Return the most recent replay records.
    pub fn replay_recent(&self, limit: usize) -> Vec<EventRecord> {
        let replay = self.replay.read().expect("event replay lock poisoned");
        let take = limit.min(replay.len());
        replay
            .iter()
            .skip(replay.len().saturating_sub(take))
            .cloned()
            .collect()
    }

    /// Return replay records at or after a given sequence number.
    pub fn replay_since(&self, from_sequence: u64, limit: usize) -> Vec<EventRecord> {
        let replay = self.replay.read().expect("event replay lock poisoned");
        replay
            .iter()
            .filter(|record| record.sequence >= from_sequence)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Latest published sequence number.
    pub fn latest_sequence(&self) -> u64 {
        self.sequence.load(Ordering::Relaxed)
    }

    /// Load historical records from an audit JSONL file.
    pub fn load_audit_records(
        path: impl AsRef<Path>,
        from_sequence: u64,
        limit: usize,
    ) -> std::io::Result<Vec<EventRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut records = Vec::with_capacity(limit.min(1024));

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<EventRecord>(&line) {
                Ok(record) if record.sequence >= from_sequence => {
                    records.push(record);
                    if records.len() >= limit {
                        break;
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    warn!(error = %err, "failed to parse event audit record");
                }
            }
        }

        Ok(records)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

fn open_audit_log(path: &Path) -> std::io::Result<BufWriter<File>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = OpenOptions::new().create(true).append(true).open(path)?;
    Ok(BufWriter::new(file))
}

fn append_audit_record(writer: &mut BufWriter<File>, record: &EventRecord) -> std::io::Result<()> {
    serde_json::to_writer(&mut *writer, record)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health_event(component: &str) -> MayaEvent {
        MayaEvent::HealthCheck {
            component: component.to_string(),
            status: "ok".to_string(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn replay_since_tracks_ordered_records() {
        let bus = EventBus::new();
        let _ = bus.publish(health_event("network"));
        let _ = bus.publish(health_event("sandbox"));

        let records = bus.replay_since(2, 10);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sequence, 2);
        match &records[0].event {
            MayaEvent::HealthCheck { component, .. } => assert_eq!(component, "sandbox"),
            _ => panic!("unexpected event type"),
        }
    }

    #[test]
    fn replay_capacity_evicts_oldest_records() {
        let bus = EventBus::with_config(EventBusConfig {
            replay_capacity: 2,
            ..EventBusConfig::default()
        })
        .expect("bus init should succeed");

        let _ = bus.publish(health_event("a"));
        let _ = bus.publish(health_event("b"));
        let _ = bus.publish(health_event("c"));

        let records = bus.replay_recent(10);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].sequence, 2);
        assert_eq!(records[1].sequence, 3);
    }

    #[test]
    fn audit_log_is_appended_and_replayable() {
        let path = std::env::temp_dir().join(format!("maya-events-{}.jsonl", Uuid::new_v4()));

        let bus = EventBus::with_audit_log(&path).expect("audit bus init should succeed");
        let _ = bus.publish(health_event("consensus"));
        let _ = bus.publish(health_event("crypto"));

        let loaded = EventBus::load_audit_records(&path, 1, 10).expect("audit load should work");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].sequence, 1);
        assert_eq!(loaded[1].sequence, 2);

        std::fs::remove_file(path).ok();
    }
}
