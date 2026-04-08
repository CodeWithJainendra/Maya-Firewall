//! Runtime state for the dashboard API and websocket stream.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use dashmap::DashSet;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, broadcast};

use maya_core::events::MayaEvent;
use maya_core::types::Severity;

use crate::api::GridStats;

const STREAM_CHANNEL_CAPACITY: usize = 2048;
const FEED_HISTORY_LIMIT: usize = 100;
const SERIES_HISTORY_LIMIT: usize = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSeriesPoint {
    pub time: String,
    pub intensity: u32,
    pub probes: u32,
    pub exploits: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveFeedEvent {
    pub id: String,
    pub actor: String,
    pub command: String,
    pub command_label: String,
    pub severity: String,
    pub decoy: String,
    pub decoy_type: Option<String>,
    pub state: String,
    pub source_module: String,
    pub metadata: HashMap<String, serde_json::Value>,
    pub time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveStreamMessage {
    pub kind: String,
    pub feed: LiveFeedEvent,
    pub stats: GridStats,
    pub series: Vec<AttackSeriesPoint>,
}

#[derive(Clone)]
pub struct DashboardState {
    stats: Arc<RwLock<GridStats>>,
    trapped_attackers: Arc<DashSet<String>>,
    feed_history: Arc<RwLock<VecDeque<LiveFeedEvent>>>,
    attack_series: Arc<RwLock<VecDeque<AttackSeriesPoint>>>,
    stream_tx: broadcast::Sender<LiveStreamMessage>,
    seq: Arc<AtomicU64>,
}

impl DashboardState {
    pub fn new() -> Self {
        let (stream_tx, _) = broadcast::channel(STREAM_CHANNEL_CAPACITY);

        let seed = vec![
            AttackSeriesPoint {
                time: "10:00".into(),
                intensity: 45,
                probes: 42,
                exploits: 6,
            },
            AttackSeriesPoint {
                time: "10:15".into(),
                intensity: 52,
                probes: 51,
                exploits: 9,
            },
            AttackSeriesPoint {
                time: "10:30".into(),
                intensity: 38,
                probes: 34,
                exploits: 5,
            },
            AttackSeriesPoint {
                time: "10:45".into(),
                intensity: 85,
                probes: 77,
                exploits: 18,
            },
            AttackSeriesPoint {
                time: "11:00".into(),
                intensity: 65,
                probes: 61,
                exploits: 11,
            },
            AttackSeriesPoint {
                time: "11:15".into(),
                intensity: 92,
                probes: 84,
                exploits: 22,
            },
            AttackSeriesPoint {
                time: "11:30".into(),
                intensity: 78,
                probes: 69,
                exploits: 14,
            },
        ];

        Self {
            stats: Arc::new(RwLock::new(GridStats::default())),
            trapped_attackers: Arc::new(DashSet::new()),
            feed_history: Arc::new(RwLock::new(VecDeque::with_capacity(FEED_HISTORY_LIMIT))),
            attack_series: Arc::new(RwLock::new(VecDeque::from(seed))),
            stream_tx,
            seq: Arc::new(AtomicU64::new(1)),
        }
    }

    pub async fn stats_snapshot(&self) -> GridStats {
        self.stats.read().await.clone()
    }

    pub async fn series_snapshot(&self) -> Vec<AttackSeriesPoint> {
        self.attack_series.read().await.iter().cloned().collect()
    }

    pub fn subscribe_stream(&self) -> broadcast::Receiver<LiveStreamMessage> {
        self.stream_tx.subscribe()
    }

    pub async fn recent_stream(&self, limit: usize) -> Vec<LiveStreamMessage> {
        let feed = self
            .feed_history
            .read()
            .await
            .iter()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();

        let stats = self.stats_snapshot().await;
        let series = self.series_snapshot().await;

        feed.into_iter()
            .map(|entry| LiveStreamMessage {
                kind: "snapshot".to_string(),
                feed: entry,
                stats: stats.clone(),
                series: series.clone(),
            })
            .collect()
    }

    pub async fn apply_event(&self, event: MayaEvent) {
        match event {
            MayaEvent::ConnectionDetected {
                source_ip,
                dest_port,
                ..
            } => {
                let metadata =
                    HashMap::from([("dest_port".to_string(), serde_json::json!(dest_port))]);

                self.push_feed_and_series(
                    source_ip.to_string(),
                    format!("tcp connect -> port {dest_port}"),
                    "connection_probe".to_string(),
                    Severity::Low,
                    "edge-gateway".to_string(),
                    None,
                    "recon".to_string(),
                    "network".to_string(),
                    metadata,
                    6,
                    5,
                    1,
                )
                .await;
            }
            MayaEvent::ScanDetected {
                source_ip,
                scan_type,
                ports_scanned,
                severity,
                scan_speed_pps,
                ..
            } => {
                {
                    let mut stats = self.stats.write().await;
                    stats.scans_detected = stats.scans_detected.saturating_add(1);
                }

                let metadata = HashMap::from([
                    (
                        "scan_type".to_string(),
                        serde_json::json!(format!("{:?}", scan_type)),
                    ),
                    (
                        "ports_scanned".to_string(),
                        serde_json::json!(ports_scanned.len()),
                    ),
                    (
                        "scan_speed_pps".to_string(),
                        serde_json::json!(scan_speed_pps),
                    ),
                ]);

                self.push_feed_and_series(
                    source_ip.to_string(),
                    format!("scan {:?} across {} ports", scan_type, ports_scanned.len()),
                    "network_scan".to_string(),
                    severity,
                    "network-topology".to_string(),
                    None,
                    "recon".to_string(),
                    "network".to_string(),
                    metadata,
                    severity_weight(severity),
                    12,
                    2,
                )
                .await;
            }
            MayaEvent::DecoySpawned {
                decoy_id,
                decoy_type,
                services,
                ..
            } => {
                {
                    let mut stats = self.stats.write().await;
                    stats.active_decoys = stats.active_decoys.saturating_add(1);
                }

                let metadata =
                    HashMap::from([("services".to_string(), serde_json::json!(services))]);

                self.push_feed_and_series(
                    "maya-orchestrator".to_string(),
                    format!("spawned decoy {:?}", decoy_type),
                    "decoy_spawn".to_string(),
                    Severity::Medium,
                    decoy_id.to_string(),
                    Some(format!("{:?}", decoy_type)),
                    "deploy".to_string(),
                    "deception".to_string(),
                    metadata,
                    10,
                    3,
                    1,
                )
                .await;
            }
            MayaEvent::DecoyDestroyed { decoy_id, reason } => {
                {
                    let mut stats = self.stats.write().await;
                    stats.active_decoys = stats.active_decoys.saturating_sub(1);
                }

                let metadata = HashMap::from([("reason".to_string(), serde_json::json!(reason))]);

                self.push_feed_and_series(
                    "maya-orchestrator".to_string(),
                    "destroyed decoy".to_string(),
                    "decoy_destroy".to_string(),
                    Severity::Low,
                    decoy_id.to_string(),
                    None,
                    "cleanup".to_string(),
                    "deception".to_string(),
                    metadata,
                    5,
                    2,
                    0,
                )
                .await;
            }
            MayaEvent::AttackerEngaged {
                attacker_ip,
                decoy_id,
                engagement_level,
                ..
            } => {
                let attacker_key = attacker_ip.to_string();

                {
                    let mut stats = self.stats.write().await;
                    stats.active_sessions = stats.active_sessions.saturating_add(1);
                }

                self.trapped_attackers.insert(attacker_key.clone());
                {
                    let mut stats = self.stats.write().await;
                    stats.trapped_attackers = self.trapped_attackers.len() as u32;
                }

                let metadata = HashMap::from([(
                    "engagement_level".to_string(),
                    serde_json::json!(format!("{:?}", engagement_level)),
                )]);

                self.push_feed_and_series(
                    attacker_key,
                    "engaged with deception shell".to_string(),
                    "session_engage".to_string(),
                    Severity::High,
                    decoy_id.to_string(),
                    None,
                    "interactive".to_string(),
                    "network".to_string(),
                    metadata,
                    14,
                    4,
                    4,
                )
                .await;
            }
            MayaEvent::CommandExecuted {
                session_id,
                command,
                command_label,
                severity,
                decoy_id,
                decoy_type,
                metadata,
                ..
            } => {
                let sev = severity.unwrap_or(Severity::Medium);
                let label_for_state = command_label.clone();
                self.push_feed_and_series(
                    session_id.to_string(),
                    command,
                    command_label.unwrap_or_else(|| "command_execution".to_string()),
                    sev,
                    decoy_id.to_string(),
                    decoy_type.map(|dt| format!("{:?}", dt)),
                    classify_state_from_label(label_for_state.as_deref()),
                    "deception".to_string(),
                    metadata,
                    severity_weight(sev),
                    3,
                    if sev >= Severity::High { 5 } else { 2 },
                )
                .await;
            }
            MayaEvent::MalwareCaptured {
                sha256,
                file_size,
                session_id,
                ..
            } => {
                {
                    let mut stats = self.stats.write().await;
                    stats.malware_captured = stats.malware_captured.saturating_add(1);
                }

                let metadata = HashMap::from([
                    (
                        "sha256_prefix".to_string(),
                        serde_json::json!(sha256.chars().take(12).collect::<String>()),
                    ),
                    ("file_size".to_string(), serde_json::json!(file_size)),
                ]);

                self.push_feed_and_series(
                    session_id.to_string(),
                    "uploaded malware sample".to_string(),
                    "malware_upload".to_string(),
                    Severity::Critical,
                    "sandbox-intake".to_string(),
                    None,
                    "collection".to_string(),
                    "sandbox".to_string(),
                    metadata,
                    20,
                    2,
                    8,
                )
                .await;
            }
            MayaEvent::AlertGenerated { alert } => {
                {
                    let mut stats = self.stats.write().await;
                    stats.alerts_generated = stats.alerts_generated.saturating_add(1);
                }

                let metadata = HashMap::from([
                    ("title".to_string(), serde_json::json!(alert.title)),
                    (
                        "phase".to_string(),
                        serde_json::json!(format!("{}", alert.attack_phase)),
                    ),
                ]);

                self.push_feed_and_series(
                    alert.attacker_ip.to_string(),
                    alert.description,
                    "soc_alert".to_string(),
                    alert.severity,
                    alert
                        .decoy_id
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "unassigned".to_string()),
                    None,
                    "alert".to_string(),
                    "soc".to_string(),
                    metadata,
                    severity_weight(alert.severity),
                    1,
                    6,
                )
                .await;
            }
            MayaEvent::GridStats {
                active_decoys,
                active_sessions,
                trapped_attackers,
                malware_captured,
                ..
            } => {
                let mut stats = self.stats.write().await;
                stats.active_decoys = active_decoys;
                stats.active_sessions = active_sessions;
                stats.trapped_attackers = trapped_attackers;
                stats.malware_captured = malware_captured;
            }
            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn push_feed_and_series(
        &self,
        actor: String,
        command: String,
        command_label: String,
        severity: Severity,
        decoy: String,
        decoy_type: Option<String>,
        state: String,
        source_module: String,
        metadata: HashMap<String, serde_json::Value>,
        intensity_delta: u32,
        probes: u32,
        exploits: u32,
    ) {
        let feed = LiveFeedEvent {
            id: format!("feed-{}", self.seq.fetch_add(1, Ordering::Relaxed)),
            actor,
            command,
            command_label,
            severity: severity_to_css(&severity).to_string(),
            decoy,
            decoy_type,
            state,
            source_module,
            metadata,
            time: Utc::now().format("%H:%M:%S UTC").to_string(),
        };

        {
            let mut history = self.feed_history.write().await;
            history.push_front(feed.clone());
            while history.len() > FEED_HISTORY_LIMIT {
                let _ = history.pop_back();
            }
        }

        self.push_series_point(intensity_delta, probes, exploits)
            .await;

        let packet = LiveStreamMessage {
            kind: "event".to_string(),
            feed,
            stats: self.stats_snapshot().await,
            series: self.series_snapshot().await,
        };

        let _ = self.stream_tx.send(packet);
    }

    async fn push_series_point(&self, intensity_delta: u32, probes: u32, exploits: u32) {
        let mut series = self.attack_series.write().await;
        let previous = series.back().map(|point| point.intensity).unwrap_or(50);
        let baseline = previous.saturating_sub(6);
        let next = (baseline + intensity_delta).clamp(5, 100);

        series.push_back(AttackSeriesPoint {
            time: Utc::now().format("%H:%M:%S").to_string(),
            intensity: next,
            probes,
            exploits,
        });

        while series.len() > SERIES_HISTORY_LIMIT {
            let _ = series.pop_front();
        }
    }
}

fn classify_state_from_label(label: Option<&str>) -> String {
    match label.unwrap_or_default() {
        "recon_scan" | "system_discovery" => "recon".to_string(),
        "credential_discovery" => "collection".to_string(),
        "payload_transfer" | "data_access" => "lateral".to_string(),
        _ => "interactive".to_string(),
    }
}

fn severity_weight(severity: Severity) -> u32 {
    match severity {
        Severity::Info => 4,
        Severity::Low => 6,
        Severity::Medium => 10,
        Severity::High => 14,
        Severity::Critical => 20,
    }
}

fn severity_to_css(severity: &Severity) -> &'static str {
    match severity {
        Severity::Info | Severity::Low => "medium",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

impl Default for DashboardState {
    fn default() -> Self {
        Self::new()
    }
}
