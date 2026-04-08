//! Network Engine — the main orchestrator for MAYA's network layer.
//! Coordinates packet processing, scan detection, intrusion classification,
//! and routing into the deception grid.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::RwLock;

use anyhow::Result;
use dashmap::DashMap;
use tracing::{debug, info, warn};

use maya_core::config::NetworkConfig;
use maya_core::events::{EventBus, MayaEvent};
use maya_core::types::{DecoyId, NetworkEventType, Protocol, SessionId, Severity};

use crate::detector::{DeceptionDecision, IntrusionClassifier};
use crate::packet::{ParsedPacket, RawPacket};
use crate::scanner::ScanDetector;
use crate::session::SessionManager;
use crate::xdp::{XdpAttachResult, XdpManager, XdpMode};

/// The Network Engine — MAYA's first line of interaction.
///
/// All traffic flows through this engine. It detects reconnaissance,
/// classifies threats, and routes attackers into the deception grid.
pub struct NetworkEngine {
    /// Configuration
    config: NetworkConfig,
    /// Scan detection subsystem
    scan_detector: Arc<ScanDetector>,
    /// Intrusion classification
    classifier: Arc<IntrusionClassifier>,
    /// Session management
    sessions: Arc<SessionManager>,
    /// Event bus for publishing events
    event_bus: Arc<EventBus>,
    /// XDP ingress manager
    xdp: Arc<XdpManager>,
    /// Last XDP initialization status
    xdp_status: Arc<RwLock<Option<XdpAttachResult>>>,
    /// Port-level connection counters (for rate limiting)
    port_counters: Arc<DashMap<u16, u64>>,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl NetworkEngine {
    /// Create a new Network Engine.
    pub fn new(config: NetworkConfig, event_bus: Arc<EventBus>) -> Self {
        let scan_detector = Arc::new(ScanDetector::new(5, 60)); // 5 ports in 60s = scan
        let classifier = Arc::new(IntrusionClassifier::new());

        info!(
            interface = %config.interface,
            ports = ?config.monitored_ports,
            "🌐 Network Engine initialized"
        );

        let xdp = Arc::new(XdpManager::new(&config));

        Self {
            config,
            scan_detector,
            classifier,
            sessions: Arc::new(SessionManager::new()),
            event_bus,
            xdp,
            xdp_status: Arc::new(RwLock::new(None)),
            port_counters: Arc::new(DashMap::new()),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start the network engine.
    pub async fn start(&self) -> Result<()> {
        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        info!(
            "🕸️  MAYA Network Engine ACTIVE on interface: {}",
            self.config.interface
        );
        info!("   Monitoring ports: {:?}", self.config.monitored_ports);
        info!("   Decoy subnet: {}", self.config.decoy_subnet);
        info!("   DNS intercept: {}", self.config.dns_intercept);

        let xdp_status = self.xdp.initialize().await?;
        match xdp_status.mode {
            XdpMode::Attached => info!(
                interface = %xdp_status.interface,
                details = %xdp_status.details,
                "🧬 XDP ingress active"
            ),
            XdpMode::DryRun => warn!(
                interface = %xdp_status.interface,
                details = %xdp_status.details,
                "🧪 XDP ingress unavailable, continuing in dry-run mode"
            ),
            XdpMode::Unsupported => warn!(
                interface = %xdp_status.interface,
                details = %xdp_status.details,
                "⚠️  XDP ingress unsupported on this interface"
            ),
        }
        *self.xdp_status.write().expect("xdp status lock poisoned") = Some(xdp_status);

        // Start the cleanup task for stale scan trackers
        let detector = self.scan_detector.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                detector.cleanup(std::time::Duration::from_secs(600));
                debug!(
                    "🧹 Cleaned up stale scan trackers. Active: {}",
                    detector.active_trackers()
                );
            }
        });

        Ok(())
    }

    /// Process a raw packet captured from XDP, AF_XDP, or a userspace tap.
    pub async fn process_raw_packet(&self, raw: &RawPacket) -> Result<Option<DeceptionDecision>> {
        let Some(packet) = ParsedPacket::parse(raw) else {
            return Ok(None);
        };

        if packet.tcp.is_none() {
            return Ok(None);
        }

        let (Some(source_ip), Some(source_port), Some(dest_port)) =
            (packet.source_ip, packet.source_port, packet.dest_port)
        else {
            return Ok(None);
        };

        if !self.xdp.monitored_ports().contains(&dest_port) {
            return Ok(None);
        }

        let protocol = Protocol::Tcp;

        let scan_type = packet.tcp.as_ref().and_then(|tcp| tcp.flags.scan_type());
        let event_type = scan_type
            .clone()
            .map(NetworkEventType::PortScan)
            .unwrap_or(NetworkEventType::LoginAttempt);

        let decision = self
            .process_connection_internal(
                source_ip,
                source_port,
                dest_port,
                protocol,
                scan_type,
                &event_type,
            )
            .await?;

        Ok(Some(decision))
    }

    /// Process an incoming connection event.
    ///
    /// This is the core decision loop:
    /// 1. Check if this is part of a scan
    /// 2. Classify the activity
    /// 3. Decide: Allow / Redirect / Spawn Decoy / Drop
    /// 4. Publish events for other subsystems
    pub async fn process_connection(
        &self,
        source_ip: IpAddr,
        source_port: u16,
        dest_port: u16,
        protocol: Protocol,
    ) -> Result<DeceptionDecision> {
        self.process_connection_internal(
            source_ip,
            source_port,
            dest_port,
            protocol,
            None,
            &NetworkEventType::LoginAttempt,
        )
        .await
    }

    async fn process_connection_internal(
        &self,
        source_ip: IpAddr,
        source_port: u16,
        dest_port: u16,
        protocol: Protocol,
        scan_type: Option<maya_core::types::ScanType>,
        fallback_event_type: &NetworkEventType,
    ) -> Result<DeceptionDecision> {
        // Track connection count
        *self.port_counters.entry(dest_port).or_insert(0) += 1;

        // Publish connection event
        let _ = self.event_bus.publish(MayaEvent::ConnectionDetected {
            source_ip,
            source_port,
            dest_port,
            protocol,
            timestamp: chrono::Utc::now(),
        });

        // Check for scan activity
        if let Some(scan) = self
            .scan_detector
            .record_probe(source_ip, dest_port, scan_type)
        {
            warn!(
                "🔍 SCAN DETECTED from {} — {} unique ports, type: {:?}, threat: {:?}",
                source_ip, scan.unique_ports_scanned, scan.scan_type, scan.threat_classification
            );

            let _ = self.event_bus.publish(MayaEvent::ScanDetected {
                source_ip,
                scan_type: scan.scan_type.clone(),
                ports_scanned: scan.ports.clone(),
                severity: match scan.threat_classification {
                    crate::scanner::ThreatClass::LowThreat => Severity::Low,
                    crate::scanner::ThreatClass::MediumThreat => Severity::Medium,
                    crate::scanner::ThreatClass::HighThreat => Severity::High,
                    crate::scanner::ThreatClass::CriticalThreat => Severity::Critical,
                },
                scan_speed_pps: scan.scan_speed_pps,
                timestamp: chrono::Utc::now(),
            });

            // For scans, return decision to spawn decoy network
            return Ok(DeceptionDecision::SpawnCustomDecoy {
                template: "network-topology".to_string(),
                services: scan.ports,
            });
        }

        // Classify the connection
        let decision = self
            .classifier
            .classify(source_ip, dest_port, fallback_event_type);

        match &decision {
            DeceptionDecision::RedirectToDecoy {
                decoy_type,
                engagement_level,
            } => {
                info!(
                    "🎭 Redirecting {} → decoy type: {}, engagement: {}",
                    source_ip, decoy_type, engagement_level
                );
            }
            DeceptionDecision::SpawnCustomDecoy { template, services } => {
                info!(
                    "🎪 Spawning custom decoy for {} — template: {}, services: {:?}",
                    source_ip, template, services
                );
            }
            DeceptionDecision::Drop => {
                debug!("🚫 Dropping connection from {}", source_ip);
            }
            DeceptionDecision::Allow => {
                debug!("✅ Allowing connection from {}", source_ip);
            }
            _ => {}
        }

        Ok(decision)
    }

    /// Create a new tracked session for an attacker.
    pub fn create_session(
        &self,
        attacker_ip: IpAddr,
        attacker_port: u16,
        decoy_id: DecoyId,
    ) -> SessionId {
        let session_id = self
            .sessions
            .create_session(attacker_ip, attacker_port, decoy_id.clone());

        info!(
            "🕸️  New session {} — Attacker: {}:{} → Decoy: {}",
            session_id, attacker_ip, attacker_port, decoy_id
        );

        let _ = self.event_bus.publish(MayaEvent::AttackerEngaged {
            session_id: session_id.clone(),
            attacker_ip,
            decoy_id,
            engagement_level: maya_core::types::EngagementLevel::High,
        });

        session_id
    }

    /// Get session manager reference.
    pub fn sessions(&self) -> &SessionManager {
        &self.sessions
    }

    /// Get engine statistics.
    pub fn stats(&self) -> NetworkStats {
        let xdp_mode = self
            .xdp_status
            .read()
            .expect("xdp status lock poisoned")
            .as_ref()
            .map(|status| status.mode.to_string())
            .unwrap_or_else(|| "uninitialized".to_string());

        NetworkStats {
            active_sessions: self.sessions.active_count(),
            total_scans_detected: self.scan_detector.total_scans(),
            active_trackers: self.scan_detector.active_trackers(),
            xdp_mode,
        }
    }

    /// Shutdown the engine.
    pub async fn shutdown(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        info!("🛑 Network Engine shutting down");
    }
}

/// Network engine statistics.
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub active_sessions: usize,
    pub total_scans_detected: u64,
    pub active_trackers: usize,
    pub xdp_mode: String,
}
