//! Scan detection engine.
//! Analyzes incoming packets to detect port scans, service probes,
//! and reconnaissance activity.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use maya_core::types::ScanType;

/// Tracks scan activity from a single source IP.
#[derive(Debug)]
pub struct ScanTracker {
    /// Ports probed by this IP
    pub ports_probed: Vec<(u16, DateTime<Utc>)>,
    /// First probe timestamp
    pub first_seen: DateTime<Utc>,
    /// Last probe timestamp
    pub last_seen: DateTime<Utc>,
    /// Detected scan type
    pub scan_type: Option<ScanType>,
    /// Number of SYN packets without completing handshake
    pub incomplete_handshakes: u32,
    /// Whether we've triggered deception for this scanner
    pub deception_active: bool,
}

/// The scan detection engine.
/// Uses sliding window analysis to detect port scans with high accuracy
/// while minimizing false positives.
pub struct ScanDetector {
    /// Active scan trackers indexed by source IP
    trackers: Arc<DashMap<IpAddr, ScanTracker>>,
    /// Minimum ports probed to declare a "scan"
    scan_threshold_ports: u16,
    /// Time window for scan detection (seconds)
    scan_window_secs: u64,
    /// Total scans detected (atomic for lock-free counting)
    total_scans_detected: AtomicU64,
}

impl ScanDetector {
    pub fn new(threshold_ports: u16, window_secs: u64) -> Self {
        Self {
            trackers: Arc::new(DashMap::new()),
            scan_threshold_ports: threshold_ports,
            scan_window_secs: window_secs,
            total_scans_detected: AtomicU64::new(0),
        }
    }

    /// Record a probe from a source IP to a destination port.
    /// Returns `Some(ScanType)` if this crosses our scan detection threshold.
    pub fn record_probe(
        &self,
        source_ip: IpAddr,
        dest_port: u16,
        scan_type: Option<ScanType>,
    ) -> Option<ScanDetection> {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::seconds(self.scan_window_secs as i64);

        let mut entry = self
            .trackers
            .entry(source_ip)
            .or_insert_with(|| ScanTracker {
                ports_probed: Vec::new(),
                first_seen: now,
                last_seen: now,
                scan_type: None,
                incomplete_handshakes: 0,
                deception_active: false,
            });

        let tracker = entry.value_mut();
        tracker.last_seen = now;
        tracker.ports_probed.push((dest_port, now));

        // Update scan type if detected from flags
        if scan_type.is_some() {
            tracker.scan_type = scan_type;
        }

        // Prune old entries outside the window
        tracker.ports_probed.retain(|(_, ts)| *ts > cutoff);

        // Count unique ports
        let mut unique_ports: Vec<u16> = tracker.ports_probed.iter().map(|(p, _)| *p).collect();
        unique_ports.sort();
        unique_ports.dedup();

        // Threshold check
        if unique_ports.len() >= self.scan_threshold_ports as usize && !tracker.deception_active {
            tracker.deception_active = true;
            self.total_scans_detected.fetch_add(1, Ordering::Relaxed);

            let scan_speed = if tracker.ports_probed.len() > 1 {
                let duration = (tracker.last_seen - tracker.first_seen)
                    .num_milliseconds()
                    .max(1) as f64;
                tracker.ports_probed.len() as f64 / (duration / 1000.0)
            } else {
                0.0
            };

            return Some(ScanDetection {
                source_ip,
                scan_type: tracker.scan_type.clone().unwrap_or(ScanType::ConnectScan),
                unique_ports_scanned: unique_ports.len() as u32,
                total_probes: tracker.ports_probed.len() as u32,
                ports: unique_ports.clone(),
                scan_speed_pps: scan_speed,
                first_seen: tracker.first_seen,
                last_seen: tracker.last_seen,
                threat_classification: classify_scan_threat(
                    unique_ports.len() as u32,
                    scan_speed,
                    &tracker.scan_type,
                ),
            });
        }

        None
    }

    /// Get total number of detected scans.
    pub fn total_scans(&self) -> u64 {
        self.total_scans_detected.load(Ordering::Relaxed)
    }

    /// Clean up stale trackers.
    pub fn cleanup(&self, max_age: Duration) {
        let cutoff = Utc::now() - chrono::Duration::from_std(max_age).unwrap_or_default();
        self.trackers
            .retain(|_, tracker| tracker.last_seen > cutoff);
    }

    /// Get active tracker count.
    pub fn active_trackers(&self) -> usize {
        self.trackers.len()
    }
}

/// Result of scan detection analysis.
#[derive(Debug, Clone)]
pub struct ScanDetection {
    pub source_ip: IpAddr,
    pub scan_type: ScanType,
    pub unique_ports_scanned: u32,
    pub total_probes: u32,
    pub ports: Vec<u16>,
    pub scan_speed_pps: f64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub threat_classification: ThreatClass,
}

/// Threat classification for detected activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatClass {
    /// Script kiddie / noisy scanner
    LowThreat,
    /// Methodical scanning, possibly automated tool
    MediumThreat,
    /// Slow, deliberate scanning — likely APT
    HighThreat,
    /// Targeted attack pattern
    CriticalThreat,
}

/// Classify the threat level of a scan.
fn classify_scan_threat(
    unique_ports: u32,
    speed: f64,
    scan_type: &Option<ScanType>,
) -> ThreatClass {
    // Slow + stealthy = APT indicator
    if speed < 5.0 && unique_ports < 20 {
        if matches!(
            scan_type,
            Some(ScanType::FinScan | ScanType::NullScan | ScanType::XmasScan)
        ) {
            return ThreatClass::CriticalThreat;
        }
        return ThreatClass::HighThreat;
    }

    // Fast + wide = automated tool
    if speed > 1000.0 && unique_ports > 100 {
        return ThreatClass::LowThreat; // Noisy = script kiddie
    }

    // Moderate = semi-automated or experienced attacker
    if unique_ports > 20 || matches!(scan_type, Some(ScanType::SynScan)) {
        return ThreatClass::MediumThreat;
    }

    ThreatClass::LowThreat
}
