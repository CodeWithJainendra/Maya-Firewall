//! Intrusion detection and classification engine.
//! Classifies incoming connections and decides how to route them
//! into the deception grid.

use maya_core::types::{AttackPhase, NetworkEventType, ScanType};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Decision on how to handle a detected intrusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeceptionDecision {
    /// Allow through (legitimate traffic)
    Allow,
    /// Redirect to a decoy
    RedirectToDecoy {
        decoy_type: String,
        engagement_level: String,
    },
    /// Spawn a new decoy specifically for this attacker
    SpawnCustomDecoy {
        template: String,
        services: Vec<u16>,
    },
    /// Drop the packet silently
    Drop,
    /// Rate limit this source
    RateLimit { max_pps: u32 },
    /// Log and monitor only
    Monitor,
}

/// Classification engine for network activity.
pub struct IntrusionClassifier {
    /// Known whitelist IPs
    whitelist: Vec<IpAddr>,
    /// Known threat intelligence IPs
    threat_intel: Vec<ThreatIntelEntry>,
}

/// Threat intelligence entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelEntry {
    pub ip: IpAddr,
    pub threat_type: String,
    pub confidence: f64,
    pub source: String,
    pub last_updated: String,
}

impl IntrusionClassifier {
    pub fn new() -> Self {
        Self {
            whitelist: Vec::new(),
            threat_intel: Vec::new(),
        }
    }

    /// Add an IP to the whitelist.
    pub fn add_whitelist(&mut self, ip: IpAddr) {
        self.whitelist.push(ip);
    }

    /// Add threat intelligence entries.
    pub fn add_threat_intel(&mut self, entries: Vec<ThreatIntelEntry>) {
        self.threat_intel.extend(entries);
    }

    /// Classify an incoming connection and decide disposition.
    pub fn classify(
        &self,
        source_ip: IpAddr,
        dest_port: u16,
        event_type: &NetworkEventType,
    ) -> DeceptionDecision {
        // Check whitelist first
        if self.whitelist.contains(&source_ip) {
            return DeceptionDecision::Allow;
        }

        // Check threat intelligence
        if let Some(intel) = self.threat_intel.iter().find(|e| e.ip == source_ip)
            && intel.confidence > 0.8
        {
            return DeceptionDecision::SpawnCustomDecoy {
                template: "high-interaction".to_string(),
                services: self.services_for_port(dest_port),
            };
        }

        // Classify by event type
        match event_type {
            NetworkEventType::PortScan(scan_type) => self.handle_scan(scan_type, dest_port),
            NetworkEventType::BruteForce => DeceptionDecision::RedirectToDecoy {
                decoy_type: self.decoy_type_for_port(dest_port),
                engagement_level: "high".to_string(),
            },
            NetworkEventType::ExploitAttempt => DeceptionDecision::SpawnCustomDecoy {
                template: "vulnerable-target".to_string(),
                services: self.services_for_port(dest_port),
            },
            NetworkEventType::C2Beacon => DeceptionDecision::Monitor,
            _ => DeceptionDecision::RedirectToDecoy {
                decoy_type: "generic".to_string(),
                engagement_level: "medium".to_string(),
            },
        }
    }

    /// Determine appropriate decoy type based on targeted port.
    fn decoy_type_for_port(&self, port: u16) -> String {
        match port {
            22 => "linux-ssh-server".to_string(),
            23 => "telnet-device".to_string(),
            80 | 443 | 8080 | 8443 => "web-server".to_string(),
            3306 => "mysql-database".to_string(),
            5432 => "postgresql-database".to_string(),
            1433 => "mssql-database".to_string(),
            3389 => "windows-rdp-server".to_string(),
            445 | 139 => "windows-smb-server".to_string(),
            25 | 587 | 993 => "email-server".to_string(),
            21 => "ftp-server".to_string(),
            161 | 162 => "snmp-device".to_string(),
            502 => "scada-modbus".to_string(),
            102 => "scada-s7comm".to_string(),
            47808 => "scada-bacnet".to_string(),
            _ => "generic-service".to_string(),
        }
    }

    /// Determine services to expose based on port.
    fn services_for_port(&self, port: u16) -> Vec<u16> {
        match port {
            22 => vec![22, 80, 443],
            80 | 443 => vec![80, 443, 22, 3306],
            3306 | 5432 => vec![port, 22, 80],
            3389 => vec![3389, 445, 135, 139],
            _ => vec![port, 22, 80],
        }
    }

    /// Handle scan detection with appropriate response.
    fn handle_scan(&self, scan_type: &ScanType, dest_port: u16) -> DeceptionDecision {
        match scan_type {
            // Stealthy scans = sophisticated attacker. High interaction.
            ScanType::FinScan | ScanType::NullScan | ScanType::XmasScan => {
                DeceptionDecision::SpawnCustomDecoy {
                    template: "enterprise-network".to_string(),
                    services: vec![22, 80, 443, 3306, 3389, 445, 8080],
                }
            }
            // SYN scan = nmap default. Medium interaction.
            ScanType::SynScan => DeceptionDecision::RedirectToDecoy {
                decoy_type: self.decoy_type_for_port(dest_port),
                engagement_level: "medium".to_string(),
            },
            // Service scan = attacker looking for specific vulns.
            ScanType::ServiceScan => DeceptionDecision::SpawnCustomDecoy {
                template: "vulnerable-target".to_string(),
                services: self.services_for_port(dest_port),
            },
            _ => DeceptionDecision::RedirectToDecoy {
                decoy_type: "generic".to_string(),
                engagement_level: "low".to_string(),
            },
        }
    }

    /// Map network event to MITRE ATT&CK phase.
    pub fn map_attack_phase(&self, event_type: &NetworkEventType) -> AttackPhase {
        match event_type {
            NetworkEventType::PortScan(_) | NetworkEventType::DnsQuery => {
                AttackPhase::Reconnaissance
            }
            NetworkEventType::LoginAttempt | NetworkEventType::BruteForce => {
                AttackPhase::InitialAccess
            }
            NetworkEventType::ExploitAttempt => AttackPhase::Execution,
            NetworkEventType::CommandExecution => AttackPhase::Execution,
            NetworkEventType::LateralMovement => AttackPhase::LateralMovement,
            NetworkEventType::C2Beacon => AttackPhase::CommandAndControl,
            NetworkEventType::DataExfiltration => AttackPhase::Exfiltration,
            NetworkEventType::Unknown => AttackPhase::Reconnaissance,
        }
    }
}

impl Default for IntrusionClassifier {
    fn default() -> Self {
        Self::new()
    }
}
