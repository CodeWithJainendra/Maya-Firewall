//! Core data types for Project MAYA.
//!
//! These types form the vocabulary of the entire deception grid.
//! Every subsystem speaks in terms of these primitives.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════
// SESSION & ATTACKER TYPES
// ═══════════════════════════════════════════════════════════════════

/// Unique identifier for a deception session.
/// One attacker interaction = one session.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SES-{}", &self.0.to_string()[..8])
    }
}

/// Represents a tracked attacker within the MAYA grid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attacker {
    /// Unique attacker identifier
    pub id: Uuid,
    /// Source IP address
    pub source_ip: IpAddr,
    /// Source port
    pub source_port: u16,
    /// OS fingerprint (from TCP/IP stack analysis)
    pub os_fingerprint: Option<OsFingerprint>,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Last activity timestamp
    pub last_seen: DateTime<Utc>,
    /// Threat level assessment (0.0 - 1.0)
    pub threat_level: f64,
    /// Suspected APT group attribution
    pub attribution: Option<Attribution>,
    /// All sessions associated with this attacker
    pub session_ids: Vec<SessionId>,
    /// Attacker's behavioral fingerprint
    pub behavior_fingerprint: Option<BehaviorFingerprint>,
    /// Current phase of attack (MITRE ATT&CK)
    pub attack_phase: AttackPhase,
}

/// MITRE ATT&CK Kill Chain phases.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttackPhase {
    /// Initial reconnaissance / scanning
    Reconnaissance,
    /// Attempting to gain access
    InitialAccess,
    /// Running malicious code
    Execution,
    /// Maintaining foothold
    Persistence,
    /// Elevating privileges
    PrivilegeEscalation,
    /// Avoiding detection
    DefenseEvasion,
    /// Stealing credentials
    CredentialAccess,
    /// Exploring the network
    Discovery,
    /// Moving through the network
    LateralMovement,
    /// Gathering target data
    Collection,
    /// Command and control comms
    CommandAndControl,
    /// Stealing data
    Exfiltration,
    /// Destroying or manipulating
    Impact,
}

impl std::fmt::Display for AttackPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reconnaissance => write!(f, "TA0043: Reconnaissance"),
            Self::InitialAccess => write!(f, "TA0001: Initial Access"),
            Self::Execution => write!(f, "TA0002: Execution"),
            Self::Persistence => write!(f, "TA0003: Persistence"),
            Self::PrivilegeEscalation => write!(f, "TA0004: Privilege Escalation"),
            Self::DefenseEvasion => write!(f, "TA0005: Defense Evasion"),
            Self::CredentialAccess => write!(f, "TA0006: Credential Access"),
            Self::Discovery => write!(f, "TA0007: Discovery"),
            Self::LateralMovement => write!(f, "TA0008: Lateral Movement"),
            Self::Collection => write!(f, "TA0009: Collection"),
            Self::CommandAndControl => write!(f, "TA0011: Command and Control"),
            Self::Exfiltration => write!(f, "TA0010: Exfiltration"),
            Self::Impact => write!(f, "TA0040: Impact"),
        }
    }
}

/// Operating System fingerprint derived from network behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprint {
    pub os_family: String,
    pub os_version: Option<String>,
    pub tcp_window_size: u16,
    pub ttl: u8,
    pub mss: u16,
    pub confidence: f64,
}

/// APT group attribution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribution {
    /// Suspected group name (e.g., "APT41", "Lazarus", "SideWinder")
    pub group_name: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Matching TTPs from MITRE ATT&CK
    pub matching_ttps: Vec<String>,
    /// Country of origin (suspected)
    pub suspected_origin: Option<String>,
    /// Evidence chain
    pub evidence: Vec<String>,
}

/// Behavioral fingerprint of an attacker — their "digital DNA."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorFingerprint {
    /// Average keystroke interval in milliseconds
    pub avg_keystroke_interval_ms: f64,
    /// Keystroke interval variance
    pub keystroke_variance: f64,
    /// Typing speed (chars/minute)
    pub typing_speed_cpm: f64,
    /// Common command sequences
    pub command_patterns: Vec<String>,
    /// Working hours pattern (UTC)
    pub active_hours: Vec<u8>,
    /// Language indicators (from typos, locale settings)
    pub language_indicators: Vec<String>,
    /// Tool preferences (metasploit, cobalt strike, etc.)
    pub tool_signatures: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════
// DECOY & DECEPTION TYPES
// ═══════════════════════════════════════════════════════════════════

/// Unique identifier for a decoy instance.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecoyId(pub Uuid);

impl DecoyId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for DecoyId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DecoyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DCY-{}", &self.0.to_string()[..8])
    }
}

/// Represents a single decoy in the deception grid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decoy {
    /// Unique decoy ID
    pub id: DecoyId,
    /// Type of decoy
    pub decoy_type: DecoyType,
    /// Decoy status
    pub status: DecoyStatus,
    /// Fake hostname
    pub hostname: String,
    /// Fake IP address assigned
    pub ip_addr: IpAddr,
    /// Open ports (service, version)
    pub services: Vec<FakeService>,
    /// Container ID (if container-backed)
    pub container_id: Option<String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Time-to-live (auto-destroy)
    pub ttl_secs: u64,
    /// Current attacker sessions interacting with this decoy
    pub active_sessions: Vec<SessionId>,
    /// Interaction engagement level
    pub engagement_level: EngagementLevel,
}

/// Type of decoy system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DecoyType {
    /// Full Linux server with SSH, HTTP, etc.
    LinuxServer,
    /// Windows Server / Desktop emulation
    WindowsServer,
    /// Database server (MySQL, PostgreSQL, MSSQL)
    DatabaseServer,
    /// Email server (SMTP, IMAP)
    EmailServer,
    /// File server (SMB, NFS)
    FileServer,
    /// SCADA/ICS device (PLC, RTU, HMI)
    ScadaDevice,
    /// Network equipment (Router, Switch, Firewall)
    NetworkDevice,
    /// Active Directory / Domain Controller
    DomainController,
    /// Web Application server
    WebApplication,
    /// IoT device
    IoTDevice,
    /// Custom decoy type
    Custom(String),
}

/// Status of a decoy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DecoyStatus {
    /// Being spawned
    Spawning,
    /// Ready and waiting
    Active,
    /// Currently engaged with attacker
    Engaged,
    /// Being destroyed
    Destroying,
    /// Destroyed / cleaned up
    Destroyed,
    /// Error state
    Error(String),
}

/// How deeply the decoy engages with the attacker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EngagementLevel {
    /// Low interaction — only banners and basic responses
    Low,
    /// Medium — simulated services, basic command execution
    Medium,
    /// High — full OS emulation with AI-generated responses
    High,
    /// Ultra — complete environment with lateral movement paths
    Ultra,
}

/// A fake service running on a decoy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeService {
    /// Port number
    pub port: u16,
    /// Protocol (TCP/UDP)
    pub protocol: Protocol,
    /// Service name
    pub service_name: String,
    /// Service version banner
    pub version_banner: String,
    /// Whether the service has known "vulnerabilities" (to lure attackers)
    pub has_vuln: bool,
    /// CVE IDs of fake vulnerabilities
    pub fake_cves: Vec<String>,
}

/// Network protocol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

// ═══════════════════════════════════════════════════════════════════
// NETWORK & PACKET TYPES
// ═══════════════════════════════════════════════════════════════════

/// Represents a captured network event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: NetworkEventType,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub dest_ip: IpAddr,
    pub dest_port: u16,
    pub protocol: Protocol,
    pub payload_size: usize,
    pub payload_hash: Option<String>,
}

/// Types of network events MAYA tracks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkEventType {
    /// Port scan detected (SYN, ACK, FIN, XMAS, NULL)
    PortScan(ScanType),
    /// Login attempt (SSH, RDP, FTP, etc.)
    LoginAttempt,
    /// Brute force detected
    BruteForce,
    /// Exploit attempt
    ExploitAttempt,
    /// Command execution
    CommandExecution,
    /// Data exfiltration attempt
    DataExfiltration,
    /// C2 beacon
    C2Beacon,
    /// Lateral movement
    LateralMovement,
    /// DNS query
    DnsQuery,
    /// Unknown/other
    Unknown,
}

/// Port scan types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanType {
    SynScan,
    AckScan,
    FinScan,
    XmasScan,
    NullScan,
    UdpScan,
    ConnectScan,
    ServiceScan,
}

// ═══════════════════════════════════════════════════════════════════
// MALWARE & SANDBOX TYPES
// ═══════════════════════════════════════════════════════════════════

/// Represents an analyzed malware sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareSample {
    pub id: Uuid,
    pub sha256: String,
    pub md5: String,
    pub file_size: u64,
    pub file_type: String,
    pub captured_at: DateTime<Utc>,
    pub source_session: SessionId,
    pub analysis: Option<MalwareAnalysis>,
}

/// Results of automated malware analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareAnalysis {
    /// Malware family classification
    pub family: Option<String>,
    /// Detected capabilities
    pub capabilities: Vec<String>,
    /// Extracted C2 server addresses
    pub c2_servers: Vec<String>,
    /// Encryption keys found
    pub extracted_keys: Vec<String>,
    /// Network IOCs (Indicators of Compromise)
    pub network_iocs: Vec<String>,
    /// File system IOCs
    pub file_iocs: Vec<String>,
    /// Registry IOCs (Windows)
    pub registry_iocs: Vec<String>,
    /// YARA rule matches
    pub yara_matches: Vec<String>,
    /// Entropy score (0.0 - 8.0, high = packed/encrypted)
    pub entropy: f64,
    /// Strings extracted
    pub interesting_strings: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════
// ALERT & INTELLIGENCE TYPES
// ═══════════════════════════════════════════════════════════════════

/// Alert severity levels.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "🔴 CRITICAL"),
        }
    }
}

/// A SOC alert generated by MAYA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub session_id: SessionId,
    pub attacker_ip: IpAddr,
    pub decoy_id: Option<DecoyId>,
    pub attack_phase: AttackPhase,
    pub mitre_techniques: Vec<String>,
    pub evidence: HashMap<String, serde_json::Value>,
    pub recommended_action: String,
}

// ═══════════════════════════════════════════════════════════════════
// CONSENSUS TYPES
// ═══════════════════════════════════════════════════════════════════

/// A proposal in the HotStuff consensus protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProposal {
    pub id: Uuid,
    pub view_number: u64,
    pub proposer: String,
    pub payload: ConsensusPayload,
    pub parent_hash: String,
    pub timestamp: DateTime<Utc>,
}

/// Payload types for consensus proposals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusPayload {
    /// Spawn a new decoy across the grid
    SpawnDecoy(DecoyId, DecoyType),
    /// Destroy a decoy
    DestroyDecoy(DecoyId),
    /// Update threat intelligence
    ThreatIntelUpdate(Vec<String>),
    /// Redistribute attacker traffic
    TrafficRedirect {
        session_id: SessionId,
        target_node: String,
    },
    /// Synchronize deception state
    StateSync(HashMap<String, serde_json::Value>),
}
