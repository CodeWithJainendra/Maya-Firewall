//! Configuration management for Project MAYA.
//!
//! Supports loading from TOML files, environment variables,
//! and runtime reconfiguration.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::MayaResult;

/// Root configuration for the entire MAYA system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MayaConfig {
    /// Global system settings
    pub system: SystemConfig,
    /// Network deception engine settings
    pub network: NetworkConfig,
    /// Deception orchestrator settings
    pub deception: DeceptionConfig,
    /// AI engine settings
    pub ai: AiConfig,
    /// Sandbox settings
    pub sandbox: SandboxConfig,
    /// Cryptography settings
    pub crypto: CryptoConfig,
    /// Consensus protocol settings
    pub consensus: ConsensusConfig,
    /// Profiler settings
    pub profiler: ProfilerConfig,
    /// Dashboard settings
    pub dashboard: DashboardConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    /// Unique node identifier
    pub node_id: String,
    /// Data storage directory
    pub data_dir: PathBuf,
    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,
    /// Maximum concurrent deception sessions
    pub max_sessions: u32,
    /// Enable/disable the entire deception grid
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Interface to attach XDP program to
    pub interface: String,
    /// Enforce fail-closed behavior: startup fails if XDP cannot attach
    #[serde(default)]
    pub xdp_strict: bool,
    /// Ports to monitor for incoming connections
    pub monitored_ports: Vec<u16>,
    /// Maximum packets per second to process
    pub max_pps: u64,
    /// Enable raw packet capture
    pub packet_capture: bool,
    /// Network CIDR range for fake hosts
    pub decoy_subnet: String,
    /// DNS spoofing configuration
    pub dns_intercept: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionConfig {
    /// Maximum number of concurrent decoy containers
    pub max_decoys: u32,
    /// Container runtime: "gvisor" or "kata"
    pub container_runtime: String,
    /// Base images for decoy systems
    pub base_images: Vec<String>,
    /// Auto-spawn decoys on scan detection
    pub auto_spawn: bool,
    /// Decoy TTL in seconds (auto-destroy after this)
    pub decoy_ttl_secs: u64,
    /// Milliseconds to spawn a new decoy (target: < 100ms)
    pub spawn_budget_ms: u64,
    /// Fake data generation seed (for reproducible deception)
    pub fake_data_seed: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// LLM backend URL (local Ollama, vLLM, or remote)
    pub llm_endpoint: String,
    /// Model name (e.g., "llama3:8b-instruct")
    pub model_name: String,
    /// Maximum context window size
    pub max_context_tokens: u64,
    /// Temperature for generation (lower = more deterministic)
    pub temperature: f32,
    /// Enable RAG for session context retention
    pub rag_enabled: bool,
    /// System prompt template path
    pub system_prompt_path: Option<PathBuf>,
    /// Response timeout in seconds
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// WASM runtime: "wasmtime" or "wasmer"
    pub runtime: String,
    /// Maximum execution time for sandboxed code (seconds)
    pub max_exec_time_secs: u64,
    /// Maximum memory for sandboxed execution (MB)
    pub max_memory_mb: u64,
    /// Directory for extracted malware samples
    pub samples_dir: PathBuf,
    /// Enable automated C2 beacon extraction
    pub c2_extraction: bool,
    /// Enable entropy analysis for crypto detection
    pub entropy_analysis: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Post-quantum algorithm: "kyber768" or "kyber1024"
    pub kem_algorithm: String,
    /// Signature algorithm: "dilithium3" or "ed25519_hybrid"
    pub sig_algorithm: String,
    /// Key rotation interval in hours
    pub key_rotation_hours: u32,
    /// Enable hybrid classical+PQ mode
    pub hybrid_mode: bool,
    /// Path to node's private key
    pub private_key_path: PathBuf,
    /// Path to node's certificate
    pub cert_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Consensus protocol: "hotstuff"
    pub protocol: String,
    /// Peer nodes in the deception grid
    pub peers: Vec<PeerConfig>,
    /// Minimum quorum size
    pub quorum_size: u32,
    /// View timeout in milliseconds
    pub view_timeout_ms: u64,
    /// Maximum batch size for proposals
    pub max_batch_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Peer node ID
    pub node_id: String,
    /// Peer address (host:port)
    pub address: String,
    /// Peer's public key (hex-encoded)
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilerConfig {
    /// Enable keystroke dynamics analysis
    pub keystroke_analysis: bool,
    /// Enable mouse movement tracking
    pub mouse_tracking: bool,
    /// TTP database path (MITRE ATT&CK mappings)
    pub ttp_db_path: PathBuf,
    /// Minimum confidence for APT attribution (0.0 - 1.0)
    pub attribution_threshold: f64,
    /// Enable real-time CERT-In reporting
    pub cert_in_reporting: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Dashboard HTTP listen address
    pub listen_addr: String,
    /// Dashboard HTTP port
    pub listen_port: u16,
    /// Enable WebSocket real-time updates
    pub websocket_enabled: bool,
    /// Allowed browser origins for dashboard API access. Empty disables CORS.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Optional dashboard bearer token. Mandatory when binding publicly.
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Static assets directory
    pub assets_dir: PathBuf,
}

impl MayaConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> MayaResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::MayaError::Config(format!("Failed to read config: {e}")))?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| crate::error::MayaError::Config(format!("Invalid TOML: {e}")))?;
        Ok(config)
    }

    /// Create a default configuration for development/testing.
    pub fn default_dev() -> Self {
        Self {
            system: SystemConfig {
                node_id: "maya-dev-001".to_string(),
                data_dir: PathBuf::from("/tmp/maya-data"),
                log_level: "debug".to_string(),
                max_sessions: 100,
                enabled: true,
            },
            network: NetworkConfig {
                interface: "eth0".to_string(),
                xdp_strict: false,
                monitored_ports: vec![22, 80, 443, 3306, 5432, 8080, 8443, 3389],
                max_pps: 100_000,
                packet_capture: true,
                decoy_subnet: "10.13.37.0/24".to_string(),
                dns_intercept: true,
            },
            deception: DeceptionConfig {
                max_decoys: 500,
                container_runtime: "gvisor".to_string(),
                base_images: vec![
                    "maya/linux-decoy:latest".to_string(),
                    "maya/windows-decoy:latest".to_string(),
                    "maya/db-decoy:latest".to_string(),
                    "maya/scada-decoy:latest".to_string(),
                ],
                auto_spawn: true,
                decoy_ttl_secs: 3600,
                spawn_budget_ms: 50,
                fake_data_seed: None,
            },
            ai: AiConfig {
                llm_endpoint: "http://127.0.0.1:11434".to_string(),
                model_name: "llama3:8b-instruct".to_string(),
                max_context_tokens: 8192,
                temperature: 0.3,
                rag_enabled: true,
                system_prompt_path: None,
                timeout_secs: 30,
            },
            sandbox: SandboxConfig {
                runtime: "wasmtime".to_string(),
                max_exec_time_secs: 60,
                max_memory_mb: 256,
                samples_dir: PathBuf::from("/tmp/maya-data/samples"),
                c2_extraction: true,
                entropy_analysis: true,
            },
            crypto: CryptoConfig {
                kem_algorithm: "kyber768".to_string(),
                sig_algorithm: "ed25519_hybrid".to_string(),
                key_rotation_hours: 24,
                hybrid_mode: true,
                private_key_path: PathBuf::from("/tmp/maya-data/keys/node.key"),
                cert_path: PathBuf::from("/tmp/maya-data/keys/node.cert"),
            },
            consensus: ConsensusConfig {
                protocol: "hotstuff".to_string(),
                peers: vec![],
                quorum_size: 1,
                view_timeout_ms: 5000,
                max_batch_size: 100,
            },
            profiler: ProfilerConfig {
                keystroke_analysis: true,
                mouse_tracking: false,
                ttp_db_path: PathBuf::from("/tmp/maya-data/ttp.db"),
                attribution_threshold: 0.75,
                cert_in_reporting: false,
            },
            dashboard: DashboardConfig {
                listen_addr: "127.0.0.1".to_string(),
                listen_port: 8900,
                websocket_enabled: true,
                allowed_origins: vec![
                    "http://127.0.0.1:8900".to_string(),
                    "http://localhost:8900".to_string(),
                    "http://127.0.0.1:5173".to_string(),
                    "http://localhost:5173".to_string(),
                ],
                auth_token: Some("maya-dev-token".to_string()),
                assets_dir: PathBuf::from("./dashboard/dist"),
            },
        }
    }

    /// Create a production-safe baseline configuration template.
    ///
    /// This template intentionally avoids fragile dev-only defaults such as
    /// single-node quorum and `/tmp` persistence paths.
    pub fn default_prod() -> Self {
        Self {
            system: SystemConfig {
                node_id: "maya-node-001".to_string(),
                data_dir: PathBuf::from("/var/lib/maya"),
                log_level: "info".to_string(),
                max_sessions: 1000,
                enabled: true,
            },
            network: NetworkConfig {
                interface: "eth0".to_string(),
                xdp_strict: true,
                monitored_ports: vec![22, 80, 443, 3306, 5432, 8080, 8443, 3389],
                max_pps: 100_000,
                packet_capture: true,
                decoy_subnet: "10.13.37.0/24".to_string(),
                dns_intercept: true,
            },
            deception: DeceptionConfig {
                max_decoys: 500,
                container_runtime: "gvisor".to_string(),
                base_images: vec![
                    "maya/linux-decoy:latest".to_string(),
                    "maya/windows-decoy:latest".to_string(),
                    "maya/db-decoy:latest".to_string(),
                    "maya/scada-decoy:latest".to_string(),
                ],
                auto_spawn: true,
                decoy_ttl_secs: 3600,
                spawn_budget_ms: 50,
                fake_data_seed: None,
            },
            ai: AiConfig {
                llm_endpoint: "http://127.0.0.1:11434".to_string(),
                model_name: "llama3:8b-instruct".to_string(),
                max_context_tokens: 8192,
                temperature: 0.2,
                rag_enabled: true,
                system_prompt_path: None,
                timeout_secs: 20,
            },
            sandbox: SandboxConfig {
                runtime: "wasmtime".to_string(),
                max_exec_time_secs: 60,
                max_memory_mb: 256,
                samples_dir: PathBuf::from("/var/lib/maya/samples"),
                c2_extraction: true,
                entropy_analysis: true,
            },
            crypto: CryptoConfig {
                kem_algorithm: "kyber768".to_string(),
                sig_algorithm: "ed25519_hybrid".to_string(),
                key_rotation_hours: 24,
                hybrid_mode: true,
                private_key_path: PathBuf::from("/etc/maya/keys/node.key"),
                cert_path: PathBuf::from("/etc/maya/keys/node.cert"),
            },
            consensus: ConsensusConfig {
                protocol: "hotstuff".to_string(),
                peers: vec![
                    PeerConfig {
                        node_id: "maya-node-002".to_string(),
                        address: "10.0.0.12:7000".to_string(),
                        public_key: "REPLACE_WITH_PEER_PUBLIC_KEY_HEX".to_string(),
                    },
                    PeerConfig {
                        node_id: "maya-node-003".to_string(),
                        address: "10.0.0.13:7000".to_string(),
                        public_key: "REPLACE_WITH_PEER_PUBLIC_KEY_HEX".to_string(),
                    },
                ],
                quorum_size: 2,
                view_timeout_ms: 5000,
                max_batch_size: 100,
            },
            profiler: ProfilerConfig {
                keystroke_analysis: true,
                mouse_tracking: false,
                ttp_db_path: PathBuf::from("/var/lib/maya/ttp.db"),
                attribution_threshold: 0.75,
                cert_in_reporting: false,
            },
            dashboard: DashboardConfig {
                listen_addr: "0.0.0.0".to_string(),
                listen_port: 8900,
                websocket_enabled: true,
                allowed_origins: vec!["https://soc.example.com".to_string()],
                auth_token: Some("CHANGE_ME_STRONG_DASHBOARD_TOKEN".to_string()),
                assets_dir: PathBuf::from("./dashboard/dist"),
            },
        }
    }

    /// Serialize configuration to TOML string.
    pub fn to_toml(&self) -> MayaResult<String> {
        toml::to_string_pretty(self)
            .map_err(|e| crate::error::MayaError::Config(format!("Serialization error: {e}")))
    }

    /// Validate that a non-development config does not contain known unsafe defaults.
    pub fn validate_production_safety(&self) -> MayaResult<()> {
        if !self.network.xdp_strict {
            return Err(crate::error::MayaError::Config(
                "network.xdp_strict must be true for non-dev runs".to_string(),
            ));
        }

        if self.consensus.quorum_size < 2 {
            return Err(crate::error::MayaError::Config(
                "consensus.quorum_size must be >= 2 for non-dev runs".to_string(),
            ));
        }

        if self.consensus.peers.is_empty() {
            return Err(crate::error::MayaError::Config(
                "consensus.peers cannot be empty for non-dev runs".to_string(),
            ));
        }

        if self
            .consensus
            .peers
            .iter()
            .any(|peer| peer.public_key.contains("REPLACE_WITH_PEER_PUBLIC_KEY_HEX"))
        {
            return Err(crate::error::MayaError::Config(
                "consensus.peers contains placeholder public keys".to_string(),
            ));
        }

        let token = self.dashboard.auth_token.as_deref().unwrap_or("").trim();
        if token.is_empty() {
            return Err(crate::error::MayaError::Config(
                "dashboard.auth_token must be set for non-dev runs".to_string(),
            ));
        }

        if token.eq("maya-dev-token") || token.contains("CHANGE_ME") {
            return Err(crate::error::MayaError::Config(
                "dashboard.auth_token contains an unsafe default value".to_string(),
            ));
        }

        Ok(())
    }
}
