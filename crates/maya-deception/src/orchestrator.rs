//! Deception Orchestrator — decides what, when, and how to deceive.
//!
//! This is the "brain" of the deception layer.
//! It observes attacker behavior (via events) and dynamically
//! creates the perfect illusion.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::Result;
use chrono::Utc;
use dashmap::{DashMap, DashSet};
use tracing::{info, warn};

use maya_core::config::DeceptionConfig;
use maya_core::events::{EventBus, MayaEvent};
use maya_core::types::*;

use crate::container::ContainerManager;
use crate::fakegen::FakeDataGenerator;
use crate::filesystem::FilesystemGenerator;
use crate::shell::GhostShell;

/// The Deception Orchestrator.
///
/// Manages the lifecycle of decoys, observes attacker actions,
/// and dynamically adapts the deception environment.
pub struct DeceptionOrchestrator {
    /// Configuration
    config: DeceptionConfig,
    /// Network CIDR to allocate believable decoy IPs from
    decoy_subnet: String,
    /// Cursor for deterministic sequential host selection
    ip_cursor: Arc<AtomicU32>,
    /// Currently leased decoy IP addresses
    leased_ips: Arc<DashSet<IpAddr>>,
    /// All active decoys
    decoys: Arc<DashMap<DecoyId, Decoy>>,
    /// Container manager (gVisor/Kata)
    containers: Arc<ContainerManager>,
    /// Fake data generator
    fake_gen: Arc<FakeDataGenerator>,
    /// Filesystem generator
    fs_gen: Arc<FilesystemGenerator>,
    /// Ghost shells (AI-powered fake terminals)
    shells: Arc<DashMap<SessionId, GhostShell>>,
    /// Session to decoy mapping for richer event metadata
    session_decoys: Arc<DashMap<SessionId, DecoyId>>,
    /// Event bus
    event_bus: Arc<EventBus>,
}

impl DeceptionOrchestrator {
    /// Create a new orchestrator.
    pub fn new(config: DeceptionConfig, decoy_subnet: String, event_bus: Arc<EventBus>) -> Self {
        info!(
            max_decoys = config.max_decoys,
            runtime = %config.container_runtime,
            auto_spawn = config.auto_spawn,
            decoy_subnet = %decoy_subnet,
            "🎭 Deception Orchestrator initialized"
        );

        Self {
            config,
            decoy_subnet,
            ip_cursor: Arc::new(AtomicU32::new(0)),
            leased_ips: Arc::new(DashSet::new()),
            decoys: Arc::new(DashMap::new()),
            containers: Arc::new(ContainerManager::new()),
            fake_gen: Arc::new(FakeDataGenerator::new()),
            fs_gen: Arc::new(FilesystemGenerator::new()),
            shells: Arc::new(DashMap::new()),
            session_decoys: Arc::new(DashMap::new()),
            event_bus,
        }
    }

    /// Spawn a new decoy based on the template.
    ///
    /// This is the core function. When the network engine detects an attacker,
    /// it calls this to create a believable fake environment.
    pub async fn spawn_decoy(
        &self,
        decoy_type: DecoyType,
        engagement_level: EngagementLevel,
        target_services: Vec<u16>,
    ) -> Result<DecoyId> {
        self.reclaim_expired_decoys().await;

        // Check limits
        let current = self.decoys.len() as u32;
        if current >= self.config.max_decoys {
            warn!(
                "⚠️  Decoy limit reached: {}/{}",
                current, self.config.max_decoys
            );
            // Evict oldest inactive decoy
            self.evict_oldest().await;
        }

        let decoy_id = DecoyId::new();
        let hostname = maya_core::utils::generate_hostname(match &decoy_type {
            DecoyType::LinuxServer => "linux",
            DecoyType::WindowsServer => "windows",
            DecoyType::ScadaDevice => "scada",
            DecoyType::NetworkDevice => "network",
            _ => "linux",
        });

        let ip_addr = self.allocate_decoy_ip();

        // Generate fake services for each requested port
        let services: Vec<FakeService> = target_services
            .iter()
            .map(|&port| {
                let (service_name, has_vuln, fake_cves) = match port {
                    22 => ("ssh", true, vec!["CVE-2023-38408".to_string()]),
                    80 => ("http", true, vec!["CVE-2024-23897".to_string()]),
                    443 => ("https", false, vec![]),
                    3306 => ("mysql", true, vec!["CVE-2023-22102".to_string()]),
                    5432 => ("postgresql", true, vec!["CVE-2023-5868".to_string()]),
                    3389 => ("rdp", true, vec!["CVE-2024-21351".to_string()]),
                    445 => ("smb", true, vec!["CVE-2024-26169".to_string()]),
                    502 => ("modbus", true, vec!["CVE-2023-0001".to_string()]),
                    _ => ("unknown", false, vec![]),
                };

                FakeService {
                    port,
                    protocol: Protocol::Tcp,
                    service_name: service_name.to_string(),
                    version_banner: maya_core::utils::generate_banner(service_name),
                    has_vuln,
                    fake_cves,
                }
            })
            .collect();

        let image = self.select_image_for_decoy(&decoy_type)?;
        let container_id = self
            .containers
            .spawn_container(image, &hostname, &target_services)
            .await?;

        let decoy = Decoy {
            id: decoy_id.clone(),
            decoy_type: decoy_type.clone(),
            status: DecoyStatus::Active,
            hostname: hostname.clone(),
            ip_addr,
            services: services.clone(),
            container_id: Some(container_id.clone()),
            created_at: Utc::now(),
            ttl_secs: self.config.decoy_ttl_secs,
            active_sessions: Vec::new(),
            engagement_level,
        };

        self.decoys.insert(decoy_id.clone(), decoy);
        self.leased_ips.insert(ip_addr);

        info!(
            "🎪 Decoy SPAWNED: {} ({:?}) at {} — {} services",
            hostname,
            decoy_type,
            ip_addr,
            services.len()
        );

        // Publish event
        let _ = self.event_bus.publish(MayaEvent::DecoySpawned {
            decoy_id: decoy_id.clone(),
            decoy_type,
            ip_addr,
            services: target_services,
        });

        Ok(decoy_id)
    }

    fn select_image_for_decoy(&self, decoy_type: &DecoyType) -> Result<&str> {
        if self.config.base_images.is_empty() {
            return Err(anyhow::anyhow!(
                "No base_images configured for deception containers"
            ));
        }

        let keyword = match decoy_type {
            DecoyType::LinuxServer => "linux",
            DecoyType::WindowsServer => "windows",
            DecoyType::DatabaseServer => "db",
            DecoyType::ScadaDevice => "scada",
            DecoyType::NetworkDevice => "network",
            _ => "linux",
        };

        Ok(self
            .config
            .base_images
            .iter()
            .find(|image| image.to_lowercase().contains(keyword))
            .unwrap_or(&self.config.base_images[0])
            .as_str())
    }

    fn allocate_decoy_ip(&self) -> IpAddr {
        let fallback_subnet = "10.13.37.0/24";

        for subnet in [self.decoy_subnet.as_str(), fallback_subnet] {
            if let Some(pool) = Ipv4Pool::from_cidr(subnet) {
                let max_probes = usize::try_from(pool.capacity.min(65_536)).unwrap_or(65_536);

                for _ in 0..max_probes {
                    let candidate = pool.next_ip(self.ip_cursor.fetch_add(1, Ordering::Relaxed));
                    let in_use = self.leased_ips.contains(&candidate)
                        || self.decoys.iter().any(|decoy| decoy.ip_addr == candidate);

                    if !in_use {
                        return candidate;
                    }
                }

                warn!(
                    subnet,
                    capacity = pool.capacity,
                    "Decoy IP pool exhausted for subnet, trying next fallback"
                );
            } else {
                warn!(subnet, "Invalid decoy subnet CIDR, trying next fallback");
            }
        }

        IpAddr::V4(Ipv4Addr::new(10, 13, 37, 254))
    }

    async fn reclaim_expired_decoys(&self) {
        let now = Utc::now();

        let expired_ids: Vec<DecoyId> = self
            .decoys
            .iter()
            .filter(|entry| {
                let decoy = entry.value();
                decoy.active_sessions.is_empty()
                    && now.signed_duration_since(decoy.created_at).num_seconds()
                        >= decoy.ttl_secs as i64
            })
            .map(|entry| entry.id.clone())
            .collect();

        for decoy_id in expired_ids {
            let _ = self
                .destroy_decoy_with_reason(&decoy_id, "ttl_expired")
                .await;
        }
    }

    /// Create a Ghost Shell for an attacker session.
    /// The Ghost Shell provides an AI-powered fake terminal
    /// that generates realistic responses.
    pub fn create_ghost_shell(&self, session_id: SessionId, decoy_id: &DecoyId) -> Result<()> {
        let decoy = self
            .decoys
            .get(decoy_id)
            .ok_or_else(|| anyhow::anyhow!("Decoy not found: {}", decoy_id))?;

        let shell = GhostShell::new(
            session_id.clone(),
            decoy.hostname.clone(),
            decoy.decoy_type.clone(),
            self.fake_gen.clone(),
            self.fs_gen.clone(),
        );

        self.shells.insert(session_id.clone(), shell);
        self.session_decoys
            .insert(session_id.clone(), decoy_id.clone());

        info!(
            "👻 Ghost Shell created for session {} on decoy {}",
            session_id, decoy_id
        );
        Ok(())
    }

    /// Process a command from an attacker in a Ghost Shell.
    /// Returns the fake response.
    pub async fn process_command(&self, session_id: &SessionId, command: &str) -> Result<String> {
        let shell = self
            .shells
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("No shell for session: {}", session_id))?;

        let response = shell.execute(command).await?;

        let decoy_id = self
            .session_decoys
            .get(session_id)
            .map(|entry| entry.value().clone())
            .unwrap_or_default();

        let decoy_type = self
            .decoys
            .get(&decoy_id)
            .map(|entry| entry.decoy_type.clone());

        let (command_label, severity) = classify_command(command);
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "response_length".to_string(),
            serde_json::Value::Number((response.len() as u64).into()),
        );
        metadata.insert(
            "contains_error".to_string(),
            serde_json::Value::Bool(response.to_lowercase().contains("error")),
        );

        // Log the interaction
        let _ = self.event_bus.publish(MayaEvent::CommandExecuted {
            session_id: session_id.clone(),
            command: command.to_string(),
            command_label: Some(command_label.to_string()),
            severity: Some(severity),
            decoy_id,
            decoy_type,
            metadata,
            timestamp: Utc::now(),
        });

        Ok(response)
    }

    /// Get total active decoy count.
    pub fn active_decoy_count(&self) -> usize {
        self.decoys.len()
    }

    /// Destroy a decoy.
    pub async fn destroy_decoy(&self, decoy_id: &DecoyId) -> Result<()> {
        self.destroy_decoy_with_reason(decoy_id, "manual").await
    }

    async fn destroy_decoy_with_reason(&self, decoy_id: &DecoyId, reason: &str) -> Result<()> {
        if let Some((_, mut decoy)) = self.decoys.remove(decoy_id) {
            decoy.status = DecoyStatus::Destroyed;

            if let Some(container_id) = decoy.container_id.as_ref()
                && let Err(err) = self.containers.destroy_container(container_id).await
            {
                warn!(
                    decoy = %decoy_id,
                    container = %container_id,
                    error = %err,
                    "Failed to destroy decoy container"
                );
            }

            self.leased_ips.remove(&decoy.ip_addr);
            info!("💀 Decoy {} destroyed", decoy_id);

            let _ = self.event_bus.publish(MayaEvent::DecoyDestroyed {
                decoy_id: decoy_id.clone(),
                reason: reason.to_string(),
            });
        }
        Ok(())
    }

    /// Evict the oldest inactive decoy to make room.
    async fn evict_oldest(&self) {
        let oldest = self
            .decoys
            .iter()
            .filter(|entry| entry.active_sessions.is_empty())
            .min_by_key(|entry| entry.created_at)
            .map(|entry| entry.id.clone());

        if let Some(decoy_id) = oldest {
            let _ = self.destroy_decoy(&decoy_id).await;
        }
    }

    /// Get all active decoys.
    pub fn list_decoys(&self) -> Vec<Decoy> {
        self.decoys
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
}

struct Ipv4Pool {
    network: u32,
    first_host: u32,
    capacity: u64,
}

impl Ipv4Pool {
    fn from_cidr(cidr: &str) -> Option<Self> {
        let mut parts = cidr.split('/');
        let base_str = parts.next()?;
        let prefix_str = parts.next()?;
        if parts.next().is_some() {
            return None;
        }

        let base_ip: Ipv4Addr = base_str.parse().ok()?;
        let prefix: u32 = prefix_str.parse().ok()?;
        if prefix > 32 {
            return None;
        }

        if prefix == 32 {
            return Some(Self {
                network: u32::from(base_ip),
                first_host: 0,
                capacity: 1,
            });
        }

        let host_bits = 32 - prefix;

        if host_bits == 32 {
            return Some(Self {
                network: 0,
                first_host: 1,
                capacity: (u32::MAX - 1) as u64,
            });
        }

        let mask = !((1u32 << host_bits) - 1);
        let network = u32::from(base_ip) & mask;
        let host_space = 1u64 << host_bits;

        let (first_host, capacity) = if host_bits == 1 {
            (0u32, 2u64)
        } else {
            (1u32, host_space - 2)
        };

        if capacity == 0 {
            return None;
        }

        Some(Self {
            network,
            first_host,
            capacity,
        })
    }

    fn next_ip(&self, cursor: u32) -> IpAddr {
        if self.capacity == 1 {
            return IpAddr::V4(Ipv4Addr::from(self.network));
        }

        let offset = (u64::from(cursor) % self.capacity) as u32;
        let host = self.first_host.saturating_add(offset);
        IpAddr::V4(Ipv4Addr::from(self.network | host))
    }
}

fn classify_command(command: &str) -> (&'static str, Severity) {
    let normalized = command.trim().to_lowercase();

    if normalized.starts_with("nmap") || normalized.contains("masscan") {
        return ("recon_scan", Severity::High);
    }
    if normalized.contains("whoami")
        || normalized.starts_with("id")
        || normalized.starts_with("uname")
        || normalized.starts_with("hostname")
    {
        return ("system_discovery", Severity::Low);
    }
    if normalized.contains("cat /etc/passwd")
        || normalized.contains("cat /etc/shadow")
        || normalized.contains("ls -la /root")
    {
        return ("credential_discovery", Severity::Medium);
    }
    if normalized.starts_with("mysql")
        || normalized.starts_with("sqlite3")
        || normalized.contains("select *")
    {
        return ("data_access", Severity::High);
    }
    if normalized.contains("wget")
        || normalized.contains("curl")
        || normalized.contains("scp")
        || normalized.contains("nc ")
    {
        return ("payload_transfer", Severity::Critical);
    }

    ("generic_command", Severity::Medium)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_pool_allocates_deterministically() {
        let pool = Ipv4Pool::from_cidr("10.13.37.0/24").expect("pool parse");

        let a = pool.next_ip(0);
        let b = pool.next_ip(1);
        let c = pool.next_ip(2);

        assert_eq!(a, IpAddr::V4(Ipv4Addr::new(10, 13, 37, 1)));
        assert_eq!(b, IpAddr::V4(Ipv4Addr::new(10, 13, 37, 2)));
        assert_eq!(c, IpAddr::V4(Ipv4Addr::new(10, 13, 37, 3)));
    }

    #[test]
    fn ipv4_pool_skips_network_and_broadcast_for_standard_subnet() {
        let pool = Ipv4Pool::from_cidr("192.168.50.0/24").expect("pool parse");
        assert_eq!(pool.capacity, 254);

        let first = pool.next_ip(0);
        let last = pool.next_ip(253);

        assert_eq!(first, IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1)));
        assert_eq!(last, IpAddr::V4(Ipv4Addr::new(192, 168, 50, 254)));
    }

    #[test]
    fn ipv4_pool_supports_single_host_cidr() {
        let pool = Ipv4Pool::from_cidr("10.13.37.42/32").expect("pool parse");
        assert_eq!(pool.capacity, 1);
        assert_eq!(pool.next_ip(0), IpAddr::V4(Ipv4Addr::new(10, 13, 37, 42)));
    }
}
