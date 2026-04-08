//! Container Management for MAYA decoys.
//! Manages gVisor/Kata container lifecycle for high-isolation decoys.

use anyhow::Result;
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
};
use bollard::models::{HostConfig, PortBinding};
use std::collections::HashMap;
use tracing::{debug, info};

/// Container runtime types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerRuntime {
    /// Google gVisor — application kernel for sandboxing
    GVisor,
    /// Kata Containers — lightweight VMs
    Kata,
    /// Standard Docker (fallback)
    Docker,
}

/// Manages container lifecycle for decoys.
pub struct ContainerManager {
    runtime: ContainerRuntime,
}

impl ContainerManager {
    pub fn new() -> Self {
        Self {
            runtime: ContainerRuntime::Docker, // Default, auto-detect later
        }
    }

    /// Detect available container runtime.
    pub async fn detect_runtime(&mut self) -> Result<ContainerRuntime> {
        // Check for gVisor (runsc)
        if std::process::Command::new("runsc")
            .arg("--version")
            .output()
            .is_ok()
        {
            info!("🛡️  gVisor (runsc) detected — using hardware-level isolation");
            self.runtime = ContainerRuntime::GVisor;
            return Ok(ContainerRuntime::GVisor);
        }

        // Check for Kata
        if std::process::Command::new("kata-runtime")
            .arg("--version")
            .output()
            .is_ok()
        {
            info!("🛡️  Kata Containers detected — using micro-VM isolation");
            self.runtime = ContainerRuntime::Kata;
            return Ok(ContainerRuntime::Kata);
        }

        // Fallback to Docker
        if std::process::Command::new("docker")
            .arg("--version")
            .output()
            .is_ok()
        {
            info!("🐳 Docker detected — using standard container isolation");
            self.runtime = ContainerRuntime::Docker;
            return Ok(ContainerRuntime::Docker);
        }

        Err(anyhow::anyhow!("No container runtime found"))
    }

    /// Spawn a container for a decoy.
    pub async fn spawn_container(
        &self,
        image: &str,
        hostname: &str,
        ports: &[u16],
    ) -> Result<String> {
        let effective_runtime = self.runtime_for_spawn();

        let runtime_name = match effective_runtime {
            ContainerRuntime::GVisor => Some("runsc".to_string()),
            ContainerRuntime::Kata => Some("kata-runtime".to_string()),
            ContainerRuntime::Docker => None,
        };

        info!(
            "🚀 Spawning container: image={}, hostname={}, runtime={:?}, ports={:?}",
            image, hostname, effective_runtime, ports
        );

        let docker = Docker::connect_with_local_defaults()?;

        let port_bindings: HashMap<String, Option<Vec<PortBinding>>> = ports
            .iter()
            .map(|port| {
                (
                    format!("{port}/tcp"),
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_string()),
                        host_port: Some(port.to_string()),
                    }]),
                )
            })
            .collect();

        let exposed_ports: HashMap<String, HashMap<(), ()>> = ports
            .iter()
            .map(|port| (format!("{port}/tcp"), HashMap::new()))
            .collect();

        let container_name = format!(
            "maya-{}-{}",
            sanitize_container_name(hostname),
            uuid::Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("0000")
        );

        let config = Config {
            image: Some(image.to_string()),
            hostname: Some(hostname.to_string()),
            exposed_ports: Some(exposed_ports),
            host_config: Some(HostConfig {
                runtime: runtime_name,
                port_bindings: Some(port_bindings),
                ..Default::default()
            }),
            ..Default::default()
        };

        let response = docker
            .create_container(
                Some(CreateContainerOptions {
                    name: container_name,
                    platform: None,
                }),
                config,
            )
            .await?;

        docker
            .start_container(&response.id, None::<StartContainerOptions<String>>)
            .await?;

        let container_id = response.id;

        debug!("📦 Container spawned: {}", container_id);
        Ok(container_id)
    }

    /// Destroy a container.
    pub async fn destroy_container(&self, container_id: &str) -> Result<()> {
        info!("💥 Destroying container: {}", container_id);

        let docker = Docker::connect_with_local_defaults()?;
        docker
            .remove_container(
                container_id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await?;

        Ok(())
    }

    /// Get container runtime info.
    pub fn runtime(&self) -> &ContainerRuntime {
        &self.runtime
    }
}

impl Default for ContainerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ContainerManager {
    fn runtime_for_spawn(&self) -> ContainerRuntime {
        if std::process::Command::new("runsc")
            .arg("--version")
            .output()
            .is_ok()
        {
            return ContainerRuntime::GVisor;
        }
        if std::process::Command::new("kata-runtime")
            .arg("--version")
            .output()
            .is_ok()
        {
            return ContainerRuntime::Kata;
        }
        self.runtime.clone()
    }
}

fn sanitize_container_name(hostname: &str) -> String {
    hostname
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect()
}
