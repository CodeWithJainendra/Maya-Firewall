//! XDP/eBPF ingress integration for MAYA.
//! Provides a safe runtime path that attempts kernel attach when available,
//! while degrading cleanly to dry-run mode on developer machines.

use std::path::{Path, PathBuf};

#[cfg(feature = "xdp")]
use anyhow::Context;
use anyhow::{Result, anyhow};
use nix::net::if_::if_nametoindex;
use serde::{Deserialize, Serialize};
#[cfg(feature = "xdp")]
use tracing::info;
use tracing::warn;

use maya_core::config::NetworkConfig;

/// Runtime status of the XDP ingress path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum XdpMode {
    /// Real XDP program attached to the configured interface.
    Attached,
    /// Kernel attach was skipped, but userspace packet ingestion remains active.
    DryRun,
    /// Interface or system capability is missing.
    Unsupported,
}

impl std::fmt::Display for XdpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Attached => write!(f, "attached"),
            Self::DryRun => write!(f, "dry-run"),
            Self::Unsupported => write!(f, "unsupported"),
        }
    }
}

/// Captures the outcome of XDP initialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdpAttachResult {
    pub mode: XdpMode,
    pub interface: String,
    pub ifindex: Option<u32>,
    pub object_path: Option<PathBuf>,
    pub details: String,
}

/// Runtime manager for MAYA's XDP ingress layer.
pub struct XdpManager {
    interface: String,
    strict_mode: bool,
    monitored_ports: Vec<u16>,
}

impl XdpManager {
    pub fn new(config: &NetworkConfig) -> Self {
        Self {
            interface: config.interface.clone(),
            strict_mode: config.xdp_strict,
            monitored_ports: config.monitored_ports.clone(),
        }
    }

    /// Attempt to attach an XDP program to the configured interface.
    pub async fn initialize(&self) -> Result<XdpAttachResult> {
        let ifindex = match if_nametoindex(self.interface.as_str()) {
            Ok(idx) => Some(idx),
            Err(err) => {
                return self.enforce_mode(XdpAttachResult {
                    mode: XdpMode::Unsupported,
                    interface: self.interface.clone(),
                    ifindex: None,
                    object_path: None,
                    details: format!("interface lookup failed: {err}"),
                });
            }
        };

        if unsafe { nix::libc::geteuid() } != 0 {
            return self.enforce_mode(XdpAttachResult {
                mode: XdpMode::DryRun,
                interface: self.interface.clone(),
                ifindex,
                object_path: self.find_bpf_object(),
                details: "running without CAP_BPF/CAP_NET_ADMIN; staying in userspace dry-run mode"
                    .to_string(),
            });
        }

        let Some(object_path) = self.find_bpf_object() else {
            return self.enforce_mode(XdpAttachResult {
                mode: XdpMode::DryRun,
                interface: self.interface.clone(),
                ifindex,
                object_path: None,
                details: format!(
                    "no compiled eBPF object found; expected one of: {}",
                    self.candidate_bpf_objects()
                        .into_iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        };

        self.attach_program(&object_path, ifindex.unwrap_or_default())
            .await
            .map(|details| XdpAttachResult {
                mode: XdpMode::Attached,
                interface: self.interface.clone(),
                ifindex,
                object_path: Some(object_path.clone()),
                details,
            })
            .or_else(|err| {
                warn!(
                    interface = %self.interface,
                    error = %err,
                    "XDP attach failed, falling back to dry-run mode"
                );
                Ok(XdpAttachResult {
                    mode: XdpMode::DryRun,
                    interface: self.interface.clone(),
                    ifindex,
                    object_path: Some(object_path),
                    details: format!("kernel attach failed: {err}"),
                })
            })
            .and_then(|result| self.enforce_mode(result))
    }

    fn enforce_mode(&self, result: XdpAttachResult) -> Result<XdpAttachResult> {
        if self.strict_mode && result.mode != XdpMode::Attached {
            return Err(anyhow!(
                "XDP strict mode is enabled for interface {} but ingress is {} ({})",
                self.interface,
                result.mode,
                result.details
            ));
        }

        Ok(result)
    }

    pub fn monitored_ports(&self) -> &[u16] {
        &self.monitored_ports
    }

    fn candidate_bpf_objects(&self) -> Vec<PathBuf> {
        vec![
            PathBuf::from("target/bpfel-unknown-none/debug/maya-network-ebpf"),
            PathBuf::from("target/bpfel-unknown-none/release/maya-network-ebpf"),
            PathBuf::from("target/ebpf/bpfel-unknown-none/debug/maya-network-ebpf"),
            PathBuf::from("target/ebpf/bpfel-unknown-none/release/maya-network-ebpf"),
            PathBuf::from(
                "crates/maya-network-ebpf/target/bpfel-unknown-none/debug/maya-network-ebpf",
            ),
            PathBuf::from(
                "crates/maya-network-ebpf/target/bpfel-unknown-none/release/maya-network-ebpf",
            ),
            PathBuf::from("target/bpfel-unknown-none/debug/maya_ingress"),
            PathBuf::from("target/bpfel-unknown-none/release/maya_ingress"),
        ]
    }

    fn find_bpf_object(&self) -> Option<PathBuf> {
        self.candidate_bpf_objects()
            .into_iter()
            .find(|path| path.exists() && path.is_file())
    }

    #[cfg(feature = "xdp")]
    async fn attach_program(&self, object_path: &Path, ifindex: u32) -> Result<String> {
        use aya::Ebpf;
        use aya::programs::{Xdp, XdpFlags};

        let bytes = std::fs::read(object_path)
            .with_context(|| format!("failed to read eBPF object {}", object_path.display()))?;
        let mut bpf = Ebpf::load(&bytes).context("failed to load eBPF object")?;
        let program: &mut Xdp = bpf
            .program_mut("maya_ingress")
            .context("missing `maya_ingress` XDP program symbol")?
            .try_into()
            .context("program is not an XDP program")?;

        program.load().context("failed to load XDP program")?;
        program
            .attach(&self.interface, XdpFlags::default())
            .context("failed to attach XDP program")?;

        info!(
            interface = %self.interface,
            ifindex,
            object = %object_path.display(),
            ports = ?self.monitored_ports,
            "🧬 XDP ingress attached"
        );

        // Keep the object alive for process lifetime by intentionally leaking it.
        let _leaked = Box::leak(Box::new(bpf));

        Ok(format!(
            "attached `maya_ingress` to {} (ifindex {}) for monitored ports {:?}",
            self.interface, ifindex, self.monitored_ports
        ))
    }

    #[cfg(not(feature = "xdp"))]
    async fn attach_program(&self, object_path: &Path, ifindex: u32) -> Result<String> {
        let _ = (object_path, ifindex);
        Err(anyhow::anyhow!(
            "binary built without `maya-network/xdp` feature; recompile with `--features maya-network/xdp`"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(strict: bool) -> NetworkConfig {
        NetworkConfig {
            interface: "eth0".to_string(),
            xdp_strict: strict,
            monitored_ports: vec![80, 443],
            max_pps: 100_000,
            packet_capture: true,
            decoy_subnet: "10.13.37.0/24".to_string(),
            dns_intercept: true,
        }
    }

    fn make_result(mode: XdpMode) -> XdpAttachResult {
        XdpAttachResult {
            mode,
            interface: "eth0".to_string(),
            ifindex: Some(2),
            object_path: None,
            details: "test".to_string(),
        }
    }

    #[test]
    fn strict_mode_rejects_non_attached_modes() {
        let manager = XdpManager::new(&test_config(true));
        assert!(manager.enforce_mode(make_result(XdpMode::DryRun)).is_err());
        assert!(manager
            .enforce_mode(make_result(XdpMode::Unsupported))
            .is_err());
    }

    #[test]
    fn non_strict_mode_allows_dry_run() {
        let manager = XdpManager::new(&test_config(false));
        assert!(manager.enforce_mode(make_result(XdpMode::DryRun)).is_ok());
    }

    #[test]
    fn strict_mode_allows_attached() {
        let manager = XdpManager::new(&test_config(true));
        assert!(manager.enforce_mode(make_result(XdpMode::Attached)).is_ok());
    }
}
