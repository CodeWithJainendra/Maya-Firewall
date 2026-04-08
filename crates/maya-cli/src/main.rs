//! # Project MAYA — Active Deception Grid
//!
//! "Westworld" for Cyber-Attackers.
//! AI-powered Dynamic Deception Engine.
//!
//! CDIS, IIT Kanpur
//!
//! ```text
//!  ███╗   ███╗ █████╗ ██╗   ██╗ █████╗
//!  ████╗ ████║██╔══██╗╚██╗ ██╔╝██╔══██╗
//!  ██╔████╔██║███████║ ╚████╔╝ ███████║
//!  ██║╚██╔╝██║██╔══██║  ╚██╔╝  ██╔══██║
//!  ██║ ╚═╝ ██║██║  ██║   ██║   ██║  ██║
//!  ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
//!  Active Deception Grid v0.1.0
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

use maya_core::config::MayaConfig;
use maya_core::events::EventBus;
use maya_core::types::*;

use maya_ai::DeceptionBrain;
use maya_consensus::HotStuffEngine;
use maya_crypto::KeyManager;
use maya_dashboard::DashboardServer;
use maya_deception::DeceptionOrchestrator;
use maya_network::NetworkEngine;
use maya_profiler::BehaviorAnalyzer;
use maya_sandbox::SandboxEngine;

const BANNER: &str = r#"
 ███╗   ███╗ █████╗ ██╗   ██╗ █████╗ 
 ████╗ ████║██╔══██╗╚██╗ ██╔╝██╔══██╗
 ██╔████╔██║███████║ ╚████╔╝ ███████║
 ██║╚██╔╝██║██╔══██║  ╚██╔╝  ██╔══██║
 ██║ ╚═╝ ██║██║  ██║   ██║   ██║  ██║
 ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
 Active Deception Grid v0.1.0
 CDIS, IIT Kanpur
"#;

/// Project MAYA — AI-powered Active Deception Grid
#[derive(Parser)]
#[command(name = "maya", version, about = "Project MAYA — Active Deception Grid", long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/maya.toml")]
    config: PathBuf,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MAYA deception grid
    Start {
        /// Run in development mode
        #[arg(long)]
        dev: bool,
    },
    /// Generate a default configuration file
    Init {
        /// Generate a development config (unsafe for production)
        #[arg(long)]
        dev: bool,
    },
    /// Spawn a single test decoy
    TestDecoy {
        /// Decoy type: linux, windows, database, scada
        #[arg(short, long, default_value = "linux")]
        decoy_type: String,
    },
    /// Run the Ghost Shell interactively (for testing)
    GhostShell {
        /// Hostname for the fake system
        #[arg(short = 'H', long, default_value = "srv-001.corp.local")]
        hostname: String,
    },
    /// Generate cryptographic identity
    GenKeys {
        /// Node ID
        #[arg(short, long, default_value = "maya-node-001")]
        node_id: String,
    },
    /// Show system status
    Status,
    /// Run the SOC dashboard
    Dashboard {
        /// Listen port
        #[arg(short, long, default_value = "8900")]
        port: u16,
    },
    /// Analyze a malware sample
    Analyze {
        /// Path to the file
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Validate configuration file safety and readiness
    ValidateConfig {
        /// Validate as development config (skip production-safety checks)
        #[arg(long)]
        dev: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level));
    fmt().with_env_filter(filter).with_target(false).init();

    match cli.command {
        Commands::Start { dev } => cmd_start(dev, &cli.config).await,
        Commands::Init { dev } => cmd_init(dev).await,
        Commands::TestDecoy { decoy_type } => cmd_test_decoy(&decoy_type).await,
        Commands::GhostShell { hostname } => cmd_ghost_shell(&hostname).await,
        Commands::GenKeys { node_id } => cmd_gen_keys(&node_id).await,
        Commands::Status => cmd_status().await,
        Commands::Dashboard { port } => cmd_dashboard(port).await,
        Commands::Analyze { file } => cmd_analyze(&file).await,
        Commands::ValidateConfig { dev } => cmd_validate_config(&cli.config, dev).await,
    }
}

/// Start the full MAYA grid.
async fn cmd_start(dev: bool, config_path: &Path) -> Result<()> {
    eprintln!("{}", BANNER);

    let config = if dev {
        info!("🔧 Running in DEVELOPMENT mode");
        MayaConfig::default_dev()
    } else {
        let loaded = MayaConfig::load(config_path)?;
        loaded.validate_production_safety()?;
        loaded
    };

    // Initialize the durable event bus (append-only audit + replay buffer)
    let event_audit_path = config.system.data_dir.join("events/audit.jsonl");
    let event_bus = Arc::new(EventBus::with_audit_log(&event_audit_path)?);
    info!(
        audit_log = %event_audit_path.display(),
        "🧾 Event audit log enabled"
    );

    // Initialize all subsystems
    info!("🚀 Initializing MAYA subsystems...");

    // 1. Network Engine
    let network = NetworkEngine::new(config.network.clone(), event_bus.clone());
    network.start().await?;

    // 2. Deception Engine
    let _deception = DeceptionOrchestrator::new(
        config.deception.clone(),
        config.network.decoy_subnet.clone(),
        event_bus.clone(),
    );

    // 3. AI Brain
    let _brain = DeceptionBrain::new(config.ai.clone());

    // 4. Sandbox
    let _sandbox = SandboxEngine::new(
        config.sandbox.max_exec_time_secs,
        config.sandbox.max_memory_mb,
        config.sandbox.samples_dir.to_str().unwrap_or("/tmp"),
    );

    // 5. Crypto
    let mut key_mgr = KeyManager::new(&config.system.node_id);
    let _keys = key_mgr.generate_identity()?;

    // 6. Consensus
    let _consensus = HotStuffEngine::new(
        &config.system.node_id,
        config.consensus.quorum_size,
        config.consensus.peers.len() as u32 + 1,
    );

    // 7. Profiler
    let _profiler = BehaviorAnalyzer::new(config.profiler.attribution_threshold);

    // 8. Dashboard
    let dashboard =
        DashboardServer::new(&config.dashboard.listen_addr, config.dashboard.listen_port)
            .with_assets_dir(&config.dashboard.assets_dir)
            .with_ai_endpoint(Some(config.ai.llm_endpoint.clone()))
            .with_security(
                config.dashboard.auth_token.clone(),
                config.dashboard.allowed_origins.clone(),
            )
            .with_event_bus(event_bus.clone());

    info!("═══════════════════════════════════════════════════");
    info!("  🕸️  MAYA ACTIVE DECEPTION GRID — ALL SYSTEMS GO");
    info!("═══════════════════════════════════════════════════");
    info!("  Node ID:    {}", config.system.node_id);
    info!("  Interface:  {}", config.network.interface);
    info!("  Decoy Net:  {}", config.network.decoy_subnet);
    info!("  Max Decoys: {}", config.deception.max_decoys);
    info!(
        "  Dashboard:  http://{}:{}",
        config.dashboard.listen_addr, config.dashboard.listen_port
    );
    info!("═══════════════════════════════════════════════════");

    // Run dashboard (blocks)
    dashboard.start().await?;

    Ok(())
}

/// Generate default config.
async fn cmd_init(dev: bool) -> Result<()> {
    eprintln!("{}", BANNER);
    let config = if dev {
        info!("🔧 Writing DEVELOPMENT config (not for production)");
        MayaConfig::default_dev()
    } else {
        info!("🛡️ Writing production-safe baseline config template");
        MayaConfig::default_prod()
    };
    let toml_str = config.to_toml()?;

    std::fs::create_dir_all("config")?;
    std::fs::write("config/maya.toml", &toml_str)?;
    info!("✅ Configuration written to config/maya.toml");
    println!("{}", toml_str);
    Ok(())
}

/// Spawn a test decoy.
async fn cmd_test_decoy(decoy_type_str: &str) -> Result<()> {
    eprintln!("{}", BANNER);
    let event_bus = Arc::new(EventBus::new());
    let config = MayaConfig::default_dev();
    let orchestrator =
        DeceptionOrchestrator::new(config.deception, config.network.decoy_subnet, event_bus);

    let decoy_type = match decoy_type_str {
        "linux" => DecoyType::LinuxServer,
        "windows" => DecoyType::WindowsServer,
        "database" => DecoyType::DatabaseServer,
        "scada" => DecoyType::ScadaDevice,
        _ => DecoyType::LinuxServer,
    };

    let id = orchestrator
        .spawn_decoy(decoy_type, EngagementLevel::High, vec![22, 80, 443, 3306])
        .await?;

    info!("🎪 Test decoy spawned: {}", id);
    Ok(())
}

/// Interactive Ghost Shell for testing.
async fn cmd_ghost_shell(hostname: &str) -> Result<()> {
    eprintln!("{}", BANNER);
    info!("👻 Starting Ghost Shell on hostname: {}", hostname);
    info!("   Type commands as if you're in a real Linux terminal.");
    info!("   Type 'exit' to quit.\n");

    let fake_gen = Arc::new(maya_deception::fakegen::FakeDataGenerator::new());
    let fs_gen = Arc::new(maya_deception::filesystem::FilesystemGenerator::new());
    let session_id = SessionId::new();

    let shell = maya_deception::shell::GhostShell::new(
        session_id,
        hostname.to_string(),
        DecoyType::LinuxServer,
        fake_gen,
        fs_gen,
    );

    let stdin = std::io::stdin();
    let mut input = String::new();

    loop {
        eprint!("{}", shell.prompt());
        input.clear();
        stdin.read_line(&mut input)?;
        let cmd = input.trim();

        if cmd == "exit" || cmd == "quit" {
            eprintln!("logout");
            break;
        }

        let output = shell.execute(cmd).await?;
        eprint!("{}", output);
    }

    Ok(())
}

/// Generate cryptographic keys.
async fn cmd_gen_keys(node_id: &str) -> Result<()> {
    eprintln!("{}", BANNER);
    let mut mgr = KeyManager::new(node_id);
    let bundle = mgr.generate_identity()?;
    println!("{}", serde_json::to_string_pretty(&bundle)?);
    Ok(())
}

/// Show status.
async fn cmd_status() -> Result<()> {
    eprintln!("{}", BANNER);
    println!("MAYA Grid Status: OFFLINE (run 'maya start' to activate)");
    Ok(())
}

/// Run dashboard standalone.
async fn cmd_dashboard(port: u16) -> Result<()> {
    eprintln!("{}", BANNER);
    let server = DashboardServer::new("127.0.0.1", port)
        .with_assets_dir("./dashboard/dist")
        .with_ai_endpoint(Some("http://127.0.0.1:11434".to_string()))
        .with_security(
            Some("maya-dev-token".to_string()),
            vec![
                format!("http://127.0.0.1:{port}"),
                format!("http://localhost:{port}"),
                "http://127.0.0.1:5173".to_string(),
                "http://localhost:5173".to_string(),
            ],
        );

    info!("🔐 Dashboard login token (dev): maya-dev-token");
    server.start().await?;
    Ok(())
}

/// Analyze a malware sample.
async fn cmd_analyze(file: &PathBuf) -> Result<()> {
    eprintln!("{}", BANNER);
    let data = std::fs::read(file)?;
    let session_id = SessionId::new();
    let engine = SandboxEngine::new(60, 256, "/tmp/maya-samples");
    let result = engine.analyze_payload(&data, session_id).await?;

    println!("═══ MALWARE ANALYSIS REPORT ═══");
    println!("SHA256:   {}", result.sample.sha256);
    println!("Size:     {} bytes", result.sample.file_size);
    println!("Type:     {}", result.sample.file_type);
    println!("Entropy:  {:.2}", result.analysis.entropy);
    println!("Family:   {:?}", result.analysis.family);
    println!("C2:       {:?}", result.analysis.c2_servers);
    println!("Caps:     {:?}", result.analysis.capabilities);
    println!("Duration: {}ms", result.sandbox_duration_ms);
    Ok(())
}

/// Validate a MAYA configuration file.
async fn cmd_validate_config(config_path: &Path, dev: bool) -> Result<()> {
    eprintln!("{}", BANNER);
    let config = MayaConfig::load(config_path)?;

    if dev {
        info!(
            "✅ Config parsed successfully in development mode: {}",
            config_path.display()
        );
        return Ok(());
    }

    config.validate_production_safety()?;
    info!(
        "✅ Config passed production safety validation: {}",
        config_path.display()
    );
    Ok(())
}
