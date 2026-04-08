//! # Maya Deception Engine
//!
//! The heart of MAYA — dynamically spawns realistic fake environments
//! that evolve in response to attacker behavior.
//!
//! ## Architecture
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                  DECEPTION ENGINE                         │
//! ├─────────────┬────────────────┬───────────────────────────┤
//! │  Orchestrator│  Container    │  Fake Data Generator      │
//! │  (decides    │  Manager      │  (Aadhaar, PAN, banking   │
//! │   what to    │  (gVisor/     │   records, patient data,  │
//! │   spawn)     │   Kata)       │   Git repos, emails)      │
//! ├─────────────┼────────────────┼───────────────────────────┤
//! │  Shell      │  Service      │  Filesystem               │
//! │  Emulator   │  Emulator     │  Generator                │
//! │  (AI-backed │  (SSH, HTTP,  │  (realistic /etc, /var,   │
//! │   terminal) │   DB, SCADA)  │   /home with histories)   │
//! └─────────────┴────────────────┴───────────────────────────┘
//! ```

pub mod container;
pub mod fakegen;
pub mod filesystem;
pub mod orchestrator;
pub mod services;
pub mod shell;

pub use orchestrator::DeceptionOrchestrator;
