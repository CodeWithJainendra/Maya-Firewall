//! # Maya Core
//!
//! Foundation module for Project MAYA — Active Deception Grid.
//! Contains core types, configuration, error handling, and shared utilities
//! used across all MAYA subsystems.
//!
//! ## Architecture
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                    MAYA CORE                              │
//! ├──────────┬──────────┬───────────┬──────────┬────────────┤
//! │  Config  │  Types   │  Errors   │ Events   │  Utils     │
//! └──────────┴──────────┴───────────┴──────────┴────────────┘
//! ```

pub mod config;
pub mod error;
pub mod events;
pub mod types;
pub mod utils;

pub use config::MayaConfig;
pub use error::{MayaError, MayaResult};
pub use types::*;
