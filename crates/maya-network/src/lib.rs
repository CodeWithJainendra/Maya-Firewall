//! # Maya Network Engine
//!
//! XDP/eBPF-inspired kernel-level packet interception and manipulation.
//! Detects port scans, classifies intrusion attempts, and routes
//! attackers into the MAYA deception grid.
//!
//! ## Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  INCOMING PACKETS                                          │
//! │       │                                                     │
//! │       ▼                                                     │
//! │  ┌──────────┐    ┌──────────────┐    ┌───────────────┐     │
//! │  │  XDP/    │───▶│  Scan        │───▶│  Deception    │     │
//! │  │  eBPF    │    │  Detector    │    │  Router       │     │
//! │  │  Filter  │    │  (ML Model)  │    │  (→ Decoys)   │     │
//! │  └──────────┘    └──────────────┘    └───────────────┘     │
//! │       │                                     │               │
//! │       ▼                                     ▼               │
//! │  ┌──────────┐                      ┌───────────────┐       │
//! │  │  Rate    │                      │  Session      │       │
//! │  │  Limiter │                      │  Tracker      │       │
//! │  └──────────┘                      └───────────────┘       │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod detector;
pub mod engine;
pub mod packet;
pub mod scanner;
pub mod session;
pub mod xdp;

pub use engine::NetworkEngine;
