//! # Maya Sandbox — WASM-based Malware Analysis
//! Safe execution of captured payloads in WebAssembly sandbox.

pub mod engine;
pub use engine::SandboxEngine;
