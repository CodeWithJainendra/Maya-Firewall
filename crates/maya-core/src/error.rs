//! Error types for the MAYA Deception Engine.
//!
//! Uses `thiserror` for ergonomic error definitions with zero-cost abstractions.

use thiserror::Error;

/// Result type alias for MAYA operations.
pub type MayaResult<T> = Result<T, MayaError>;

/// Comprehensive error enum covering all MAYA subsystem failures.
#[derive(Error, Debug)]
pub enum MayaError {
    // ── Core Errors ──────────────────────────────────────────
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Initialization failed: {0}")]
    Init(String),

    // ── Network Engine Errors ────────────────────────────────
    #[error("Network engine error: {0}")]
    Network(String),

    #[error("eBPF/XDP program load failure: {0}")]
    EbpfLoad(String),

    #[error("Packet capture error: {0}")]
    PacketCapture(String),

    #[error("Port binding failed on {port}: {reason}")]
    PortBind { port: u16, reason: String },

    // ── Deception Engine Errors ──────────────────────────────
    #[error("Decoy spawn failed: {0}")]
    DecoySpawn(String),

    #[error("Container orchestration error: {0}")]
    Container(String),

    #[error("Fake service generation failed: {0}")]
    FakeServiceGen(String),

    #[error("Decoy limit exceeded: max {max}, requested {requested}")]
    DecoyLimit { max: u32, requested: u32 },

    // ── AI Engine Errors ─────────────────────────────────────
    #[error("AI inference error: {0}")]
    AiInference(String),

    #[error("LLM backend unreachable: {0}")]
    LlmBackend(String),

    #[error("Context window exceeded: {tokens} tokens")]
    ContextOverflow { tokens: u64 },

    // ── Sandbox Errors ───────────────────────────────────────
    #[error("Sandbox execution error: {0}")]
    SandboxExec(String),

    #[error("WASM module compilation failed: {0}")]
    WasmCompile(String),

    #[error("Malware analysis timeout after {seconds}s")]
    AnalysisTimeout { seconds: u64 },

    // ── Cryptography Errors ──────────────────────────────────
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("Key exchange failure: {0}")]
    KeyExchange(String),

    #[error("Post-quantum KEM error: {0}")]
    PostQuantumKem(String),

    #[error("Signature verification failed")]
    SignatureInvalid,

    // ── Consensus Errors ─────────────────────────────────────
    #[error("Consensus failure: {0}")]
    Consensus(String),

    #[error("Quorum not reached: need {needed}, got {have}")]
    QuorumNotReached { needed: u32, have: u32 },

    #[error("Byzantine fault detected from node {node_id}")]
    ByzantineFault { node_id: String },

    // ── Profiler Errors ──────────────────────────────────────
    #[error("Profiling error: {0}")]
    Profiling(String),

    #[error("Insufficient behavioral data for attribution")]
    InsufficientData,

    // ── Storage Errors ───────────────────────────────────────
    #[error("Database error: {0}")]
    Database(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // ── Serialization Errors ─────────────────────────────────
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    // ── Generic ──────────────────────────────────────────────
    #[error("Internal error: {0}")]
    Internal(String),
}
