//! # Maya Crypto Engine
//! Post-Quantum Cryptography — Hybrid Classical + PQ.
//! Uses X25519 + Ed25519 (classical) with PQ-readiness architecture.

pub mod aead;
pub mod hybrid;
pub mod keys;

pub use hybrid::HybridCrypto;
pub use keys::KeyManager;
