//! Hybrid Classical + Post-Quantum Cryptography.
//! Architecture ready for Kyber KEM integration.

use anyhow::Result;
use ed25519_dalek::SigningKey;
#[cfg(feature = "oqs")]
use oqs::{kem, sig};
use rand::Rng;
use sha2::{Digest, Sha256};
use tracing::info;
use x25519_dalek::{PublicKey, StaticSecret};

/// Hybrid crypto system combining classical and PQ algorithms.
pub struct HybridCrypto {
    /// Whether to use hybrid mode (classical + PQ)
    hybrid_mode: bool,
}

impl HybridCrypto {
    pub fn new(hybrid_mode: bool) -> Self {
        info!(
            hybrid = hybrid_mode,
            "🔐 Hybrid Crypto Engine initialized (PQ-ready)"
        );
        Self { hybrid_mode }
    }

    /// Derive a shared secret combining X25519 (classical) with PQ KEM.
    /// When OQS is integrated, this will combine both shared secrets.
    pub fn derive_hybrid_secret(
        &self,
        classical_shared: &[u8],
        pq_shared: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"MAYA-HYBRID-KDF-v1");
        hasher.update(classical_shared);

        if let Some(pq) = pq_shared {
            hasher.update(pq);
        }

        hasher.finalize().to_vec()
    }

    /// Encapsulation path used until OQS is wired:
    /// - ciphertext = ephemeral X25519 public key (32 bytes)
    /// - shared secret = DH(ephemeral_secret, peer_public)
    pub fn kyber_encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        #[cfg(feature = "oqs")]
        {
            return self.kyber_encapsulate_oqs(public_key);
        }

        #[cfg(not(feature = "oqs"))]
        {
            self.kyber_encapsulate_fallback(public_key)
        }
    }

    /// Signing path used until OQS is wired:
    /// - Ed25519 deterministic signing from a 32-byte seed.
    pub fn dilithium_sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "oqs")]
        {
            return self.dilithium_sign_oqs(message, secret_key);
        }

        #[cfg(not(feature = "oqs"))]
        {
            self.dilithium_sign_fallback(message, secret_key)
        }
    }

    fn kyber_encapsulate_fallback(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("kyber_encapsulate expects 32-byte public key"))?;

        let mut secret_seed = [0u8; 32];
        let mut rng = rand::rng();
        rng.fill(&mut secret_seed);

        let eph_secret = StaticSecret::from(secret_seed);
        let eph_public = PublicKey::from(&eph_secret);
        let peer_public = PublicKey::from(public_key);
        let shared = eph_secret.diffie_hellman(&peer_public);

        let kem_tag = if self.hybrid_mode {
            "X25519-KEM-HYBRID"
        } else {
            "X25519-KEM"
        };

        info!(kem = kem_tag, "🔐 Encapsulation completed");

        Ok((eph_public.as_bytes().to_vec(), shared.as_bytes().to_vec()))
    }

    fn dilithium_sign_fallback(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
        let seed: [u8; 32] = secret_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("dilithium_sign expects 32-byte secret seed"))?;

        let signing_key = SigningKey::from_bytes(&seed);
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(message);

        info!(sig = "Ed25519", "✍️ Signature generated");
        Ok(signature.to_bytes().to_vec())
    }

    #[cfg(feature = "oqs")]
    fn kyber_encapsulate_oqs(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let kem = kem::Kem::new(kem::Algorithm::Kyber768)
            .map_err(|e| anyhow::anyhow!("failed to initialize Kyber768: {e}"))?;

        let pk = kem
            .public_key_from_bytes(public_key)
            .map_err(|e| anyhow::anyhow!("invalid Kyber public key bytes: {e}"))?;

        let (ciphertext, shared_secret) = kem
            .encapsulate(&pk)
            .map_err(|e| anyhow::anyhow!("Kyber encapsulation failed: {e}"))?;

        info!(kem = "Kyber768", "🔐 OQS encapsulation completed");
        Ok((ciphertext.into_vec(), shared_secret.into_vec()))
    }

    #[cfg(feature = "oqs")]
    fn dilithium_sign_oqs(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
        let signer = sig::Sig::new(sig::Algorithm::Dilithium3)
            .map_err(|e| anyhow::anyhow!("failed to initialize Dilithium3: {e}"))?;

        let sk = signer
            .secret_key_from_bytes(secret_key)
            .map_err(|e| anyhow::anyhow!("invalid Dilithium secret key bytes: {e}"))?;

        let signature = signer
            .sign(message, &sk)
            .map_err(|e| anyhow::anyhow!("Dilithium signing failed: {e}"))?;

        info!(sig = "Dilithium3", "✍️ OQS signature generated");
        Ok(signature.into_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_encapsulate_returns_real_material() {
        let peer_secret = StaticSecret::from([7u8; 32]);
        let peer_public = PublicKey::from(&peer_secret);
        let crypto = HybridCrypto::new(true);

        let (ciphertext, shared) = crypto
            .kyber_encapsulate(peer_public.as_bytes())
            .expect("encapsulation should succeed");

        assert_eq!(ciphertext.len(), 32);
        assert_eq!(shared.len(), 32);
        assert_ne!(shared, vec![0u8; 32]);
    }

    #[test]
    fn test_dilithium_sign_produces_signature() {
        let crypto = HybridCrypto::new(true);
        let secret = [11u8; 32];
        let sig = crypto
            .dilithium_sign(b"maya", &secret)
            .expect("signing should succeed");
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_derive_hybrid_secret_mixes_inputs() {
        let crypto = HybridCrypto::new(true);
        let a = crypto.derive_hybrid_secret(b"a", Some(b"b"));
        let b = crypto.derive_hybrid_secret(b"a", Some(b"c"));
        assert_ne!(a, b);
    }
}
