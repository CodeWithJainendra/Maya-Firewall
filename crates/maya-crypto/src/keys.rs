//! Key management for MAYA nodes.

use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use tracing::info;
use x25519_dalek::{PublicKey, StaticSecret};

/// Cryptographic identity of a MAYA node.
#[derive(Clone)]
pub struct NodeIdentity {
    /// Ed25519 signing key (for signatures)
    pub signing_key: SigningKey,
    /// Ed25519 verifying key (public)
    pub verifying_key: VerifyingKey,
    /// X25519 static secret (for key exchange)
    pub x25519_secret: StaticSecret,
    /// X25519 public key
    pub x25519_public: PublicKey,
}

/// Serializable public key bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    pub node_id: String,
    pub ed25519_public: String, // hex
    pub x25519_public: String,  // hex
}

/// Key Manager — generates, stores, and rotates cryptographic keys.
pub struct KeyManager {
    identity: Option<NodeIdentity>,
    node_id: String,
}

impl KeyManager {
    pub fn new(node_id: &str) -> Self {
        Self {
            identity: None,
            node_id: node_id.to_string(),
        }
    }

    /// Generate a new cryptographic identity.
    pub fn generate_identity(&mut self) -> Result<PublicKeyBundle> {
        // Generate 32 random bytes for Ed25519 seed
        let mut ed_seed = [0u8; 32];
        getrandom(&mut ed_seed);
        let signing_key = SigningKey::from_bytes(&ed_seed);
        let verifying_key = signing_key.verifying_key();

        // Generate 32 random bytes for X25519 secret
        let mut x_seed = [0u8; 32];
        getrandom(&mut x_seed);
        let x25519_secret = StaticSecret::from(x_seed);
        let x25519_public = PublicKey::from(&x25519_secret);

        let bundle = PublicKeyBundle {
            node_id: self.node_id.clone(),
            ed25519_public: hex::encode(verifying_key.as_bytes()),
            x25519_public: hex::encode(x25519_public.as_bytes()),
        };

        self.identity = Some(NodeIdentity {
            signing_key,
            verifying_key,
            x25519_secret,
            x25519_public,
        });

        info!(
            node_id = %self.node_id,
            ed25519 = %&bundle.ed25519_public[..16],
            x25519 = %&bundle.x25519_public[..16],
            "🔐 Cryptographic identity generated"
        );

        Ok(bundle)
    }

    /// Sign a message with Ed25519.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No identity generated"))?;
        use ed25519_dalek::Signer;
        let signature = identity.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify an Ed25519 signature.
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        let vk = VerifyingKey::from_bytes(
            public_key
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid public key length"))?,
        )?;
        let sig = ed25519_dalek::Signature::from_bytes(
            signature
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid signature length"))?,
        );
        use ed25519_dalek::Verifier;
        Ok(vk.verify(message, &sig).is_ok())
    }

    /// Get the public key bundle.
    pub fn public_bundle(&self) -> Result<PublicKeyBundle> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No identity generated"))?;
        Ok(PublicKeyBundle {
            node_id: self.node_id.clone(),
            ed25519_public: hex::encode(identity.verifying_key.as_bytes()),
            x25519_public: hex::encode(identity.x25519_public.as_bytes()),
        })
    }
}

/// Fill buffer with cryptographically secure random bytes.
fn getrandom(buf: &mut [u8]) {
    use rand::Rng;
    let mut rng = rand::rng();
    rng.fill(buf);
}
