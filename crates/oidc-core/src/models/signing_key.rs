use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A signing key for JWT token issuance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SigningKey {
    /// Unique identifier.
    pub id: Uuid,
    /// The realm this key belongs to.
    pub realm_id: Uuid,
    /// Key ID for JWKS.
    pub kid: String,
    /// Algorithm (RS256 or EdDSA).
    pub algorithm: Algorithm,
    /// Public key in PEM format.
    pub public_key_pem: String,
    /// AES-256-GCM encrypted private key PEM; None for HSM-backed keys.
    pub private_key_pem_encrypted: Option<String>,
    /// Whether this key is currently active for signing.
    pub active: bool,
    /// When the key was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Optional expiration timestamp.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the key was retired (no longer used for signing new tokens).
    pub retired_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Supported signing algorithms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    /// RS256 (RSA with SHA-256).
    Rs256,
    /// EdDSA (Ed25519).
    EdDSA,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Rs256 => write!(f, "RS256"),
            Algorithm::EdDSA => write!(f, "EdDSA"),
        }
    }
}
