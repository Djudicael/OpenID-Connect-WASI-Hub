use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An API key for machine-to-machine authentication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKey {
    /// Unique identifier.
    pub id: Uuid,
    /// The realm this key belongs to.
    pub realm_id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Prefix for display/lookup (first 8 chars).
    pub prefix: String,
    /// Argon2id hash of the secret portion.
    pub hashed_secret: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Whether the key has been revoked.
    pub revoked: bool,
    /// Number of requests made with this key.
    pub request_count: i64,
}
