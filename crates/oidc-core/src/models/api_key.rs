use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An API key for machine-to-machine authentication.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
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
    #[serde(skip_serializing)]
    pub hashed_secret: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Whether the key has been revoked.
    pub revoked: bool,
    /// Number of requests made with this key.
    pub request_count: i64,
    /// Optional expiration timestamp.
    pub expires_at: Option<DateTime<Utc>>,
    /// Last usage timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// ID of the user who created this key.
    pub created_by: Option<Uuid>,
    /// When this key was rotated (old key grace period).
    pub rotated_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("id", &self.id)
            .field("realm_id", &self.realm_id)
            .field("name", &self.name)
            .field("prefix", &self.prefix)
            .field("hashed_secret", &"<redacted>")
            .field("revoked", &self.revoked)
            .field("request_count", &self.request_count)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

impl ApiKey {
    /// Check if the key is expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map_or(false, |exp| Utc::now() > exp)
    }

    /// Check if the key is active (not revoked, not expired).
    pub fn is_active(&self) -> bool {
        !self.revoked && !self.is_expired()
    }
}
