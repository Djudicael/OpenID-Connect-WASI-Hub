//! API key domain models.

use serde::Deserialize;
use uuid::Uuid;

pub use oidc_core::models::ApiKey;

/// Request body for creating a new API key.
#[derive(Deserialize)]
pub struct CreateKeyRequest {
    /// Target realm for the key.
    pub realm_id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Optional expiration in days.
    pub expires_in_days: Option<u32>,
}

/// Query parameters for listing API keys.
#[derive(Deserialize)]
pub struct ListKeysQuery {
    /// Realm to filter by.
    pub realm_id: Uuid,
    /// Include revoked keys.
    pub include_revoked: Option<bool>,
}

/// Response wrapper for a newly created API key.
/// The raw key is shown exactly once.
#[derive(serde::Serialize)]
pub struct CreateKeyResponse {
    /// The created API key metadata.
    #[serde(flatten)]
    pub api_key: ApiKey,
    /// The raw key string (shown only once).
    pub raw_key: String,
}

/// Response wrapper for a rotated API key.
#[derive(serde::Serialize)]
pub struct RotateKeyResponse {
    /// The API key ID.
    pub id: Uuid,
    /// The new raw key string (shown only once).
    pub raw_key: String,
    /// The new expiration timestamp.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}
