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
}

/// Query parameters for listing API keys.
#[derive(Deserialize)]
pub struct ListKeysQuery {
    /// Realm to filter by.
    pub realm_id: Uuid,
}
