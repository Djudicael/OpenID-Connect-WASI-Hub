use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::OidcError;

/// An OAuth2/OIDC client registered within a realm.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Client {
    /// Unique identifier.
    pub id: Uuid,
    /// The realm this client belongs to.
    pub realm_id: Uuid,
    /// OAuth2 client_id (unique globally).
    pub client_id: String,
    /// Client type: confidential or public.
    pub client_type: ClientType,
    /// Argon2id hash of the client_secret (None for public clients).
    pub client_secret_hash: Option<String>,
    /// Human-readable name.
    pub name: String,
    /// Registered redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Allowed OAuth2 scopes.
    pub allowed_scopes: Vec<String>,
    /// Allowed grant types.
    pub allowed_grant_types: Vec<String>,
    /// Whether PKCE is required.
    pub pkce_required: bool,
    /// Whether the client is enabled.
    pub enabled: bool,
    /// When the client was soft-deleted.
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The type of OAuth2 client.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    /// Can keep secrets (server-side app).
    Confidential,
    /// Cannot keep secrets (SPA, mobile).
    Public,
}

impl Client {
    /// Validate the client fields.
    pub fn validate(&self) -> Result<(), OidcError> {
        if self.client_id.trim().is_empty() {
            return Err(OidcError::InvalidInput(
                "client_id must not be empty".into(),
            ));
        }
        for uri in &self.redirect_uris {
            if uri.parse::<url::Url>().is_err() {
                return Err(OidcError::InvalidInput(format!(
                    "Invalid redirect URI: {}",
                    uri
                )));
            }
        }
        Ok(())
    }
}
