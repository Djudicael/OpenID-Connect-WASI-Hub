use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An OAuth2 session / token issuance record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Session {
    /// Unique identifier.
    pub id: Uuid,
    /// The user this session belongs to.
    pub user_id: Uuid,
    /// The realm.
    pub realm_id: Uuid,
    /// The client that requested the tokens.
    pub client_id: Uuid,
    /// The grant type used.
    pub grant_type: String,
    /// SHA-256 hash of the access token.
    pub access_token_hash: String,
    /// SHA-256 hash of the refresh token (optional).
    pub refresh_token_hash: Option<String>,
    /// JWT ID of the ID token.
    pub id_token_jti: Option<String>,
    /// Granted scopes.
    pub scope: Vec<String>,
    /// Whether the session has been revoked.
    pub revoked: bool,
}
