use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An OAuth2 session / token issuance record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Session {
    /// Unique identifier.
    pub id: Uuid,
    /// The user this session belongs to (None for client_credentials grant).
    pub user_id: Option<Uuid>,
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
    /// When the access token expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// When the refresh token expires.
    pub refresh_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the session was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the session was last used.
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Token family ID for refresh token rotation.
    pub token_family_id: Option<Uuid>,
    /// Previous session ID in the rotation chain.
    pub previous_session_id: Option<Uuid>,
    /// When this session was created by rotation.
    pub rotated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When a rotated token was reused (theft detection).
    pub reused_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether the entire token family has been revoked.
    pub family_revoked: bool,
}
