use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An authorization code for the Authorization Code + PKCE flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthCode {
    /// Unique identifier.
    pub id: Uuid,
    /// The opaque authorization code string.
    pub code: String,
    /// The client this code was issued to.
    pub client_id: Uuid,
    /// The authenticated user.
    pub user_id: Uuid,
    /// The realm.
    pub realm_id: Uuid,
    /// The redirect URI that was used in the authorize request.
    pub redirect_uri: String,
    /// Granted scopes.
    pub scope: Vec<String>,
    /// PKCE code_challenge.
    pub code_challenge: String,
    /// PKCE code_challenge_method (S256 or plain).
    pub code_challenge_method: String,
    /// Whether the code has been exchanged.
    pub used: bool,
    /// Expiration timestamp (seconds since epoch).
    pub expires_at: i64,
}
