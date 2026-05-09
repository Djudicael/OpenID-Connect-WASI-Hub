use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// PKCE code challenge method.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum CodeChallengeMethod {
    /// S256 — SHA-256 hash of the code verifier (mandatory per OIDC spec).
    S256,
}

impl std::fmt::Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodeChallengeMethod::S256 => write!(f, "S256"),
        }
    }
}

impl std::str::FromStr for CodeChallengeMethod {
    type Err = OidcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "S256" => Ok(CodeChallengeMethod::S256),
            _ => Err(OidcError::InvalidInput(format!(
                "Unsupported code_challenge_method: {}",
                s
            ))),
        }
    }
}

use crate::OidcError;

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
    /// PKCE code_challenge_method.
    pub code_challenge_method: CodeChallengeMethod,
    /// OIDC nonce from the authorization request.
    pub nonce: Option<String>,
    /// Whether the code has been exchanged.
    pub used: bool,
    /// When the authorization code expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}
