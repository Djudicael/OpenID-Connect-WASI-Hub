use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An email verification token for confirming email ownership.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EmailVerificationToken {
    /// Unique identifier.
    pub id: Uuid,
    /// The user this token belongs to.
    pub user_id: Uuid,
    /// The realm.
    pub realm_id: Uuid,
    /// The email being verified.
    pub email: String,
    /// SHA-256 hash of the verification token (only hash stored in DB).
    pub token_hash: String,
    /// Whether the token has been used.
    pub used: bool,
    /// When the token expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// When the token was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}
