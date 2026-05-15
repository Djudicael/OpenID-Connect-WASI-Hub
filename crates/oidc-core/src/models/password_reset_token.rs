use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A password reset token for self-service password reset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasswordResetToken {
    /// Unique identifier.
    pub id: Uuid,
    /// The user this token belongs to.
    pub user_id: Uuid,
    /// The realm.
    pub realm_id: Uuid,
    /// The opaque reset token (SHA-256 hash is stored in DB).
    pub token_hash: String,
    /// Whether the token has been used.
    pub used: bool,
    /// When the token expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// When the token was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}
