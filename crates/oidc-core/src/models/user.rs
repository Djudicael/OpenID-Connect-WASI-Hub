use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A user within a realm.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    /// Unique identifier (UUID v7).
    pub id: Uuid,
    /// The realm this user belongs to.
    pub realm_id: Uuid,
    /// Email address (unique within realm).
    pub email: String,
    /// Whether the email has been verified.
    pub email_verified: bool,
    /// Optional username.
    pub username: Option<String>,
    /// Argon2id password hash (None for federated users).
    pub password_hash: Option<String>,
    /// Given (first) name.
    pub given_name: Option<String>,
    /// Family (last) name.
    pub family_name: Option<String>,
    /// Whether the account is enabled.
    pub enabled: bool,
}
