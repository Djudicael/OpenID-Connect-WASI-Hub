use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::OidcError;

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
    /// Phone number.
    pub phone_number: Option<String>,
    /// Locale preference (e.g., "en", "fr").
    pub locale: Option<String>,
    /// Arbitrary key-value attributes.
    pub attributes: serde_json::Value,
    /// Whether the account is enabled.
    pub enabled: bool,
    /// When the user was soft-deleted.
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl User {
    /// Validate the user fields.
    pub fn validate(&self) -> Result<(), OidcError> {
        // Basic email format validation
        let email = self.email.trim();
        if email.is_empty() {
            return Err(OidcError::InvalidInput("email must not be empty".into()));
        }
        if !email.contains('@') || !email.contains('.') {
            return Err(OidcError::InvalidInput(format!(
                "Invalid email format: {}",
                email
            )));
        }
        Ok(())
    }
}
