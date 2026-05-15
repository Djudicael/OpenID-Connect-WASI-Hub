use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::OidcError;

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_user() -> User {
        User {
            id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            email: "alice@example.com".into(),
            email_verified: true,
            username: Some("alice".into()),
            password_hash: Some("$argon2id$...".into()),
            given_name: Some("Alice".into()),
            family_name: Some("Smith".into()),
            middle_name: None,
            nickname: None,
            preferred_username: None,
            profile: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            phone_number: None,
            phone_number_verified: None,
            street_address: None,
            locality: None,
            region: None,
            postal_code: None,
            country: None,
            locale: "en".into(),
            attributes: serde_json::Value::Object(serde_json::Map::new()),
            enabled: true,
            deleted_at: None,
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_user_validate_valid() {
        let user = valid_user();
        assert!(user.validate().is_ok());
    }

    #[test]
    fn test_user_validate_empty_email() {
        let mut user = valid_user();
        user.email = "".into();
        let err = user.validate().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("empty")));
    }

    #[test]
    fn test_user_validate_no_at_sign() {
        let mut user = valid_user();
        user.email = "noemail".into();
        let err = user.validate().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(_)));
    }

    #[test]
    fn test_user_validate_no_dot() {
        let mut user = valid_user();
        user.email = "test@com".into();
        let err = user.validate().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(_)));
    }
}

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
    /// Middle name.
    pub middle_name: Option<String>,
    /// Nickname.
    pub nickname: Option<String>,
    /// Preferred username.
    pub preferred_username: Option<String>,
    /// Profile URL.
    pub profile: Option<String>,
    /// Picture URL.
    pub picture: Option<String>,
    /// Website URL.
    pub website: Option<String>,
    /// Gender.
    pub gender: Option<String>,
    /// Birthdate (ISO-8601).
    pub birthdate: Option<String>,
    /// Zoneinfo (IANA TZ).
    pub zoneinfo: Option<String>,
    /// Phone number.
    pub phone_number: Option<String>,
    /// Whether the phone number has been verified.
    pub phone_number_verified: Option<bool>,
    /// Street address component (OIDC Core §5.1.1).
    /// May contain multiple lines separated by `\n` for European addresses.
    pub street_address: Option<String>,
    /// City or locality (OIDC Core §5.1.1).
    pub locality: Option<String>,
    /// State, province, region (OIDC Core §5.1.1).
    /// Generic for any locale: US state, French région, German Bundesland, etc.
    pub region: Option<String>,
    /// Postal code / zip code (OIDC Core §5.1.1).
    /// Supports any format: US 5-digit, French 5-digit, UK alphanumeric, etc.
    pub postal_code: Option<String>,
    /// Country — ISO 3166-1 alpha-2 code preferred (OIDC Core §5.1.1).
    /// E.g., "US", "FR", "DE", "ES", "GB".
    pub country: Option<String>,
    /// Locale preference (e.g., "en", "fr"). Defaults to "en".
    pub locale: String,
    /// Arbitrary key-value attributes.
    pub attributes: serde_json::Value,
    /// Whether the account is enabled.
    pub enabled: bool,
    /// When the user was soft-deleted.
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the user record was last updated.
    pub updated_at: chrono::DateTime<chrono::Utc>,
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

    /// Build an `AddressClaim` from the user's address fields.
    /// Returns `None` if all address fields are empty.
    ///
    /// The `formatted` field is auto-generated from the component fields
    /// using European-friendly formatting (postal code before city).
    pub fn address_claim(&self) -> Option<crate::models::AddressClaim> {
        let claim = crate::models::AddressClaim::from_components(
            None, // auto-generate formatted
            self.street_address.clone(),
            self.locality.clone(),
            self.region.clone(),
            self.postal_code.clone(),
            self.country.clone(),
        );
        if claim.is_empty() { None } else { Some(claim) }
    }
}
