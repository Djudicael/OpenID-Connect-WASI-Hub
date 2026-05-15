use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::OidcError;
use crate::utils::{generate_opaque_token, sha2_256_hex};

/// An admin-initiated account recovery token.
/// Allows a user who has lost all access methods to regain access
/// by clicking a one-time link and setting a new password.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountRecoveryToken {
    /// Unique identifier.
    pub id: Uuid,
    /// The user whose account is being recovered.
    pub user_id: Uuid,
    /// The realm of the user.
    pub realm_id: Uuid,
    /// SHA-256 hash of the recovery token (one-way, like password reset tokens).
    pub token_hash: String,
    /// When the token expires (24 hours from creation).
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Whether the token has been used.
    pub used: bool,
    /// When the token was used.
    pub used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The admin who initiated the recovery.
    pub created_by: Uuid,
    /// IP address of the admin who created the token.
    pub creator_ip: Option<String>,
    /// When the token was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl AccountRecoveryToken {
    /// Create a new account recovery token.
    ///
    /// Returns a tuple of `(AccountRecoveryToken, raw_token)` where `raw_token`
    /// is the plaintext token that should be embedded in the recovery link.
    /// Only the SHA-256 hash is stored in the database.
    ///
    /// The token expires 24 hours from creation.
    pub fn new(
        user_id: Uuid,
        realm_id: Uuid,
        created_by: Uuid,
        creator_ip: Option<String>,
    ) -> Result<(Self, String), OidcError> {
        let raw_token = generate_opaque_token()?;
        let token_hash = sha2_256_hex(&raw_token);
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::hours(24);

        let entity = Self {
            id: Uuid::new_v4(),
            user_id,
            realm_id,
            token_hash,
            expires_at,
            used: false,
            used_at: None,
            created_by,
            creator_ip,
            created_at: now,
        };

        Ok((entity, raw_token))
    }

    /// Check whether this token has expired.
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    /// Validate a raw token against this stored record.
    ///
    /// Checks:
    /// 1. The SHA-256 hash of `raw_token` matches the stored `token_hash`.
    /// 2. The token has not expired.
    /// 3. The token has not been used.
    pub fn validate(&self, raw_token: &str) -> Result<(), OidcError> {
        // 1. Hash must match
        let computed = sha2_256_hex(raw_token);
        if computed != self.token_hash {
            return Err(OidcError::AuthenticationFailed(
                "invalid account recovery token".into(),
            ));
        }

        // 2. Must not be expired
        if self.is_expired() {
            return Err(OidcError::TokenExpired);
        }

        // 3. Must not be used
        if self.used {
            return Err(OidcError::AuthenticationFailed(
                "account recovery token already used".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_creation_and_hash_verification() {
        let user_id = Uuid::new_v4();
        let realm_id = Uuid::new_v4();
        let created_by = Uuid::new_v4();
        let creator_ip = Some("192.168.1.1".to_string());

        let (token, raw) =
            AccountRecoveryToken::new(user_id, realm_id, created_by, creator_ip.clone()).unwrap();

        // The raw token should be non-empty
        assert!(!raw.is_empty());

        // The stored hash should be SHA-256 of the raw token
        let expected_hash = sha2_256_hex(&raw);
        assert_eq!(token.token_hash, expected_hash);

        // Fields should be set correctly
        assert_eq!(token.user_id, user_id);
        assert_eq!(token.realm_id, realm_id);
        assert_eq!(token.created_by, created_by);
        assert_eq!(token.creator_ip, creator_ip);
        assert!(!token.used);
        assert!(token.used_at.is_none());

        // Expiry should be ~24 hours from now
        let now = chrono::Utc::now();
        let diff = token.expires_at - now;
        assert!(diff.num_hours() >= 23 && diff.num_hours() <= 24);
    }

    #[test]
    fn test_validate_success() {
        let user_id = Uuid::new_v4();
        let realm_id = Uuid::new_v4();
        let created_by = Uuid::new_v4();

        let (token, raw) = AccountRecoveryToken::new(user_id, realm_id, created_by, None).unwrap();

        // Validation should succeed with the correct raw token
        assert!(token.validate(&raw).is_ok());
    }

    #[test]
    fn test_expiry_check() {
        let user_id = Uuid::new_v4();
        let realm_id = Uuid::new_v4();
        let created_by = Uuid::new_v4();

        let (mut token, raw) =
            AccountRecoveryToken::new(user_id, realm_id, created_by, None).unwrap();

        // Not expired initially
        assert!(!token.is_expired());

        // Set expiry to the past
        token.expires_at = chrono::Utc::now() - chrono::Duration::hours(1);
        assert!(token.is_expired());

        // Validation should fail with TokenExpired
        let result = token.validate(&raw);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OidcError::TokenExpired));
    }

    #[test]
    fn test_used_token_rejection() {
        let user_id = Uuid::new_v4();
        let realm_id = Uuid::new_v4();
        let created_by = Uuid::new_v4();

        let (mut token, raw) =
            AccountRecoveryToken::new(user_id, realm_id, created_by, None).unwrap();

        // Mark as used
        token.used = true;
        token.used_at = Some(chrono::Utc::now());

        // Validation should fail
        let result = token.validate(&raw);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::AuthenticationFailed(_)));
        assert!(format!("{}", err).contains("already used"));
    }

    #[test]
    fn test_wrong_token_rejection() {
        let user_id = Uuid::new_v4();
        let realm_id = Uuid::new_v4();
        let created_by = Uuid::new_v4();

        let (token, _raw) = AccountRecoveryToken::new(user_id, realm_id, created_by, None).unwrap();

        // Validation with a wrong token should fail
        let result = token.validate("wrong-token-value");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::AuthenticationFailed(_)));
        assert!(format!("{}", err).contains("invalid account recovery token"));
    }

    #[test]
    fn test_two_tokens_have_different_hashes() {
        let user_id = Uuid::new_v4();
        let realm_id = Uuid::new_v4();
        let created_by = Uuid::new_v4();

        let (t1, r1) = AccountRecoveryToken::new(user_id, realm_id, created_by, None).unwrap();
        let (t2, r2) = AccountRecoveryToken::new(user_id, realm_id, created_by, None).unwrap();

        // Raw tokens should be different
        assert_ne!(r1, r2);

        // Hashes should be different
        assert_ne!(t1.token_hash, t2.token_hash);

        // Each raw token should only validate against its own record
        assert!(t1.validate(&r1).is_ok());
        assert!(t1.validate(&r2).is_err());
        assert!(t2.validate(&r2).is_ok());
        assert!(t2.validate(&r1).is_err());
    }
}
