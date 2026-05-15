use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::OidcError;

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_role() -> Role {
        Role {
            id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            name: "admin".into(),
            description: Some("Administrator role".into()),
            permissions: vec!["users:read".into(), "users:write".into()],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_role_validate_valid() {
        let role = valid_role();
        assert!(role.validate().is_ok());
    }

    #[test]
    fn test_role_validate_valid_with_hyphens() {
        let mut role = valid_role();
        role.name = "super-admin".into();
        assert!(role.validate().is_ok());
    }

    #[test]
    fn test_role_validate_valid_with_underscores() {
        let mut role = valid_role();
        role.name = "super_admin".into();
        assert!(role.validate().is_ok());
    }

    #[test]
    fn test_role_validate_valid_with_colons() {
        let mut role = valid_role();
        role.name = "realm:admin".into();
        assert!(role.validate().is_ok());
    }

    #[test]
    fn test_role_validate_empty_name() {
        let mut role = valid_role();
        role.name = "".into();
        let err = role.validate().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("empty")));
    }

    #[test]
    fn test_role_validate_too_short() {
        let mut role = valid_role();
        role.name = "a".into();
        let err = role.validate().unwrap_err();
        assert!(
            matches!(err, OidcError::InvalidInput(ref s) if s.contains("2") && s.contains("100"))
        );
    }

    #[test]
    fn test_role_validate_too_long() {
        let mut role = valid_role();
        role.name = "a".repeat(101);
        let err = role.validate().unwrap_err();
        assert!(
            matches!(err, OidcError::InvalidInput(ref s) if s.contains("2") && s.contains("100"))
        );
    }

    #[test]
    fn test_role_validate_invalid_characters() {
        let mut role = valid_role();
        role.name = "admin role".into(); // spaces not allowed
        let err = role.validate().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("alphanumeric")));
    }

    #[test]
    fn test_role_validate_exactly_2_chars() {
        let mut role = valid_role();
        role.name = "ab".into();
        assert!(role.validate().is_ok());
    }

    #[test]
    fn test_role_validate_exactly_100_chars() {
        let mut role = valid_role();
        role.name = "a".repeat(100);
        assert!(role.validate().is_ok());
    }
}

/// A role within a realm (e.g., "admin", "user", "editor").
///
/// Roles are collections of permissions that can be assigned to users
/// directly or through groups.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Role {
    /// Unique identifier (UUID v7).
    pub id: Uuid,
    /// The realm this role belongs to.
    pub realm_id: Uuid,
    /// Machine-readable name (e.g., "admin", "editor").
    pub name: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Permissions granted by this role (e.g., ["users:read", "users:write"]).
    pub permissions: Vec<String>,
    /// When the role was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the role was last updated.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Role {
    /// Validate the role fields.
    pub fn validate(&self) -> Result<(), OidcError> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(OidcError::InvalidInput("name must not be empty".into()));
        }
        let len = name.len();
        if len < 2 || len > 100 {
            return Err(OidcError::InvalidInput(
                "name must be between 2 and 100 characters".into(),
            ));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ':')
        {
            return Err(OidcError::InvalidInput(
                "name must be alphanumeric with hyphens, underscores, or colons".into(),
            ));
        }
        Ok(())
    }
}
