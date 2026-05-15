use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::OidcError;

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_group() -> Group {
        Group {
            id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            name: "engineering".into(),
            description: Some("Engineering team".into()),
            parent_id: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_group_validate_valid() {
        let group = valid_group();
        assert!(group.validate().is_ok());
    }

    #[test]
    fn test_group_validate_valid_with_hyphens() {
        let mut group = valid_group();
        group.name = "back-end".into();
        assert!(group.validate().is_ok());
    }

    #[test]
    fn test_group_validate_valid_with_spaces() {
        let mut group = valid_group();
        group.name = "engineering team".into();
        assert!(group.validate().is_ok());
    }

    #[test]
    fn test_group_validate_valid_with_alphanumeric() {
        let mut group = valid_group();
        group.name = "team123".into();
        assert!(group.validate().is_ok());
    }

    #[test]
    fn test_group_validate_empty_name() {
        let mut group = valid_group();
        group.name = "".into();
        let err = group.validate().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("empty")));
    }

    #[test]
    fn test_group_validate_too_short() {
        let mut group = valid_group();
        group.name = "a".into();
        let err = group.validate().unwrap_err();
        assert!(
            matches!(err, OidcError::InvalidInput(ref s) if s.contains("2") && s.contains("100"))
        );
    }

    #[test]
    fn test_group_validate_too_long() {
        let mut group = valid_group();
        group.name = "a".repeat(101);
        let err = group.validate().unwrap_err();
        assert!(
            matches!(err, OidcError::InvalidInput(ref s) if s.contains("2") && s.contains("100"))
        );
    }

    #[test]
    fn test_group_validate_invalid_characters() {
        let mut group = valid_group();
        group.name = "team@dev".into(); // @ not allowed
        let err = group.validate().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("alphanumeric")));
    }

    #[test]
    fn test_group_validate_exactly_2_chars() {
        let mut group = valid_group();
        group.name = "ab".into();
        assert!(group.validate().is_ok());
    }

    #[test]
    fn test_group_validate_exactly_100_chars() {
        let mut group = valid_group();
        group.name = "a".repeat(100);
        assert!(group.validate().is_ok());
    }
}

/// A group within a realm (e.g., "engineering", "managers").
///
/// Groups are collections of users that can have roles assigned.
/// Groups can be hierarchical via the `parent_id` field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Group {
    /// Unique identifier (UUID v7).
    pub id: Uuid,
    /// The realm this group belongs to.
    pub realm_id: Uuid,
    /// Human-readable name (e.g., "engineering", "managers").
    pub name: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Parent group ID for hierarchical groups.
    pub parent_id: Option<Uuid>,
    /// When the group was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the group was last updated.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Group {
    /// Validate the group fields.
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
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ' ')
        {
            return Err(OidcError::InvalidInput(
                "name must be alphanumeric with hyphens or spaces".into(),
            ));
        }
        Ok(())
    }
}
