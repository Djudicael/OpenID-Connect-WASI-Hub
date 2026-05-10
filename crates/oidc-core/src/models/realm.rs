use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::OidcError;

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_realm() -> Realm {
        Realm {
            id: Uuid::now_v7(),
            name: "production".into(),
            display_name: "Production".into(),
            enabled: true,
            config: serde_json::Value::Object(serde_json::Map::new()),
            deleted_at: None,
        }
    }

    #[test]
    fn test_realm_validate_valid() {
        let realm = valid_realm();
        assert!(realm.validate().is_ok());
    }

    #[test]
    fn test_realm_validate_empty_name() {
        let mut realm = valid_realm();
        realm.name = "".into();
        let err = realm.validate().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("empty")));
    }
}

/// A realm (tenant) in the OIDC hub.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Realm {
    /// Unique identifier (UUID v7).
    pub id: Uuid,
    /// Machine-readable name (e.g., "production").
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Whether the realm is enabled.
    pub enabled: bool,
    /// Realm-specific configuration as JSON.
    pub config: serde_json::Value,
    /// When the realm was soft-deleted.
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Realm {
    /// Validate the realm fields.
    pub fn validate(&self) -> Result<(), OidcError> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(OidcError::InvalidInput("name must not be empty".into()));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(OidcError::InvalidInput(
                "name must be lowercase alphanumeric with dashes or underscores".into(),
            ));
        }
        Ok(())
    }
}
