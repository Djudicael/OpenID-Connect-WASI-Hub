use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::OidcError;

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
