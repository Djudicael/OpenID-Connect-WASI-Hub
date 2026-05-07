use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
}
