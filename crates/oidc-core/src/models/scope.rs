use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A realm-scoped OAuth2 scope.
///
/// Scopes define permissions that clients can request during the OAuth2 flow.
/// Each scope belongs to exactly one realm and can be assigned to multiple
/// clients via the `client_scopes` junction table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Scope {
    /// Unique identifier (UUID v4).
    pub id: Uuid,
    /// The realm this scope belongs to.
    pub realm_id: Uuid,
    /// A human-readable name (e.g., "openid", "profile", "email").
    pub name: String,
    /// Optional human-readable description of the scope.
    pub description: Option<String>,
    /// Whether this scope is currently enabled.
    pub enabled: bool,
}
