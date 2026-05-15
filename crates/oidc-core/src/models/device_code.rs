use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A Device Authorization Code as defined by RFC 8628.
///
/// Represents a device code that a client uses to poll the token endpoint
/// while the user authorizes the request on a separate device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceCode {
    /// Unique identifier.
    pub id: Uuid,
    /// The client this device code was issued to.
    pub client_id: Uuid,
    /// The realm this device code belongs to.
    pub realm_id: Uuid,
    /// SHA-256 hash of the opaque device code (stored at rest, never plaintext).
    pub device_code: String,
    /// Human-readable code the user enters (e.g. "ABCD-EFGH").
    pub user_code: String,
    /// Full URL the user visits to authorize the device.
    pub verification_uri: String,
    /// Full URL including the user_code for convenience.
    pub verification_uri_complete: Option<String>,
    /// When the device code expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Minimum polling interval in seconds (default 5).
    pub interval: i32,
    /// Whether the device code has been exchanged for tokens.
    pub used: bool,
    /// Whether the user has authorized the device code.
    pub authorized: bool,
    /// The user who authorized the device code (set on authorization).
    pub user_id: Option<Uuid>,
    /// Requested scopes.
    pub scope: Vec<String>,
    /// When the device code was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}
