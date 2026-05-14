use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A Pushed Authorization Request (PAR) as defined by RFC 9126.
///
/// Stores the original authorization request parameters pushed by the client
/// to the PAR endpoint. The `request_uri_token` is the opaque value returned
/// to the client and later presented at the authorize endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PushedAuthorizationRequest {
    /// Unique identifier.
    pub id: Uuid,
    /// The client that pushed this request.
    pub client_id: Uuid,
    /// The realm this request belongs to.
    pub realm_id: Uuid,
    /// The opaque request_uri token returned to the client.
    pub request_uri_token: String,
    /// The original request parameters as JSON.
    pub request_params: serde_json::Value,
    /// When this PAR expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Whether this PAR has already been used.
    pub used: bool,
    /// When this PAR was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}
