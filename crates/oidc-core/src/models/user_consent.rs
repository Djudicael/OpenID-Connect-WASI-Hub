use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Scopes a user has approved for an OIDC client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserConsent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub realm_id: Uuid,
    pub client_id: Uuid,
    pub scopes: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
