use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CibaClientConfig {
    pub client_id: Uuid,
    pub delivery_mode: String,
    pub client_notification_endpoint: Option<String>,
    pub request_lifetime_seconds: i32,
    pub polling_interval_seconds: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CibaAuthenticationRequest {
    pub id: Uuid,
    pub auth_req_id_hash: String,
    #[serde(skip_serializing)]
    pub auth_req_id_encrypted: String,
    pub client_id: Uuid,
    pub realm_id: Uuid,
    pub user_id: Uuid,
    pub scope: Vec<String>,
    pub binding_message: Option<String>,
    pub request_context: Option<String>,
    #[serde(skip_serializing)]
    pub client_notification_token_encrypted: Option<String>,
    pub delivery_mode: String,
    pub client_notification_endpoint: Option<String>,
    pub status: String,
    pub interval_seconds: i32,
    pub last_polled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub requested_acr: Vec<String>,
    pub auth_time: Option<chrono::DateTime<chrono::Utc>>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
