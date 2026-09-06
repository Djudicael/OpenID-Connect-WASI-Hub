use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    #[serde(skip_serializing)]
    pub secret_encrypted: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    #[serde(skip_serializing)]
    pub credential: serde_json::Value,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct RecoveryCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct MfaCeremony {
    pub id: Uuid,
    pub token_hash: String,
    pub user_id: Uuid,
    pub realm_id: Uuid,
    pub client_id: Option<Uuid>,
    pub purpose: String,
    pub state: serde_json::Value,
    pub attempts: i32,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
