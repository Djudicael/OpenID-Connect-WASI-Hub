use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SamlRealmKey {
    pub realm_id: Uuid,
    #[serde(skip_serializing)]
    pub private_key_encrypted: String,
    pub certificate_pem: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SamlServiceProvider {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub name: String,
    pub entity_id: String,
    pub metadata_xml: String,
    pub enabled: bool,
    pub require_signed_requests: bool,
    pub sign_responses: bool,
    pub sign_assertions: bool,
    pub encrypt_assertions: bool,
    pub attribute_mapping: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SamlPendingRequest {
    pub id: Uuid,
    pub token_hash: String,
    pub realm_id: Uuid,
    pub service_provider_id: Option<Uuid>,
    pub identity_provider_id: Option<Uuid>,
    pub purpose: String,
    pub wire_payload: Option<String>,
    pub binding: Option<String>,
    pub relay_state: Option<String>,
    pub tracker: Option<serde_json::Value>,
    pub return_to: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}
