use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Cryptographic signing keys for a realm.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RealmSigningKeys {
    pub realm_id: Uuid,
    pub rsa_private_pem: String,
    pub rsa_kid: String,
    pub rsa_public_n: String,
    pub rsa_public_e: String,
    pub ed25519_private_pem: String,
    pub ed25519_kid: String,
    pub ed25519_public_x: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
