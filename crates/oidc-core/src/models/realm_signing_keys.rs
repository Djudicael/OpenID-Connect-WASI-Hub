use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Cryptographic signing keys for a realm.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct RealmSigningKeys {
    pub realm_id: Uuid,
    #[serde(skip_serializing)]
    pub rsa_private_pem: String,
    pub rsa_kid: String,
    pub rsa_public_n: String,
    pub rsa_public_e: String,
    #[serde(skip_serializing)]
    pub ed25519_private_pem: String,
    pub ed25519_kid: String,
    pub ed25519_public_x: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Debug for RealmSigningKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealmSigningKeys")
            .field("realm_id", &self.realm_id)
            .field("rsa_private_pem", &"<redacted>")
            .field("rsa_kid", &self.rsa_kid)
            .field("rsa_public_n", &self.rsa_public_n)
            .field("rsa_public_e", &self.rsa_public_e)
            .field("ed25519_private_pem", &"<redacted>")
            .field("ed25519_kid", &self.ed25519_kid)
            .field("ed25519_public_x", &self.ed25519_public_x)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}
