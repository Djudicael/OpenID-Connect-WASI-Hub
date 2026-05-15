use base64::Engine;
use std::collections::HashMap;
use std::sync::Arc;

use oidc_core::traits::Hasher;
use oidc_core::traits::email::EmailSender;
use oidc_repository::Connection;

use crate::tokens::JwtTokenService;

/// Shared state for OIDC handlers.
#[derive(Clone)]
pub struct OidcState {
    /// Issuer URL.
    pub issuer: String,
    /// JWT token service (global fallback for realms without custom keys).
    pub token_service: Arc<JwtTokenService>,
    /// Password/API-key hasher.
    pub hasher: Arc<dyn Hasher>,
    /// Email sender service.
    pub email_sender: Arc<dyn EmailSender>,
    /// Database configuration for per-request connections.
    pub db_config: wasi_pg_client::Config,
    /// Encryption key for session cookie HMAC (hex-encoded 32 bytes).
    pub encryption_key: String,
    /// Per-realm token services loaded on demand.
    pub realm_token_services: Arc<std::sync::Mutex<HashMap<uuid::Uuid, Arc<JwtTokenService>>>>,
    /// Salt for pairwise subject identifier computation.
    pub pairwise_salt: String,
}

impl OidcState {
    /// Open a new database connection.
    pub async fn connect(&self) -> Result<Connection, oidc_core::OidcError> {
        let conn = wasi_pg_client::Connection::connect(&self.db_config)
            .await
            .map_err(|e| oidc_core::OidcError::Internal(e.to_string()))?;
        Ok(Connection::from_pg_client(conn))
    }

    /// Decode the hex-encoded encryption key into raw bytes.
    /// Returns an error if the key is not valid hex or is not 32 bytes.
    pub fn decode_encryption_key(&self) -> Result<[u8; 32], oidc_core::OidcError> {
        let bytes = hex::decode(&self.encryption_key).map_err(|e| {
            oidc_core::OidcError::Internal(format!("Invalid encryption key hex: {e}"))
        })?;
        if bytes.len() != 32 {
            return Err(oidc_core::OidcError::Internal(
                "Encryption key must be 32 bytes (64 hex chars)".to_string(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    /// Get the token service for a specific realm.
    ///
    /// If the realm has realm-specific signing keys stored in the database, a
    /// dedicated [`JwtTokenService`] is built from those keys and cached.
    /// Otherwise the global `token_service` is returned as a fallback.
    pub async fn token_service_for_realm(
        &self,
        realm_id: uuid::Uuid,
    ) -> Result<Arc<JwtTokenService>, oidc_core::OidcError> {
        // Fast path: check cache (lock is never held across await points)
        {
            let cache = self
                .realm_token_services
                .lock()
                .map_err(|e| oidc_core::OidcError::Internal(e.to_string()))?;
            if let Some(svc) = cache.get(&realm_id) {
                return Ok(svc.clone());
            }
        }

        // Slow path: load from DB
        let mut conn = self.connect().await?;
        match oidc_repository::repositories::realm_signing_keys_repo::RealmSigningKeysRepo
            .find_by_realm_id(&mut conn, realm_id)
            .await
        {
            Ok(Some(keys)) => {
                let svc = Arc::new(JwtTokenService::from_pems(
                    &self.issuer,
                    &keys.rsa_private_pem,
                    &keys.rsa_kid,
                    &keys.ed25519_private_pem,
                    &keys.ed25519_kid,
                )?);
                {
                    let mut cache = self
                        .realm_token_services
                        .lock()
                        .map_err(|e| oidc_core::OidcError::Internal(e.to_string()))?;
                    cache.insert(realm_id, svc.clone());
                }
                Ok(svc)
            }
            _ => Ok(self.token_service.clone()), // Fallback to global
        }
    }

    /// Decrypt a client's JWE symmetric key using the server's encryption key.
    ///
    /// The encrypted value is base64-encoded and contains: nonce (12 bytes) + ciphertext + tag.
    /// This is used to recover the raw symmetric key for JWE `dir` encryption at
    /// ID token issuance time.
    pub fn decrypt_client_encryption_key(
        &self,
        encrypted: &str,
    ) -> Result<Vec<u8>, oidc_core::OidcError> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encrypted)
            .map_err(|e| {
                oidc_core::OidcError::Internal(format!("Invalid base64 in encryption key: {e}"))
            })?;

        if bytes.len() < 29 {
            // 12 (nonce) + 16 (tag) + 1 (minimum ciphertext)
            return Err(oidc_core::OidcError::Internal(
                "Encrypted key too short".into(),
            ));
        }

        let (nonce_bytes, ct_and_tag) = bytes.split_at(12);
        let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);

        let key_bytes = self.decode_encryption_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| oidc_core::OidcError::Internal(format!("AES key error: {e}")))?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let mut combined = Vec::with_capacity(ct.len() + tag.len());
        combined.extend_from_slice(ct);
        combined.extend_from_slice(tag);

        let decrypted = cipher
            .decrypt(nonce, combined.as_ref())
            .map_err(|e| oidc_core::OidcError::Internal(format!("Decryption error: {e}")))?;

        Ok(decrypted)
    }

    /// Encrypt a client's JWE symmetric key using the server's encryption key.
    ///
    /// Returns a base64-encoded string containing: nonce (12 bytes) + ciphertext + tag.
    /// This is used to securely store the raw symmetric key at rest.
    pub fn encrypt_client_encryption_key(
        &self,
        raw_key: &[u8],
    ) -> Result<String, oidc_core::OidcError> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let key_bytes = self.decode_encryption_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| oidc_core::OidcError::Internal(format!("AES key error: {e}")))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| oidc_core::OidcError::Internal(format!("getrandom failed: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, raw_key)
            .map_err(|e| oidc_core::OidcError::Internal(format!("AES-GCM encrypt error: {e}")))?;

        // ciphertext includes tag appended (last 16 bytes)
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(base64::engine::general_purpose::STANDARD.encode(&result))
    }
}
