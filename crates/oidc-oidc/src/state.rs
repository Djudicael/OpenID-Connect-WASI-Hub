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
                let rsa_private_pem =
                    self.decrypt_sensitive_string_or_plaintext(&keys.rsa_private_pem)?;
                let ed25519_private_pem =
                    self.decrypt_sensitive_string_or_plaintext(&keys.ed25519_private_pem)?;
                let svc = Arc::new(JwtTokenService::from_pems(
                    &self.issuer,
                    &rsa_private_pem,
                    &keys.rsa_kid,
                    &ed25519_private_pem,
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

    /// Decrypt an arbitrary sensitive value using the server's encryption key.
    ///
    /// The encrypted value is base64-encoded and contains: nonce (12 bytes) + ciphertext + tag.
    pub fn decrypt_sensitive_value(
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

    /// Encrypt an arbitrary sensitive value using the server's encryption key.
    ///
    /// Returns a base64-encoded string containing: nonce (12 bytes) + ciphertext + tag.
    pub fn encrypt_sensitive_value(&self, raw_key: &[u8]) -> Result<String, oidc_core::OidcError> {
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

    /// Decrypt a client's JWE symmetric key using the server's encryption key.
    pub fn decrypt_client_encryption_key(
        &self,
        encrypted: &str,
    ) -> Result<Vec<u8>, oidc_core::OidcError> {
        self.decrypt_sensitive_value(encrypted)
    }

    /// Encrypt a client's JWE symmetric key using the server's encryption key.
    pub fn encrypt_client_encryption_key(
        &self,
        raw_key: &[u8],
    ) -> Result<String, oidc_core::OidcError> {
        self.encrypt_sensitive_value(raw_key)
    }

    /// Decrypt a UTF-8 secret that may still be stored in legacy plaintext form.
    pub fn decrypt_sensitive_string_or_plaintext(
        &self,
        value: &str,
    ) -> Result<String, oidc_core::OidcError> {
        match self.decrypt_sensitive_value(value) {
            Ok(bytes) => String::from_utf8(bytes).map_err(|_| {
                oidc_core::OidcError::Internal("decrypted secret is not valid UTF-8".into())
            }),
            Err(_) => Ok(value.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn test_state() -> OidcState {
        let realm_keys = crate::tokens::keygen::generate_realm_keys(uuid::Uuid::new_v4())
            .expect("test signing key generation should succeed");
        OidcState {
            issuer: "http://localhost:8080".to_string(),
            token_service: Arc::new(
                JwtTokenService::from_pems(
                    "http://localhost:8080",
                    &realm_keys.rsa_private_pem,
                    &realm_keys.rsa_kid,
                    &realm_keys.ed25519_private_pem,
                    &realm_keys.ed25519_kid,
                )
                .expect("token service should initialize"),
            ),
            hasher: Arc::new(oidc_core::traits::hasher::Argon2idHasher::new()),
            email_sender: Arc::new(oidc_core::traits::noop_email::NoOpEmailSender),
            db_config: wasi_pg_client::Config::from_uri(
                "postgresql://localhost/oidc_hub?sslmode=prefer",
            )
            .expect("test database URL should parse"),
            encryption_key: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .to_string(),
            realm_token_services: Arc::new(Mutex::new(HashMap::new())),
            pairwise_salt: "test-pairwise-salt".to_string(),
        }
    }

    #[test]
    fn sensitive_value_roundtrip_encrypts_and_decrypts() {
        let state = test_state();
        let plaintext = b"secret-value";
        let encrypted = state
            .encrypt_sensitive_value(plaintext)
            .expect("encryption should succeed");

        assert_ne!(encrypted, String::from_utf8_lossy(plaintext));
        let decrypted = state
            .decrypt_sensitive_value(&encrypted)
            .expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_sensitive_string_or_plaintext_accepts_legacy_plaintext() {
        let state = test_state();
        let value = state
            .decrypt_sensitive_string_or_plaintext("plain-secret")
            .expect("plaintext fallback should succeed");
        assert_eq!(value, "plain-secret");
    }
}
