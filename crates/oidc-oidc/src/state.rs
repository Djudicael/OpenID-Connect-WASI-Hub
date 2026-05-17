use base64::Engine;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::Arc;

use oidc_core::traits::Hasher;
use oidc_core::traits::email::EmailSender;
use oidc_core::traits::token_service::TokenService;
use oidc_repository::Connection;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;

use crate::tokens::JwtTokenService;

/// Shared state for OIDC handlers.
#[derive(Clone)]
pub struct OidcState {
    /// Effective issuer URL for the current request context.
    pub issuer: String,
    /// Base issuer URL for the deployment, without realm scoping.
    pub base_issuer: String,
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
    /// Per-realm token services loaded on demand and keyed by `(realm_id, issuer)`.
    pub realm_token_services:
        Arc<std::sync::Mutex<HashMap<(uuid::Uuid, String), Arc<JwtTokenService>>>>,
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

    /// Return a clone of this state with a different effective issuer.
    pub fn with_issuer(&self, issuer: impl Into<String>) -> Self {
        let mut cloned = self.clone();
        cloned.issuer = issuer.into();
        cloned
    }

    fn is_realm_scoped_issuer(&self) -> bool {
        let base = self.base_issuer.trim_end_matches('/');
        self.issuer != self.base_issuer && self.issuer.starts_with(&format!("{base}/realms/"))
    }

    fn protocol_endpoint(&self, global_path: &str, realm_path: &str) -> String {
        if self.is_realm_scoped_issuer() {
            format!("{}{}", self.issuer, realm_path)
        } else {
            format!("{}{}", self.issuer, global_path)
        }
    }

    pub fn token_endpoint_uri(&self) -> String {
        self.protocol_endpoint("/oidc/token", "/protocol/openid-connect/token")
    }

    pub fn userinfo_endpoint_uri(&self) -> String {
        self.protocol_endpoint("/oidc/userinfo", "/protocol/openid-connect/userinfo")
    }

    pub fn par_endpoint_uri(&self) -> String {
        self.protocol_endpoint("/oidc/par", "/protocol/openid-connect/par")
    }

    pub fn device_authorization_endpoint_uri(&self) -> String {
        self.protocol_endpoint(
            "/oidc/device/authorize",
            "/protocol/openid-connect/device/authorize",
        )
    }

    pub fn introspection_endpoint_uri(&self) -> String {
        self.protocol_endpoint("/oidc/introspect", "/protocol/openid-connect/introspect")
    }

    pub fn revocation_endpoint_uri(&self) -> String {
        self.protocol_endpoint("/oidc/revoke", "/protocol/openid-connect/revoke")
    }

    pub fn logout_endpoint_uri(&self) -> String {
        self.protocol_endpoint("/oidc/logout", "/protocol/openid-connect/logout")
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

    /// Get the token service for a specific realm using the current request issuer.
    pub async fn token_service_for_realm(
        &self,
        realm_id: uuid::Uuid,
    ) -> Result<Arc<JwtTokenService>, oidc_core::OidcError> {
        self.token_service_for_realm_with_issuer(realm_id, &self.issuer)
            .await
    }

    /// Get the token service for a specific realm using an explicit issuer.
    pub async fn token_service_for_realm_with_issuer(
        &self,
        realm_id: uuid::Uuid,
        issuer: &str,
    ) -> Result<Arc<JwtTokenService>, oidc_core::OidcError> {
        let cache_key = (realm_id, issuer.to_string());

        {
            let cache = self
                .realm_token_services
                .lock()
                .map_err(|e| oidc_core::OidcError::Internal(e.to_string()))?;
            if let Some(svc) = cache.get(&cache_key) {
                return Ok(svc.clone());
            }
        }

        let mut conn = self.connect().await?;
        match oidc_repository::repositories::realm_signing_keys_repo::RealmSigningKeysRepo
            .find_by_realm_id(&mut conn, realm_id)
            .await
        {
            Ok(Some(keys)) => {
                let rsa_private_pem = self.decrypt_sensitive_string(&keys.rsa_private_pem)?;
                let ed25519_private_pem =
                    self.decrypt_sensitive_string(&keys.ed25519_private_pem)?;
                let svc = Arc::new(JwtTokenService::from_pems(
                    issuer,
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
                    cache.insert(cache_key, svc.clone());
                }
                Ok(svc)
            }
            _ => {
                let svc = Arc::new(self.token_service.clone_with_issuer(issuer));
                {
                    let mut cache = self
                        .realm_token_services
                        .lock()
                        .map_err(|e| oidc_core::OidcError::Internal(e.to_string()))?;
                    cache.insert(cache_key, svc.clone());
                }
                Ok(svc)
            }
        }
    }

    /// Verify an access token while honoring either global or realm-scoped issuers.
    pub async fn verify_access_token_with_claims_any_issuer(
        &self,
        token: &str,
    ) -> Result<oidc_core::traits::token_service::VerifiedAccessToken, oidc_core::OidcError> {
        let claims: crate::tokens::jwt_service::AccessTokenClaims =
            Self::decode_jwt_payload_unverified(token)?;
        let client_id = Self::client_id_from_aud(&claims.aud);
        let token_service = self
            .token_service_for_token_context(&claims.iss, client_id.as_deref())
            .await?;
        token_service.verify_access_token_with_claims(token).await
    }

    /// Verify an ID token while honoring either global or realm-scoped issuers.
    pub async fn verify_id_token_any_issuer(
        &self,
        token: &str,
    ) -> Result<String, oidc_core::OidcError> {
        let claims: crate::tokens::jwt_service::IdTokenClaims =
            Self::decode_jwt_payload_unverified(token)?;
        let token_service = self
            .token_service_for_token_context(&claims.iss, Some(&claims.aud))
            .await?;
        token_service.verify_id_token(token).await
    }

    async fn token_service_for_token_context(
        &self,
        issuer: &str,
        client_id: Option<&str>,
    ) -> Result<Arc<JwtTokenService>, oidc_core::OidcError> {
        if let Some(realm_id) = self.resolve_realm_id_from_issuer(issuer).await? {
            return self
                .token_service_for_realm_with_issuer(realm_id, issuer)
                .await;
        }

        if let Some(client_id) = client_id {
            let mut conn = self.connect().await?;
            if let Some(client) = ClientRepo.find_by_client_id(&mut conn, client_id).await? {
                return self
                    .token_service_for_realm_with_issuer(client.realm_id, issuer)
                    .await;
            }
        }

        if issuer == self.base_issuer {
            return Ok(self.token_service.clone());
        }

        Err(oidc_core::OidcError::InvalidTokenSignature)
    }

    async fn resolve_realm_id_from_issuer(
        &self,
        issuer: &str,
    ) -> Result<Option<uuid::Uuid>, oidc_core::OidcError> {
        let normalized_base = self.base_issuer.trim_end_matches('/');
        let normalized_issuer = issuer.trim_end_matches('/');
        if normalized_issuer == normalized_base {
            return Ok(None);
        }

        let prefix = format!("{normalized_base}/realms/");
        let Some(realm_name) = normalized_issuer.strip_prefix(&prefix) else {
            return Ok(None);
        };

        if realm_name.is_empty() || realm_name.contains('/') {
            return Err(oidc_core::OidcError::InvalidTokenSignature);
        }

        let mut conn = self.connect().await?;
        let realm = RealmRepo
            .find_by_name(&mut conn, realm_name)
            .await?
            .ok_or(oidc_core::OidcError::InvalidTokenSignature)?;
        Ok(Some(realm.id))
    }

    fn client_id_from_aud(aud: &serde_json::Value) -> Option<String> {
        match aud {
            serde_json::Value::String(value) => Some(value.clone()),
            serde_json::Value::Array(values) => values
                .first()
                .and_then(|value| value.as_str())
                .map(|value| value.to_string()),
            _ => None,
        }
    }

    fn decode_jwt_payload_unverified<T: DeserializeOwned>(
        token: &str,
    ) -> Result<T, oidc_core::OidcError> {
        let payload_segment = token
            .split('.')
            .nth(1)
            .ok_or(oidc_core::OidcError::InvalidTokenSignature)?;

        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_segment)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload_segment))
            .map_err(|_| oidc_core::OidcError::InvalidTokenSignature)?;

        serde_json::from_slice(&payload_bytes)
            .map_err(|_| oidc_core::OidcError::InvalidTokenSignature)
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

    /// Decrypt an encrypted UTF-8 secret.
    pub fn decrypt_sensitive_string(&self, value: &str) -> Result<String, oidc_core::OidcError> {
        let bytes = self.decrypt_sensitive_value(value)?;
        String::from_utf8(bytes).map_err(|_| {
            oidc_core::OidcError::Internal("decrypted secret is not valid UTF-8".into())
        })
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
            base_issuer: "http://localhost:8080".to_string(),
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
    fn decode_jwt_helpers_switch_endpoint_shape_for_realm_issuers() {
        let state = test_state().with_issuer("http://localhost:8080/realms/master");

        assert_eq!(
            state.token_endpoint_uri(),
            "http://localhost:8080/realms/master/protocol/openid-connect/token"
        );
        assert_eq!(
            state.userinfo_endpoint_uri(),
            "http://localhost:8080/realms/master/protocol/openid-connect/userinfo"
        );
    }

    #[test]
    fn decrypt_sensitive_string_requires_valid_ciphertext() {
        let state = test_state();
        let err = state
            .decrypt_sensitive_string("plain-secret")
            .expect_err("plaintext should no longer be accepted");
        assert!(
            matches!(err, oidc_core::OidcError::Internal(_)),
            "expected internal error for invalid ciphertext"
        );
    }
}
