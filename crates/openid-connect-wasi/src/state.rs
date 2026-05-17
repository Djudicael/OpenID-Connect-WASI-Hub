//! Application state shared across all request handlers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use uuid::Uuid;

type RealmTokenServiceCache =
    Arc<Mutex<HashMap<(Uuid, String), Arc<oidc_oidc::tokens::JwtTokenService>>>>;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Application configuration.
    pub config: Arc<AppConfig>,
    /// JWT token service.
    pub token_service: Arc<oidc_oidc::tokens::JwtTokenService>,
    /// Password/API-key hasher.
    pub hasher: Arc<dyn oidc_core::traits::Hasher>,
    /// Email sender service.
    pub email_sender: Arc<dyn oidc_core::traits::EmailSender>,
    /// Database configuration for per-request connections.
    pub db_config: wasi_pg_client::Config,
    /// Shared per-realm token-service cache reused across request-scoped `OidcState` clones.
    pub oidc_realm_token_services: RealmTokenServiceCache,
}

fn validate_encryption_key_hex(value: &str) {
    if value.len() != 64 {
        panic!(
            "invalid OIDC_ENCRYPTION_KEY: expected 64 hex characters (32 bytes), got {} characters",
            value.len()
        );
    }

    for pair in value.as_bytes().chunks_exact(2) {
        let pair_str = std::str::from_utf8(pair).expect("hex input should remain valid UTF-8");
        u8::from_str_radix(pair_str, 16).unwrap_or_else(|e| {
            panic!(
                "invalid OIDC_ENCRYPTION_KEY: expected 64 hex characters (32 bytes), got decode error at '{pair_str}': {e}"
            )
        });
    }
}

/// Runtime configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Database connection URL.
    pub database_url: String,
    /// Server bind address.
    pub bind_address: String,
    /// Server port.
    pub port: u16,
    /// Base URL for the issuer.
    pub issuer: String,
    /// Encryption key for cookies/JWE (64 hex chars / 32 bytes).
    pub encryption_key: String,
    /// Salt for pairwise subject identifier computation.
    pub pairwise_salt: String,
    /// RSA signing key in PKCS#1 PEM format (optional, falls back to env var).
    pub signing_key: Option<String>,
    /// Ed25519 signing key in PKCS#8 PEM format (optional, falls back to env var).
    pub ed25519_key: Option<String>,
}

impl oidc_apikey::ApiKeyVerifierState for AppState {
    fn db_config(&self) -> &wasi_pg_client::Config {
        &self.db_config
    }
}

impl AppState {
    /// Decode the configured encryption key into raw bytes.
    pub fn decode_encryption_key(&self) -> Result<[u8; 32], oidc_core::OidcError> {
        let bytes = hex::decode(&self.config.encryption_key).map_err(|e| {
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

    /// Encrypt an arbitrary sensitive value using the server encryption key.
    pub fn encrypt_sensitive_value(
        &self,
        plaintext: &[u8],
    ) -> Result<String, oidc_core::OidcError> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use base64::Engine;

        let key_bytes = self.decode_encryption_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| oidc_core::OidcError::Internal(format!("AES key error: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| oidc_core::OidcError::Internal(format!("getrandom failed: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| oidc_core::OidcError::Internal(format!("AES-GCM encrypt error: {e}")))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(base64::engine::general_purpose::STANDARD.encode(&result))
    }

    /// Decrypt an arbitrary sensitive value using the server encryption key.
    pub fn decrypt_sensitive_value(
        &self,
        encrypted: &str,
    ) -> Result<Vec<u8>, oidc_core::OidcError> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use base64::Engine;

        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encrypted)
            .map_err(|e| {
                oidc_core::OidcError::Internal(format!("Invalid base64 in secret: {e}"))
            })?;

        if bytes.len() < 29 {
            return Err(oidc_core::OidcError::Internal(
                "Encrypted secret too short".into(),
            ));
        }

        let (nonce_bytes, ct_and_tag) = bytes.split_at(12);
        let key_bytes = self.decode_encryption_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| oidc_core::OidcError::Internal(format!("AES key error: {e}")))?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce, ct_and_tag)
            .map_err(|e| oidc_core::OidcError::Internal(format!("Decryption error: {e}")))?;

        Ok(decrypted)
    }

    /// Build state directly from a config struct (no env vars).
    pub fn from_config(config: AppConfig) -> Self {
        validate_encryption_key_hex(&config.encryption_key);

        let token_service = Arc::new(
            oidc_oidc::tokens::JwtTokenService::with_keys(
                &config.issuer,
                config.signing_key.clone(),
                config.ed25519_key.clone(),
            )
            .unwrap_or_else(|e| {
                panic!(
                    "failed to initialize JWT token service with issuer '{}': {e}",
                    config.issuer
                )
            }),
        );
        let hasher = Arc::new(oidc_core::traits::hasher::Argon2idHasher::new());
        let email_sender = Arc::new(oidc_core::traits::noop_email::NoOpEmailSender);

        let db_config = wasi_pg_client::Config::from_uri(&config.database_url)
            .unwrap_or_else(|e| panic!("invalid OIDC_DATABASE_URL '{}': {e}", config.database_url));

        Self {
            config: Arc::new(config),
            token_service,
            hasher,
            email_sender,
            db_config,
            oidc_realm_token_services: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Load state from environment variables.
    pub fn from_env() -> Self {
        let database_url = std::env::var("OIDC_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://localhost/oidc_hub?sslmode=prefer".into());
        if !std::env::var("OIDC_DATABASE_URL").is_ok() {
            tracing::warn!(
                "OIDC_DATABASE_URL not set — using default (not suitable for production)"
            );
        }

        let issuer =
            std::env::var("OIDC_ISSUER").unwrap_or_else(|_| "http://localhost:8080".into());
        if !std::env::var("OIDC_ISSUER").is_ok() {
            tracing::warn!(
                "OIDC_ISSUER not set — using default localhost (not suitable for production)"
            );
        }

        let config = AppConfig {
            database_url,
            bind_address: std::env::var("OIDC_SERVER_BIND_ADDRESS")
                .unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("OIDC_SERVER_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8080),
            issuer,
            encryption_key: std::env::var("OIDC_ENCRYPTION_KEY").expect(
                "OIDC_ENCRYPTION_KEY environment variable must be set (64 hex chars / 32 bytes)",
            ),
            pairwise_salt: std::env::var("OIDC_PAIRWISE_SALT").expect(
                "OIDC_PAIRWISE_SALT environment variable must be set — a predictable salt breaks pairwise subject identifier privacy guarantees",
            ),
            signing_key: None,
            ed25519_key: None,
        };
        Self::from_config(config)
    }

    /// Build the OIDC state used by `oidc-oidc` handlers.
    pub fn oidc_state(&self) -> oidc_oidc::state::OidcState {
        oidc_oidc::state::OidcState {
            issuer: self.config.issuer.clone(),
            base_issuer: self.config.issuer.clone(),
            token_service: self.token_service.clone(),
            hasher: self.hasher.clone(),
            email_sender: self.email_sender.clone(),
            db_config: self.db_config.clone(),
            encryption_key: self.config.encryption_key.clone(),
            realm_token_services: self.oidc_realm_token_services.clone(),
            pairwise_salt: self.config.pairwise_salt.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AppConfig {
        let realm_keys = oidc_oidc::tokens::keygen::generate_realm_keys(Uuid::new_v4())
            .expect("test signing key generation should succeed");
        AppConfig {
            database_url: "postgresql://localhost/oidc_hub?sslmode=prefer".to_string(),
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            issuer: "http://localhost:8080".to_string(),
            encryption_key: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .to_string(),
            pairwise_salt: "test-pairwise-salt".to_string(),
            signing_key: Some(realm_keys.rsa_private_pem.clone()),
            ed25519_key: Some(realm_keys.ed25519_private_pem.clone()),
        }
    }

    #[test]
    fn oidc_state_reuses_realm_token_service_cache_across_requests() {
        let state = AppState::from_config(test_config());

        let oidc_state_a = state.oidc_state();
        let oidc_state_b = state.oidc_state();

        assert!(Arc::ptr_eq(
            &oidc_state_a.realm_token_services,
            &oidc_state_b.realm_token_services,
        ));

        let realm_id = Uuid::new_v4();
        let cache_key = (realm_id, oidc_state_a.issuer.clone());
        oidc_state_a
            .realm_token_services
            .lock()
            .expect("cache lock should succeed")
            .insert(cache_key.clone(), state.token_service.clone());

        assert!(
            oidc_state_b
                .realm_token_services
                .lock()
                .expect("cache lock should succeed")
                .contains_key(&cache_key)
        );
    }

    #[test]
    #[should_panic(expected = "invalid OIDC_ENCRYPTION_KEY")]
    fn from_config_rejects_non_hex_encryption_key() {
        let mut config = test_config();
        config.encryption_key = "not-hex".to_string();
        let _ = AppState::from_config(config);
    }

    #[test]
    #[should_panic(expected = "expected 64 hex characters")]
    fn from_config_rejects_wrong_length_encryption_key() {
        let mut config = test_config();
        config.encryption_key = "00112233".to_string();
        let _ = AppState::from_config(config);
    }

    #[test]
    fn sensitive_value_roundtrip_encrypts_and_decrypts() {
        let state = AppState::from_config(test_config());
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
}
