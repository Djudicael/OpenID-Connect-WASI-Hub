use std::sync::Arc;

use oidc_core::traits::Hasher;
use oidc_repository::Connection;

use crate::tokens::JwtTokenService;

/// Shared state for OIDC handlers.
#[derive(Clone)]
pub struct OidcState {
    /// Issuer URL.
    pub issuer: String,
    /// JWT token service.
    pub token_service: Arc<JwtTokenService>,
    /// Password/API-key hasher.
    pub hasher: Arc<dyn Hasher>,
    /// Database configuration for per-request connections.
    pub db_config: wasi_pg_client::Config,
    /// Encryption key for session cookie HMAC (hex-encoded 32 bytes).
    pub encryption_key: String,
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
}
