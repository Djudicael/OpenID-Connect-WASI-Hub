use std::collections::HashMap;
use std::sync::Arc;

use oidc_core::traits::Hasher;
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
    /// Database configuration for per-request connections.
    pub db_config: wasi_pg_client::Config,
    /// Encryption key for session cookie HMAC (hex-encoded 32 bytes).
    pub encryption_key: String,
    /// Per-realm token services loaded on demand.
    pub realm_token_services: Arc<std::sync::Mutex<HashMap<uuid::Uuid, Arc<JwtTokenService>>>>,
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
}
