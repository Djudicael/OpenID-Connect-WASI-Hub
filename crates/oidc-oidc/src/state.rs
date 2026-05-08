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
}

impl OidcState {
    /// Open a new database connection.
    pub async fn connect(&self) -> Result<Connection, oidc_core::OidcError> {
        let conn = wasi_pg_client::Connection::connect(&self.db_config)
            .await
            .map_err(|e| oidc_core::OidcError::Internal(e.to_string()))?;
        Ok(Connection::from_pg_client(conn))
    }
}
