//! Application state shared across all request handlers.

use std::sync::Arc;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Application configuration.
    pub config: Arc<AppConfig>,
    /// JWT token service.
    pub token_service: Arc<oidc_oidc::tokens::JwtTokenService>,
    /// Password/API-key hasher.
    pub hasher: Arc<dyn oidc_core::traits::Hasher>,
    /// Database configuration for per-request connections.
    pub db_config: wasi_pg_client::Config,
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
    /// Encryption key for cookies/JWE (base64, 32 bytes).
    pub encryption_key: String,
}

impl oidc_apikey::ApiKeyVerifierState for AppState {
    fn db_config(&self) -> &wasi_pg_client::Config {
        &self.db_config
    }
}

impl AppState {
    /// Build state directly from a config struct (no env vars).
    pub fn from_config(config: AppConfig) -> Self {
        let token_service =
            Arc::new(oidc_oidc::tokens::JwtTokenService::new(&config.issuer).unwrap());
        let hasher = Arc::new(oidc_core::traits::hasher::Argon2idHasher::new());

        let db_config = wasi_pg_client::Config::from_uri(&config.database_url)
            .unwrap_or_else(|_| wasi_pg_client::Config::new());

        Self {
            config: Arc::new(config),
            token_service,
            hasher,
            db_config,
        }
    }

    /// Load state from environment variables.
    pub fn from_env() -> Self {
        let config = AppConfig {
            database_url: std::env::var("OIDC_DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://localhost/oidc_hub".into()),
            bind_address: std::env::var("OIDC_SERVER_BIND_ADDRESS")
                .unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("OIDC_SERVER_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8080),
            issuer: std::env::var("OIDC_ISSUER").unwrap_or_else(|_| "http://localhost:8080".into()),
            encryption_key: std::env::var("OIDC_ENCRYPTION_KEY").expect(
                "OIDC_ENCRYPTION_KEY environment variable must be set (32-byte base64 key)",
            ),
        };
        Self::from_config(config)
    }

    /// Build the OIDC state used by `oidc-oidc` handlers.
    pub fn oidc_state(&self) -> oidc_oidc::state::OidcState {
        oidc_oidc::state::OidcState {
            issuer: self.config.issuer.clone(),
            token_service: self.token_service.clone(),
            hasher: self.hasher.clone(),
            db_config: wasi_pg_client::Config::from_uri(&self.config.database_url)
                .unwrap_or_else(|_| wasi_pg_client::Config::new()),
            encryption_key: self.config.encryption_key.clone(),
            realm_token_services: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }
    }
}
