//! Application state shared across all request handlers.

use std::sync::Arc;

/// Shared application state.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Application configuration.
    pub config: Arc<AppConfig>,
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
    /// Whether MLS is enabled.
    pub mls_enabled: bool,
}

impl AppState {
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
            issuer: std::env::var("OIDC_ISSUER")
                .unwrap_or_else(|_| "http://localhost:8080".into()),
            encryption_key: std::env::var("OIDC_ENCRYPTION_KEY").unwrap_or_default(),
            mls_enabled: std::env::var("OIDC_MLS_ENABLED")
                .map(|s| s.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        };

        Self {
            config: Arc::new(config),
        }
    }
}
