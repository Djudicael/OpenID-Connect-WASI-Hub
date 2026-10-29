//! # openid-connect-wasi
//!
//! WASI-first HTTP server for the OpenID Connect Hub.
//! Compiles to both native (dev/tests) and wasm32-wasip2 (production).

#![allow(missing_docs)]

pub mod dns_verifier;
pub mod email_sender;
pub mod error;
pub mod middleware;
pub mod router;
pub mod server;
pub mod state;

use axum::Router;

/// Build the application router from environment variables.
pub fn app_router() -> Router {
    server::starter::build_router()
}

/// Build the application router with an explicit configuration.
///
/// This is the parallel-safe entry point used by integration tests.
/// Each `TestApp` passes its own isolated `AppConfig` so there is no
/// race on `std::env::set_var`.
pub fn app_router_with_config(config: state::AppConfig) -> Router {
    server::starter::build_router_with_config(config)
}

#[cfg(target_arch = "wasm32")]
wasip3::http::service::export!(HttpServer);

#[cfg(target_arch = "wasm32")]
struct HttpServer;

#[cfg(target_arch = "wasm32")]
impl wasip3::exports::http::handler::Guest for HttpServer {
    async fn handle(
        request: wasip3::http::types::Request,
    ) -> Result<wasip3::http::types::Response, wasip3::http::types::ErrorCode> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();
        oidc_wasi_http::handle(app_router(), request).await
    }
}
