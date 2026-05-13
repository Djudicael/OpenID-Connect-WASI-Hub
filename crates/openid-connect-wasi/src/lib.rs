//! # openid-connect-wasi
//!
//! WASI-first HTTP server for the OpenID Connect Hub.
//! Compiles to both native (dev/tests) and wasm32-wasip2 (production).

#![allow(missing_docs)]

pub mod error;
pub mod middleware;
pub mod router;
pub mod server;
pub mod state;

use axum::Router;

/// Build the application router.
pub fn app_router() -> Router {
    server::starter::build_router()
}

/// WASI P2 HTTP server entry point — only compiled when targeting wasm32.
#[cfg(target_arch = "wasm32")]
#[wstd_axum::http_server]
fn main() -> Router {
    // Initialize tracing so logs are emitted to stderr (visible via wasmtime)
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
    app_router()
}
