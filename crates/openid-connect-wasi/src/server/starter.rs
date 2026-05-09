//! Server startup logic for native and WASM runtimes.

use crate::router;
use crate::state::AppState;
use axum::Router;

/// Assemble all sub-routers into the application router.
pub fn build_router() -> Router {
    let state = AppState::from_env();

    // Rate limiter shared state (per-IP, in-memory)
    let rate_limiter = std::sync::Arc::new(crate::middleware::rate_limit::RateLimiter::from_env());

    Router::new()
        .merge(router::oidc::router())
        .merge(router::apikey::router())
        .merge(router::health::router())
        .merge(router::admin::router())
        .with_state(state.clone())
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .layer(crate::middleware::cors::cors_layer())
        .layer(axum::middleware::from_fn(
            crate::middleware::security_headers::security_headers_middleware,
        ))
        .layer(axum::middleware::from_fn(
            crate::middleware::rate_limit::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn(
            crate::middleware::logging::logging_middleware,
        ))
        // Make the RateLimiter available to the middleware via extensions
        .layer(axum::Extension(rate_limiter))
}

/// Run the axum server on a TCP listener with graceful shutdown on SIGTERM.
#[cfg(not(target_arch = "wasm32"))]
pub async fn run_tcp(app: Router, addr: &str, port: u16) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(format!("{}:{}", addr, port)).await?;
    tracing::info!("Listening on {}:{}", addr, port);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        sigterm.recv().await;
    }
    #[cfg(windows)]
    {
        let mut ctrl_c =
            tokio::signal::windows::ctrl_c().expect("failed to install Ctrl-C handler");
        ctrl_c.recv().await;
    }
    tracing::info!("shutdown signal received, starting graceful shutdown");
}
