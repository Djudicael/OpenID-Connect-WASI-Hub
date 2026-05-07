//! Server startup logic for native and WASM runtimes.

use crate::router;
use axum::Router;

/// Assemble all sub-routers into the application router.
pub fn build_router() -> Router {
    Router::new()
        .merge(router::oidc::router())
        .merge(router::apikey::router())
        .merge(router::mls::router())
        .merge(router::health::router())
        .merge(router::admin::router())
        .layer(crate::middleware::cors::cors_layer())
        .layer(axum::middleware::from_fn(
            crate::middleware::logging::logging_middleware,
        ))
}
