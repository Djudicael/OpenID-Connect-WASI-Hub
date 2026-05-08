//! Server startup logic for native and WASM runtimes.

use crate::router;
use crate::state::AppState;
use axum::Router;

/// Assemble all sub-routers into the application router.
pub fn build_router() -> Router {
    let state = AppState::from_env();

    Router::new()
        .merge(router::oidc::router())
        .merge(router::apikey::router())
        .merge(router::mls::router())
        .merge(router::health::router())
        .merge(router::admin::router())
        .with_state(state.clone())
        .layer(crate::middleware::cors::cors_layer())
        .layer(axum::middleware::from_fn(
            crate::middleware::logging::logging_middleware,
        ))
}
