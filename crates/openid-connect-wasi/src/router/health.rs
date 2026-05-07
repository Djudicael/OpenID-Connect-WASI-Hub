//! Health and observability routes.

use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

/// Build the health sub-router.
pub fn router() -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/health/ready", get(ready_handler))
        .route("/health/live", get(live_handler))
}

/// Basic health check.
async fn health_handler() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Readiness probe (checks DB connectivity).
async fn ready_handler() -> Json<Value> {
    // TODO: check database connectivity
    Json(json!({"status": "ready"}))
}

/// Liveness probe (always returns ok).
async fn live_handler() -> Json<Value> {
    Json(json!({"status": "alive"}))
}
