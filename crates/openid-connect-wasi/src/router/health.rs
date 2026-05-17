//! Health and observability routes.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

use crate::state::AppState;

/// Build the health sub-router.
pub fn router() -> Router<AppState> {
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
async fn ready_handler(State(state): State<AppState>) -> Json<Value> {
    let db_ok = check_database(&state).await;

    if db_ok {
        Json(json!({"status": "ready", "checks": {"database": "ok"}}))
    } else {
        Json(json!({"status": "not_ready", "checks": {"database": "failed"}}))
    }
}

/// Liveness probe (always returns ok).
async fn live_handler() -> Json<Value> {
    Json(json!({"status": "alive"}))
}

/// Check database connectivity by opening a connection and running a simple query.
async fn check_database(state: &AppState) -> bool {
    match wasi_pg_client::Connection::connect(&state.db_config).await {
        Ok(mut conn) => match conn.query("SELECT 1").await {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!("Database query failed: {}", e);
                false
            }
        },
        Err(e) => {
            tracing::warn!("Database connection failed: {}", e);
            false
        }
    }
}
