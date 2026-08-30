//! Health and observability routes.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};
use std::future::Future;
use std::time::Duration;

use crate::state::AppState;

const DATABASE_HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

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
async fn ready_handler(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let db_ok = check_database(&state).await;

    if db_ok {
        (
            StatusCode::OK,
            Json(json!({"status": "ready", "checks": {"database": "ok"}})),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready", "checks": {"database": "failed"}})),
        )
    }
}

/// Liveness probe (always returns ok).
async fn live_handler() -> Json<Value> {
    Json(json!({"status": "alive"}))
}

/// Check database connectivity by opening a connection and running a simple query.
async fn check_database(state: &AppState) -> bool {
    match run_with_timeout(DATABASE_HEALTH_TIMEOUT, check_database_unbounded(state)).await {
        Some(result) => result,
        None => {
            tracing::warn!(
                timeout_ms = DATABASE_HEALTH_TIMEOUT.as_millis(),
                "Database readiness check timed out"
            );
            false
        }
    }
}

async fn check_database_unbounded(state: &AppState) -> bool {
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

#[cfg(not(target_arch = "wasm32"))]
async fn run_with_timeout<F>(timeout: Duration, future: F) -> Option<F::Output>
where
    F: Future,
{
    tokio::time::timeout(timeout, future).await.ok()
}

#[cfg(target_arch = "wasm32")]
async fn run_with_timeout<F>(timeout: Duration, future: F) -> Option<F::Output>
where
    F: Future,
{
    use std::task::Poll;

    let mut future = std::pin::pin!(future);
    let timer = wstd::time::Timer::after(timeout.into());
    let mut timeout_wait = std::pin::pin!(timer.wait());

    std::future::poll_fn(|cx| {
        if let Poll::Ready(output) = future.as_mut().poll(cx) {
            return Poll::Ready(Some(output));
        }
        if timeout_wait.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timeout_returns_completed_value() {
        let result = run_with_timeout(Duration::from_secs(1), async { 42 }).await;
        assert_eq!(result, Some(42));
    }

    #[tokio::test]
    async fn timeout_cancels_pending_health_work() {
        let result =
            run_with_timeout(Duration::from_millis(10), std::future::pending::<()>()).await;
        assert_eq!(result, None);
    }
}
