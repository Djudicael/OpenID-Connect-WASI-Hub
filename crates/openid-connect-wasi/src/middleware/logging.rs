//! Request logging middleware.

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use tracing::info;
use uuid::Uuid;

/// Middleware that adds a trace ID and logs requests.
pub async fn logging_middleware(request: Request<Body>, next: Next) -> Response {
    let trace_id = Uuid::new_v4().to_string();
    let method = request.method().clone();
    let uri = request.uri().clone();

    info!(trace_id = %trace_id, %method, %uri, "request started");

    let response = next.run(request).await;

    info!(
        trace_id = %trace_id,
        status = response.status().as_u16(),
        "request completed"
    );

    response
}
