//! Request logging middleware.

use axum::body::Body;
use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use tracing::info;
use uuid::Uuid;

/// Middleware that adds a trace ID and logs requests.
pub async fn logging_middleware(mut request: Request<Body>, next: Next) -> Response {
    let trace_id = Uuid::new_v4().to_string();
    let method = request.method().clone();
    let uri = request.uri().clone();

    // Insert trace_id into request extensions so downstream handlers can access it
    request.extensions_mut().insert(trace_id.clone());

    info!(trace_id = %trace_id, %method, %uri, "request started");

    let mut response = next.run(request).await;

    // Add trace_id to response headers as X-Request-Id
    if let Ok(header_value) = HeaderValue::from_str(&trace_id) {
        response.headers_mut().insert("X-Request-Id", header_value);
    }

    info!(
        trace_id = %trace_id,
        status = response.status().as_u16(),
        "request completed"
    );

    response
}
