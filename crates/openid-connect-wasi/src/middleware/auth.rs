//! Authentication middleware.

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

/// Middleware that extracts and validates authentication.
pub async fn auth_middleware(request: Request<Body>, next: Next) -> Response {
    // TODO: implement session/API key extraction
    next.run(request).await
}
