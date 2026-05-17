//! Security headers middleware.
//! Adds standard security headers to all responses.

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;

fn insert_header_if_absent(
    headers: &mut axum::http::HeaderMap,
    name: &'static str,
    value: &'static str,
) {
    let header_name = HeaderName::from_static(name);
    if !headers.contains_key(&header_name) {
        headers.insert(header_name, HeaderValue::from_static(value));
    }
}

/// Security headers middleware.
/// Adds headers recommended for production OIDC providers:
/// - X-Content-Type-Options: nosniff
/// - X-Frame-Options: DENY
/// - X-XSS-Protection: 0 (disabled, modern browsers don't need it)
/// - Referrer-Policy: strict-origin-when-cross-origin
/// - Content-Security-Policy: default-src 'self'
/// - Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
/// - Cache-Control: no-store (for OIDC endpoints)
pub async fn security_headers_middleware(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();
    insert_header_if_absent(headers, "x-content-type-options", "nosniff");
    insert_header_if_absent(headers, "x-frame-options", "DENY");
    insert_header_if_absent(headers, "x-xss-protection", "0");
    insert_header_if_absent(
        headers,
        "referrer-policy",
        "strict-origin-when-cross-origin",
    );
    insert_header_if_absent(
        headers,
        "content-security-policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
    );
    insert_header_if_absent(
        headers,
        "strict-transport-security",
        "max-age=63072000; includeSubDomains; preload",
    );
    insert_header_if_absent(headers, "cache-control", "no-store");

    response
}
