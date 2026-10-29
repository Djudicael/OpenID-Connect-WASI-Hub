//! WASI 0.3 HTTP adapters shared by the Hub and the embedded admin server.
//!
//! Components keep Rust's stable `wasm32-wasip2` target while HTTP, clocks,
//! and PostgreSQL run on the component model's native asynchronous P3 executor.

#![cfg(target_arch = "wasm32")]

pub use axum::body::Body;
use axum::body::HttpBody;
pub use axum::http::Request;
use axum::http::Response;
use tower::ServiceExt;
use wasip3::http::types::{self, ErrorCode};
use wasip3::http_compat::{
    http_from_wasi_request, http_from_wasi_response, http_into_wasi_request,
    http_into_wasi_response,
};

/// Dispatch an incoming P3 request through the existing Axum router.
pub async fn handle(
    router: axum::Router,
    request: types::Request,
) -> Result<types::Response, ErrorCode> {
    let request = http_from_wasi_request(request)?.map(Body::new);
    let response = router
        .oneshot(request)
        .await
        .unwrap_or_else(|never| match never {});
    http_into_wasi_response(response)
}

/// Send an HTTP request using the same P3 executor as the server and database.
pub async fn send(mut request: Request<Body>) -> Result<Response<Body>, ErrorCode> {
    // Retain a known body length for upstreams that require Content-Length.
    if !request
        .headers()
        .contains_key(axum::http::header::CONTENT_LENGTH)
        && let Some(length) = request.body().size_hint().exact()
    {
        request.headers_mut().insert(
            axum::http::header::CONTENT_LENGTH,
            axum::http::HeaderValue::from(length),
        );
    }
    let request = http_into_wasi_request(request)?;
    let response = wasip3::http::client::send(request).await?;
    Ok(http_from_wasi_response(response)?.map(Body::new))
}

/// Read a control-plane HTTP response with a bounded allocation.
pub async fn read_body(response: Response<Body>) -> Result<axum::body::Bytes, axum::Error> {
    axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024).await
}
