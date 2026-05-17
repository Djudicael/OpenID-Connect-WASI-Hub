//! Lightweight CSRF cookie issuance + validation for browser-admin routes.
//!
//! This middleware is intentionally scoped to browser/admin-style same-origin
//! routes. It does **not** attempt to secure OAuth/OIDC protocol endpoints.
//! It also does not block non-browser API-key clients that do not use cookies.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

const CSRF_COOKIE_NAME: &str = "oidc_csrf_token";
const CSRF_HEADER_NAME: &str = "x-csrf-token";

pub async fn csrf_middleware(request: Request<Body>, next: Next) -> Response {
    let method = request.method().clone();
    let cookie_token = extract_csrf_cookie(request.headers());

    let should_skip_validation = request.headers().contains_key("x-api-key");
    let is_safe_method = matches!(
        method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );

    if !is_safe_method && !should_skip_validation && cookie_token.is_some() {
        let header_token = request
            .headers()
            .get(CSRF_HEADER_NAME)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);

        match (cookie_token.as_deref(), header_token.as_deref()) {
            (Some(cookie), Some(header)) if cookie == header => {}
            _ => {
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({
                        "error": "csrf_validation_failed",
                        "error_description": "Missing or invalid CSRF token"
                    })),
                )
                    .into_response();
            }
        }
    }

    let mut response = next.run(request).await;

    if cookie_token.is_none() {
        let token = match generate_csrf_token() {
            Ok(token) => token,
            Err(e) => {
                tracing::warn!("failed to generate CSRF token: {e}");
                return response;
            }
        };
        if let Ok(value) = HeaderValue::from_str(&csrf_cookie_header(&token)) {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, value);
        }
    }

    response
}

fn generate_csrf_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(hex::encode(bytes))
}

fn csrf_cookie_header(value: &str) -> String {
    format!(
        "{}={}; Path=/; SameSite=Strict; Secure; Max-Age=86400",
        CSRF_COOKIE_NAME, value
    )
}

fn extract_csrf_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for cookie_pair in cookie_header.split(';') {
        let cookie_pair = cookie_pair.trim();
        if let Some(value) = cookie_pair.strip_prefix(&format!("{}=", CSRF_COOKIE_NAME)) {
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_csrf_cookie_reads_expected_cookie() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("foo=bar; oidc_csrf_token=abc123; baz=qux"),
        );

        assert_eq!(extract_csrf_cookie(&headers).as_deref(), Some("abc123"));
    }

    #[test]
    fn csrf_cookie_header_sets_expected_attributes() {
        let header = csrf_cookie_header("abc123");
        assert!(header.contains("oidc_csrf_token=abc123"));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("Secure"));
        assert!(header.contains("Max-Age=86400"));
    }
}
