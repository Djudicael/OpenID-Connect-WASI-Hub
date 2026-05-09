//! Per-IP rate limiting middleware.
//!
//! Tracks request counts per IP in an in-memory `HashMap` protected by a
//! `std::sync::Mutex` (WASM-compatible — no background threads).
//!
//! Configuration via environment variables:
//! - `OIDC_RATE_LIMIT_MAX`: max requests per window (default: 100)
//! - `OIDC_RATE_LIMIT_WINDOW_SECS`: window duration in seconds (default: 60)

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Shared rate-limiter state.
#[derive(Debug)]
pub struct RateLimiter {
    inner: Mutex<RateLimiterInner>,
    max_requests: u32,
    window_secs: u64,
}

#[derive(Debug)]
struct RateLimiterInner {
    /// IP → (window_start, request_count)
    buckets: HashMap<String, (Instant, u32)>,
}

impl RateLimiter {
    /// Create a new rate limiter, reading config from env vars.
    pub fn from_env() -> Self {
        let max_requests = std::env::var("OIDC_RATE_LIMIT_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        let window_secs = std::env::var("OIDC_RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        Self {
            inner: Mutex::new(RateLimiterInner {
                buckets: HashMap::new(),
            }),
            max_requests,
            window_secs,
        }
    }

    /// Check whether a request from the given IP should be allowed.
    /// Returns `Ok(remaining)` if allowed, `Err(())` if rate-limited.
    fn check(&self, ip: &str) -> Result<u32, ()> {
        let mut guard = self.inner.lock().map_err(|_| ())?;
        let now = Instant::now();

        let entry = guard.buckets.entry(ip.to_string()).or_insert((now, 0));

        // If the window has expired, reset the bucket
        if now.duration_since(entry.0).as_secs() >= self.window_secs {
            *entry = (now, 1);
            return Ok(self.max_requests.saturating_sub(1));
        }

        // Within the window — increment the counter
        entry.1 += 1;

        if entry.1 > self.max_requests {
            Err(())
        } else {
            Ok(self.max_requests.saturating_sub(entry.1))
        }
    }
}

/// Axum middleware layer for rate limiting.
pub async fn rate_limit_middleware(request: Request<Body>, next: Next) -> Response {
    // Try to get the rate limiter from extensions; if not present, skip limiting.
    let limiter = match request.extensions().get::<std::sync::Arc<RateLimiter>>() {
        Some(l) => l.clone(),
        None => {
            // No limiter configured — pass through
            return next.run(request).await;
        }
    };

    // Extract client IP from X-Forwarded-For, X-Real-IP, or fallback to "unknown"
    let ip = extract_client_ip(request.headers());

    match limiter.check(&ip) {
        Ok(remaining) => {
            let mut response = next.run(request).await;
            let headers = response.headers_mut();

            let limit_val = HeaderValue::from_str(&limiter.max_requests.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("100"));
            let remaining_val = HeaderValue::from_str(&remaining.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("0"));

            headers.insert(HeaderName::from_static("x-ratelimit-limit"), limit_val);
            headers.insert(
                HeaderName::from_static("x-ratelimit-remaining"),
                remaining_val,
            );

            response
        }
        Err(()) => {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(serde_json::json!({
                    "error": "too_many_requests",
                    "error_description": "Rate limit exceeded. Please try again later."
                })),
            )
                .into_response();

            let headers = response.headers_mut();
            let limit_val = HeaderValue::from_str(&limiter.max_requests.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("100"));
            headers.insert(HeaderName::from_static("x-ratelimit-limit"), limit_val);
            headers.insert(
                HeaderName::from_static("x-ratelimit-remaining"),
                HeaderValue::from_static("0"),
            );

            response
        }
    }
}

/// Extract the client IP from request headers.
///
/// Checks `X-Forwarded-For` (first entry), then `X-Real-IP`, then falls back
/// to `"unknown"`.
fn extract_client_ip(headers: &axum::http::HeaderMap) -> String {
    // X-Forwarded-For: client, proxy1, proxy2 — take the first
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(val) = xff.to_str() {
            if let Some(first) = val.split(',').next() {
                let trimmed = first.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }

    // X-Real-IP
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(val) = xri.to_str() {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    "unknown".to_string()
}
