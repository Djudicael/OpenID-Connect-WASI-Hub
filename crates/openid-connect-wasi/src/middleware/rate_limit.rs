//! Per-IP rate limiting middleware.
//!
//! Tracks request counts per IP in an in-memory `HashMap` protected by a
//! `std::sync::Mutex` (WASM-compatible — no background threads).
//!
//! This limiter is intentionally a **local safety net**, not a distributed
//! production-abuse control by itself. For multi-instance or edge deployments,
//! prefer gateway/CDN/global rate limiting and use `OIDC_RATE_LIMIT_MODE=proxy`
//! to make that upstream layer the source of truth.
//!
//! Configuration via environment variables:
//! - `OIDC_RATE_LIMIT_MAX`: max requests per window (default: 100)
//! - `OIDC_RATE_LIMIT_WINDOW_SECS`: window duration in seconds (default: 60)
//! - `OIDC_RATE_LIMIT_MODE`: `local` (default), `proxy` / `upstream`, or `off`
//! - `OIDC_TRUST_PROXY_HEADERS`: trust sanitized proxy forwarding headers

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateLimitMode {
    /// Enforce per-instance in-memory limits inside the app.
    Local,
    /// Rely on an upstream gateway/CDN or external layer as the source of truth.
    Proxy,
    /// Disable rate limiting entirely.
    Disabled,
}

impl RateLimitMode {
    fn parse(value: Option<&str>) -> Self {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("proxy") | Some("proxy-only") | Some("upstream") | Some("gateway") => Self::Proxy,
            Some("off") | Some("disabled") | Some("none") => Self::Disabled,
            _ => Self::Local,
        }
    }

    fn enforces_in_process(self) -> bool {
        matches!(self, Self::Local)
    }

    fn as_header_value(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Proxy => "proxy",
            Self::Disabled => "disabled",
        }
    }
}

/// Shared rate-limiter state.
#[derive(Debug)]
pub struct RateLimiter {
    inner: Mutex<RateLimiterInner>,
    max_requests: u32,
    window_secs: u64,
    trust_proxy_headers: bool,
    mode: RateLimitMode,
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

        let trust_proxy_headers = std::env::var("OIDC_TRUST_PROXY_HEADERS")
            .ok()
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);

        let mode = RateLimitMode::parse(std::env::var("OIDC_RATE_LIMIT_MODE").ok().as_deref());

        Self {
            inner: Mutex::new(RateLimiterInner {
                buckets: HashMap::new(),
            }),
            max_requests,
            window_secs,
            trust_proxy_headers,
            mode,
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

    if !limiter.mode.enforces_in_process() {
        let mut response = next.run(request).await;
        response.headers_mut().insert(
            HeaderName::from_static("x-oidc-rate-limit-mode"),
            HeaderValue::from_static(limiter.mode.as_header_value()),
        );
        return response;
    }

    // Extract the client IP from a trusted proxy header when configured,
    // otherwise fall back to the actual peer address if available.
    let ip = extract_client_ip(&request, limiter.trust_proxy_headers);

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
            headers.insert(
                HeaderName::from_static("x-oidc-rate-limit-mode"),
                HeaderValue::from_static(limiter.mode.as_header_value()),
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
            let retry_after = HeaderValue::from_str(&limiter.window_secs.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("60"));
            headers.insert(HeaderName::from_static("retry-after"), retry_after);
            headers.insert(
                HeaderName::from_static("x-oidc-rate-limit-mode"),
                HeaderValue::from_static(limiter.mode.as_header_value()),
            );

            response
        }
    }
}

/// Extract the client IP from the request.
///
/// By default the middleware ignores forwarded headers to avoid trusting
/// spoofable values. If `OIDC_TRUST_PROXY_HEADERS=true` is configured, it will
/// consult `Forwarded`, `X-Forwarded-For`, and `X-Real-IP` in that order.
fn extract_client_ip(request: &Request<Body>, trust_proxy_headers: bool) -> String {
    if trust_proxy_headers {
        if let Some(ip) = forwarded_ip(request.headers()) {
            return ip;
        }
        if let Some(ip) = x_forwarded_for_ip(request.headers()) {
            return ip;
        }
        if let Some(ip) = x_real_ip(request.headers()) {
            return ip;
        }
    }

    peer_addr(request).unwrap_or_else(|| "unknown".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn peer_addr(request: &Request<Body>) -> Option<String> {
    request
        .extensions()
        .get::<axum::extract::connect_info::ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
}

#[cfg(target_arch = "wasm32")]
fn peer_addr(_request: &Request<Body>) -> Option<String> {
    None
}

fn forwarded_ip(headers: &axum::http::HeaderMap) -> Option<String> {
    let header = headers.get("forwarded")?.to_str().ok()?;
    for segment in header.split(',') {
        for part in segment.split(';') {
            let part = part.trim();
            let value = part.strip_prefix("for=")?.trim_matches('"');
            if let Some(ip) = normalize_forwarded_ip(value) {
                return Some(ip);
            }
        }
    }
    None
}

fn x_forwarded_for_ip(headers: &axum::http::HeaderMap) -> Option<String> {
    let header = headers.get("x-forwarded-for")?.to_str().ok()?;
    let first = header.split(',').next()?.trim();
    normalize_forwarded_ip(first)
}

fn x_real_ip(headers: &axum::http::HeaderMap) -> Option<String> {
    let header = headers.get("x-real-ip")?.to_str().ok()?;
    normalize_forwarded_ip(header.trim())
}

fn normalize_forwarded_ip(value: &str) -> Option<String> {
    if value.is_empty() || value.eq_ignore_ascii_case("unknown") {
        return None;
    }

    if let Some(stripped) = value.strip_prefix('[') {
        let end = stripped.find(']')?;
        let ip = &stripped[..end];
        return Some(ip.to_string());
    }

    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr.ip().to_string());
    }

    Some(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::Request as HttpRequest;

    #[test]
    fn extract_client_ip_uses_peer_addr_when_proxy_headers_untrusted() {
        let mut request = HttpRequest::builder()
            .uri("/")
            .body(Body::empty())
            .expect("request should build");
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:8080".parse::<SocketAddr>().expect("socket addr"),
        ));

        assert_eq!(extract_client_ip(&request, false), "127.0.0.1");
    }

    #[test]
    fn extract_client_ip_uses_forwarded_headers_when_proxy_is_trusted() {
        let mut request = HttpRequest::builder()
            .uri("/")
            .body(Body::empty())
            .expect("request should build");
        request.headers_mut().insert(
            "forwarded",
            HeaderValue::from_static("for=198.51.100.7:1234"),
        );
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:8080".parse::<SocketAddr>().expect("socket addr"),
        ));

        assert_eq!(extract_client_ip(&request, true), "198.51.100.7");
    }

    #[test]
    fn normalize_forwarded_ip_handles_ipv6_brackets() {
        assert_eq!(
            normalize_forwarded_ip("[2001:db8::1]:443").as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn parse_rate_limit_mode_defaults_to_local() {
        assert_eq!(RateLimitMode::parse(None), RateLimitMode::Local);
        assert_eq!(RateLimitMode::parse(Some("local")), RateLimitMode::Local);
        assert_eq!(RateLimitMode::parse(Some("unknown")), RateLimitMode::Local);
    }

    #[test]
    fn parse_rate_limit_mode_accepts_proxy_aliases() {
        assert_eq!(RateLimitMode::parse(Some("proxy")), RateLimitMode::Proxy);
        assert_eq!(RateLimitMode::parse(Some("upstream")), RateLimitMode::Proxy);
        assert_eq!(RateLimitMode::parse(Some("gateway")), RateLimitMode::Proxy);
    }

    #[test]
    fn parse_rate_limit_mode_accepts_disabled_aliases() {
        assert_eq!(RateLimitMode::parse(Some("off")), RateLimitMode::Disabled);
        assert_eq!(
            RateLimitMode::parse(Some("disabled")),
            RateLimitMode::Disabled
        );
        assert_eq!(RateLimitMode::parse(Some("none")), RateLimitMode::Disabled);
    }
}
