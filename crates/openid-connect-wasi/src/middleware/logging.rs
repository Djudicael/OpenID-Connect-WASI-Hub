//! Request logging middleware.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use tracing::{Instrument, info};
use uuid::Uuid;

/// Middleware that adds a trace ID and logs requests.
pub async fn logging_middleware(mut request: Request<Body>, next: Next) -> Response {
    let trace_id =
        propagated_trace_id(request.headers()).unwrap_or_else(|| Uuid::new_v4().to_string());
    let method = request.method().clone();
    // Query values in OIDC requests can contain authorization codes, state,
    // request objects, login hints, and other credentials. Record only the
    // path; operators can correlate the request through the trace ID.
    let path = request.uri().path().to_string();
    let request_span = tracing::info_span!(
        "oidc_http_request",
        trace_id = %trace_id,
        method = %method,
        path = %path,
    );

    // Insert trace_id into request extensions so downstream handlers can access it
    request.extensions_mut().insert(trace_id.clone());

    info!(trace_id = %trace_id, %method, %path, "request started");

    let mut response = next.run(request).instrument(request_span.clone()).await;

    // Add trace_id to response headers as X-Request-Id
    if let Ok(header_value) = HeaderValue::from_str(&trace_id) {
        response.headers_mut().insert("X-Request-Id", header_value);
    }

    request_span.in_scope(|| {
        info!(
            trace_id = %trace_id,
            status = response.status().as_u16(),
            "request completed"
        );
    });

    response
}

fn propagated_trace_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-trace-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_hex_id(value, 32))
        .map(str::to_ascii_lowercase)
        .or_else(|| {
            let traceparent = headers.get("traceparent")?.to_str().ok()?;
            let mut fields = traceparent.split('-');
            let version = fields.next()?;
            let trace_id = fields.next()?;
            let parent_id = fields.next()?;
            let flags = fields.next()?;
            if fields.next().is_some()
                || !valid_hex(version, 2)
                || version.eq_ignore_ascii_case("ff")
                || !valid_hex_id(trace_id, 32)
                || !valid_hex_id(parent_id, 16)
                || !valid_hex(flags, 2)
            {
                return None;
            }
            Some(trace_id.to_ascii_lowercase())
        })
}

fn valid_hex_id(value: &str, length: usize) -> bool {
    valid_hex(value, length) && value.bytes().any(|byte| byte != b'0')
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_platform_trace_id() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-trace-id",
            HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        );
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-cccccccccccccccc-01"),
        );

        assert_eq!(
            propagated_trace_id(&headers).as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn extracts_valid_w3c_trace_id() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );

        assert_eq!(
            propagated_trace_id(&headers).as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
    }

    #[test]
    fn rejects_zero_or_malformed_context() {
        for value in [
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "not-a-traceparent",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("traceparent", HeaderValue::from_str(value).unwrap());
            assert_eq!(propagated_trace_id(&headers), None);
        }
    }

    #[test]
    fn request_log_path_excludes_sensitive_query_values() {
        let uri: axum::http::Uri = "/oidc/callback?code=secret-code&state=secret-state"
            .parse()
            .unwrap();

        assert_eq!(uri.path(), "/oidc/callback");
        assert!(!uri.path().contains("secret-code"));
        assert!(!uri.path().contains("secret-state"));
    }
}
