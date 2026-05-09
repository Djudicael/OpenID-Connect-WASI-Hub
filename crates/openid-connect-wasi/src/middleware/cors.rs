//! CORS middleware.

use tower_http::cors::CorsLayer;

/// Build the CORS layer.
/// Reads allowed origins from `OIDC_CORS_ORIGINS` env var (comma-separated).
/// If not set, defaults to same-origin only (no wildcard).
pub fn cors_layer() -> CorsLayer {
    let origins = std::env::var("OIDC_CORS_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect::<Vec<_>>();

    if origins.is_empty() {
        // No CORS origins configured — restrictive default
        CorsLayer::new()
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
                axum::http::header::HeaderName::from_static("x-api-key"),
                axum::http::header::HeaderName::from_static("x-csrf-token"),
            ])
        // No allow_origin = same-origin only
    } else {
        let mut layer = CorsLayer::new()
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
                axum::http::header::HeaderName::from_static("x-api-key"),
                axum::http::header::HeaderName::from_static("x-csrf-token"),
            ]);

        for origin in origins {
            if let Ok(parsed) = origin.parse::<axum::http::HeaderValue>() {
                layer = layer.allow_origin(parsed);
            }
        }

        layer
    }
}
