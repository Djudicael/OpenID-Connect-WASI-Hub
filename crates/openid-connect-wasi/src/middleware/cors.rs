//! CORS middleware.

use tower_http::cors::CorsLayer;

/// Build the CORS layer.
/// Reads allowed origins from `OIDC_CORS_ORIGINS` env var (comma-separated).
/// If not set, defaults to same-origin only (no wildcard).
pub fn cors_layer() -> CorsLayer {
    cors_layer_for(&std::env::var("OIDC_CORS_ORIGINS").unwrap_or_default())
}

fn cors_layer_for(configured: &str) -> CorsLayer {
    let origins = configured
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed == "*" {
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
        let layer = CorsLayer::new()
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

        let allowed: Vec<axum::http::HeaderValue> = origins
            .into_iter()
            .filter_map(|origin| origin.parse().ok())
            .collect();
        layer.allow_origin(allowed).allow_credentials(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, routing::post};
    use tower::ServiceExt;

    #[tokio::test]
    async fn allows_each_configured_origin_with_credentials_and_rejects_unknown_origins() {
        let app = Router::new()
            .route("/token", post(|| async { "ok" }))
            .layer(cors_layer_for(
                "http://localhost:3008,http://localhost:3009",
            ));
        for origin in ["http://localhost:3008", "http://localhost:3009"] {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/token")
                        .header("origin", origin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.headers()["access-control-allow-origin"], origin);
            assert_eq!(
                response.headers()["access-control-allow-credentials"],
                "true"
            );
        }
        let response = app
            .oneshot(
                Request::post("/token")
                    .header("origin", "https://untrusted.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin")
        );
        for configured in ["", "*"] {
            let app = Router::new()
                .route("/token", post(|| async { "ok" }))
                .layer(cors_layer_for(configured));
            let response = app
                .oneshot(
                    Request::post("/token")
                        .header("origin", "https://untrusted.example")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                !response
                    .headers()
                    .contains_key("access-control-allow-origin")
            );
            assert!(
                !response
                    .headers()
                    .contains_key("access-control-allow-credentials")
            );
        }
    }
}
