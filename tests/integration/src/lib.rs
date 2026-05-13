//! Integration tests for the OpenID Connect WASI Hub.
//!
//! ## Test harness
//!
//! The `harness` module spawns a single PostgreSQL container via `podman`
//! before the first test and reuses it for the entire run.  Migrations are
//! applied automatically.  No manual setup is required.
//!
//! ```bash
//! cargo test -p integration-tests -- --test-threads=1
//! ```

#[cfg(test)]
pub mod harness;

#[cfg(test)]
pub mod helpers;

#[cfg(test)]
pub mod apikey_tests;

#[cfg(test)]
pub mod db_tests;

#[cfg(test)]
pub mod oidc_tests;

#[cfg(test)]
pub mod realm_oidc_tests;

#[cfg(test)]
pub mod scope_tests;

#[cfg(test)]
pub mod security_tests;

#[cfg(test)]
pub mod repo_tests;

#[cfg(test)]
mod http_tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use openid_connect_wasi::app_router;
    use serde_json::Value;
    use tower::ServiceExt;

    async fn read_json_body(response: axum::response::Response) -> Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = app_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json_body(response).await;
        assert_eq!(body["status"], "ok");
        assert!(body["version"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_openid_configuration() {
        let app = app_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json_body(response).await;

        assert!(body["issuer"].as_str().is_some());
        assert!(body["authorization_endpoint"].as_str().is_some());
        assert!(body["token_endpoint"].as_str().is_some());
        assert!(body["userinfo_endpoint"].as_str().is_some());
        assert!(body["jwks_uri"].as_str().is_some());
        assert!(body["scopes_supported"].as_array().is_some());
        assert!(body["response_types_supported"].as_array().is_some());
        assert!(body["grant_types_supported"].as_array().is_some());
        assert!(
            body["id_token_signing_alg_values_supported"]
                .as_array()
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_jwks_endpoint() {
        let app = app_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/oidc/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json_body(response).await;

        let keys = body["keys"]
            .as_array()
            .expect("JWKS should have keys array");
        assert!(!keys.is_empty(), "JWKS should contain at least one key");

        let key = &keys[0];
        assert_eq!(key["kty"], "RSA");
        assert_eq!(key["alg"], "RS256");
        assert!(key["kid"].as_str().is_some());
        assert!(key["n"].as_str().is_some());
        assert!(key["e"].as_str().is_some());
    }
}
