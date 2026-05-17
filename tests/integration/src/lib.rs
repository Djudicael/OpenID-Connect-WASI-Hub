//! Integration tests for the OpenID Connect WASI Hub.
//!
//! ## Test harness
//!
//! The `harness` module spawns a single PostgreSQL container via `podman`
//! before the first test and reuses it for the entire run.  Migrations are
//! applied once to a template database (`oidc_hub_test`).
//!
//! Each HTTP integration test that uses [`TestApp`] gets its own **fresh
//! database** cloned from that template (`oidc_hub_test_1`,
//! `oidc_hub_test_2`, …).  This provides perfect isolation without
//! `TRUNCATE` or table locks.
//!
//! Repository / DB unit tests that do NOT spawn a server use the shared
//! template DB with per-connection transactions, so they also need no
//! explicit cleanup.
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
pub mod social_login_tests;

#[cfg(test)]
pub mod security_tests;

#[cfg(test)]
pub mod repo_tests;

#[cfg(test)]
pub mod endpoint_tests;

#[cfg(test)]
pub mod admin_tests;

#[cfg(test)]
mod http_tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use openid_connect_wasi::app_router;
    use serde_json::Value;
    use tower::ServiceExt;

    use crate::helpers::fixtures::TEST_ENCRYPTION_KEY;

    async fn read_json_body(response: axum::response::Response) -> Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Generate RSA and Ed25519 PEM keys once (reuses `helpers::app::test_signing_keys` logic).
    fn ensure_env() {
        use std::sync::OnceLock;
        static INIT: OnceLock<()> = OnceLock::new();
        INIT.get_or_init(|| {
            use rand::RngCore;
            use rand::rngs::OsRng;

            // RSA
            let rsa_key =
                rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("failed to generate RSA key");
            use rsa::pkcs1::EncodeRsaPrivateKey;
            let rsa_pem: String = rsa_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .expect("failed to serialize RSA key")
                .to_string();

            // Ed25519
            let mut secret_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut secret_bytes);
            let ed_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
            use pkcs8::EncodePrivateKey;
            let ed_pem: String = ed_key
                .to_pkcs8_pem(pkcs8::LineEnding::LF)
                .expect("failed to serialize Ed25519 key")
                .to_string();

            unsafe {
                std::env::set_var("OIDC_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY);
                std::env::set_var("OIDC_PAIRWISE_SALT", "test-pairwise-salt");
                std::env::set_var("OIDC_SIGNING_KEY", &rsa_pem);
                std::env::set_var("OIDC_ED25519_KEY", &ed_pem);
            }
        });
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        ensure_env();
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
        ensure_env();
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
        ensure_env();
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
