//! OIDC endpoint integration tests for previously untested features.
//!
//! Covers: PAR (RFC 9101), Device Authorization (RFC 8628), Password Reset,
//! Email Verification, WebFinger, Session Check, Account Recovery, Dynamic Registration.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::helpers::app::TestApp;
use crate::helpers::fixtures;

// ===================================================================
// Helpers
// ===================================================================

fn pkce_s256_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

async fn admin_login(app: &TestApp) -> String {
    let resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": fixtures::TEST_USER_PASSWORD,
        }))
        .send()
        .await
        .expect("admin login failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("login response should be JSON");
    body["access_token"]
        .as_str()
        .expect("access_token must be present")
        .to_string()
}

fn parse_redirect_fragment(location: &str, key: &str) -> Option<String> {
    let url =
        url::Url::parse(location).unwrap_or_else(|_| panic!("invalid redirect URL: {location}"));
    if let Some(fragment) = url.fragment() {
        for pair in fragment.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == key {
                    return Some(urlencoding::decode(v).ok()?.to_string());
                }
            }
        }
    }
    if let Some((_, v)) = url.query_pairs().find(|(k, _)| k == key) {
        return Some(v.to_string());
    }
    None
}

// ===================================================================
// Pushed Authorization Requests (RFC 9101)
// ===================================================================

#[tokio::test]
async fn test_par_success() {
    let app = TestApp::new().await;
    let client_id = "par-test-client";
    let redirect_uri = "https://app.example.com/callback";
    app.seed_client_with_secret(client_id, "par-secret", &[redirect_uri])
        .await;
    {
        let mut conn = app.db_conn().await;
        conn.execute_params(
            "UPDATE clients SET token_endpoint_auth_method = $1 WHERE client_id = $2",
            &[&"client_secret_basic", &client_id],
        )
        .await
        .expect("failed to update client auth method");
        let _ = conn.close().await;
    }

    let resp = app
        .client()
        .post(&format!("{}/oidc/par", app.url()))
        .basic_auth(client_id, Some("par-secret"))
        .form(&[
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("par request failed");

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.expect("par response should be JSON");
    assert!(
        body["request_uri"]
            .as_str()
            .is_some_and(|s| s.starts_with("urn:ietf:params:oauth:request_uri:"))
    );
    assert!(body["expires_in"].as_u64().is_some());
}

#[tokio::test]
async fn test_par_redirect_uri_mismatch_rejected_at_authorize() {
    let app = TestApp::new().await;
    let client_id = "par-mismatch-client";
    let redirect_uri = "https://app.example.com/callback";
    app.seed_client_with_secret(client_id, "par-secret", &[redirect_uri])
        .await;
    {
        let mut conn = app.db_conn().await;
        conn.execute_params(
            "UPDATE clients SET token_endpoint_auth_method = $1 WHERE client_id = $2",
            &[&"client_secret_basic", &client_id],
        )
        .await
        .expect("failed to update client auth method");
        let _ = conn.close().await;
    }

    let par_resp = app
        .client()
        .post(&format!("{}/oidc/par", app.url()))
        .basic_auth(client_id, Some("par-secret"))
        .form(&[
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("par request failed");

    assert_eq!(par_resp.status(), StatusCode::CREATED);
    let par_body: Value = par_resp.json().await.expect("par response should be JSON");
    let request_uri = par_body["request_uri"]
        .as_str()
        .expect("request_uri must be present");

    let authorize_resp = app
        .client()
        .get(&format!(
            "{}/oidc/authorize?client_id={}&redirect_uri={}&request_uri={}",
            app.url(),
            urlencoding::encode(client_id),
            urlencoding::encode("https://evil.example.com/callback"),
            urlencoding::encode(request_uri),
        ))
        .send()
        .await
        .expect("authorize request failed");

    assert_eq!(authorize_resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = authorize_resp
        .headers()
        .get("location")
        .expect("redirect must have Location header")
        .to_str()
        .expect("Location must be valid UTF-8");
    assert!(
        location.contains("/oidc/error") || location.contains("error=invalid_request"),
        "authorize mismatch should redirect to an error page, got: {location}"
    );
}

#[tokio::test]
async fn test_authorize_rejects_request_and_request_uri_together() {
    let app = TestApp::new().await;
    let client_id = "request-and-request-uri-client";
    let redirect_uri = "https://app.example.com/callback";
    app.seed_client_with_secret(client_id, "request-secret", &[redirect_uri])
        .await;

    let resp = app
        .client()
        .get(&format!(
            "{}/oidc/authorize?client_id={}&redirect_uri={}&request=dummy&request_uri={}",
            app.url(),
            urlencoding::encode(client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode("urn:ietf:params:oauth:request_uri:example"),
        ))
        .send()
        .await
        .expect("authorize request failed");

    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp
        .headers()
        .get("location")
        .expect("redirect must have Location header")
        .to_str()
        .expect("Location must be valid UTF-8");
    assert!(
        location.contains("/oidc/error") || location.contains("error=invalid_request"),
        "request + request_uri should be rejected, got: {location}"
    );
}

#[tokio::test]
async fn test_par_invalid_client() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/par", app.url()))
        .basic_auth("nonexistent-client", Some("wrong-secret"))
        .form(&[
            ("client_id", "nonexistent-client"),
            ("redirect_uri", "https://app.example.com/callback"),
            ("response_type", "code"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("par request failed");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ===================================================================
// Device Authorization Grant (RFC 8628)
// ===================================================================

#[tokio::test]
async fn test_device_authorize_success() {
    let app = TestApp::new().await;
    let client_id = "device-test-client";
    app.seed_client(client_id, "public", &[]).await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/device/authorize", app.url()))
        .form(&[("client_id", client_id), ("scope", "openid")])
        .send()
        .await
        .expect("device authorize failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp
        .json()
        .await
        .expect("device authorize response should be JSON");
    assert!(body["device_code"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(body["user_code"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(body["verification_uri"].as_str().is_some());
    assert!(body["verification_uri_complete"].as_str().is_some());
    assert!(body["expires_in"].as_u64().is_some());
    assert!(body["interval"].as_u64().is_some());
}

#[tokio::test]
async fn test_device_verify_page() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(&format!("{}/oidc/device?user_code=TEST1234", app.url()))
        .send()
        .await
        .expect("device verify failed");

    // Should return HTML page
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/html"));
}

#[tokio::test]
async fn test_device_authorize_missing_client() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/device/authorize", app.url()))
        .form(&[("scope", "openid")])
        .send()
        .await
        .expect("device authorize failed");

    // Returns 401 when client is not found
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ===================================================================
// WebFinger (RFC 7033)
// ===================================================================

#[tokio::test]
async fn test_webfinger_success() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(&format!(
            "{}/.well-known/webfinger?resource=acct:{}@localhost",
            app.url(),
            fixtures::TEST_USER_EMAIL
        ))
        .send()
        .await
        .expect("webfinger request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp
        .json()
        .await
        .expect("webfinger response should be JSON");
    assert_eq!(
        body["subject"].as_str().unwrap(),
        format!("acct:{}@localhost", fixtures::TEST_USER_EMAIL)
    );
    assert!(body["links"].as_array().is_some());
}

#[tokio::test]
async fn test_webfinger_missing_resource() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(&format!("{}/.well-known/webfinger", app.url()))
        .send()
        .await
        .expect("webfinger request failed");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ===================================================================
// Session Check (OIDC Session Management)
// ===================================================================

#[tokio::test]
async fn test_check_session_unchanged() {
    let app = TestApp::new().await;

    // The check_session endpoint returns an HTML page with an iframe script
    // that handles postMessage communication with the RP.
    let resp = app
        .client()
        .get(&format!(
            "{}/oidc/session/check?session_state=unchanged",
            app.url()
        ))
        .send()
        .await
        .expect("check session failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("OIDC Check Session"));
    assert!(body.contains("postMessage"));
}

#[tokio::test]
async fn test_check_session_changed() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(&format!(
            "{}/oidc/session/check?session_state=changed",
            app.url()
        ))
        .send()
        .await
        .expect("check session failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    // Same HTML page regardless of session_state value
    assert!(body.contains("OIDC Check Session"));
}

// ===================================================================
// Password Reset
// ===================================================================

#[tokio::test]
async fn test_password_reset_request() {
    let app = TestApp::new().await;
    // The test user already exists in the master realm

    let resp = app
        .client()
        .post(&format!("{}/oidc/password-reset/request", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "realm": "master",
        }))
        .send()
        .await
        .expect("password reset request failed");

    // Should always return 200 even if email doesn't exist (security)
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_password_reset_confirm_invalid_token() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/password-reset/confirm", app.url()))
        .json(&json!({
            "token": "invalid-token-12345",
            "new_password": "NewPass123!",
        }))
        .send()
        .await
        .expect("password reset confirm failed");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ===================================================================
// Email Verification
// ===================================================================

#[tokio::test]
async fn test_email_verification_request() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/email-verification/request", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "realm": "master",
        }))
        .send()
        .await
        .expect("email verification request failed");

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_email_verification_confirm_invalid_token() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/email-verification/confirm", app.url()))
        .json(&json!({
            "token": "invalid-token-12345",
        }))
        .send()
        .await
        .expect("email verification confirm failed");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ===================================================================
// Account Recovery (public endpoint)
// ===================================================================

#[tokio::test]
async fn test_account_recovery_confirm_invalid_token() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/account-recovery/confirm", app.url()))
        .json(&json!({
            "token": "invalid-recovery-token",
            "new_password": "NewPass123!",
        }))
        .send()
        .await
        .expect("account recovery confirm failed");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ===================================================================
// Dynamic Client Registration (RFC 7591)
// ===================================================================

#[tokio::test]
async fn test_register_requires_auth() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/register", app.url()))
        .json(&json!({
            "client_name": "Test Client",
            "redirect_uris": ["https://app.example.com/callback"],
        }))
        .send()
        .await
        .expect("register request failed");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_register_with_admin_auth() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    // Get realm ID
    let realms_resp = app
        .client()
        .get(&format!("{}/api/realms?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let realms_body: Value = realms_resp.json().await.unwrap();
    let realm_id = realms_body["items"][0]["id"].as_str().unwrap();

    let resp = app
        .client()
        .post(&format!("{}/oidc/register", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "client_name": "Registered Client",
            "redirect_uris": ["http://localhost:3000/callback"],
            "grant_types": ["authorization_code"],
            "scope": "openid profile email",
            "token_endpoint_auth_method": "client_secret_basic",
            "realm_id": realm_id,
        }))
        .send()
        .await
        .expect("register request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("register response should be JSON");
    assert!(body["client_id"].as_str().is_some());
    assert!(body["client_secret"].as_str().is_some());
    assert!(body["client_name"].as_str().is_some());
}

// ===================================================================
// Per-Realm Authorize (Keycloak-compatible path)
// ===================================================================

#[tokio::test]
async fn test_per_realm_authorize_redirect() {
    let app = TestApp::new().await;
    let client_id = "per-realm-auth-client";
    let redirect_uri = "https://app.example.com/callback";
    app.seed_public_client(client_id, &[redirect_uri]).await;

    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = pkce_s256_challenge(code_verifier);

    let authorize_url = format!(
        "{}/realms/master/protocol/openid-connect/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid&code_challenge={}&code_challenge_method=S256",
        app.url(),
        client_id,
        urlencoding::encode(redirect_uri),
        urlencoding::encode(&code_challenge),
    );

    let resp = app
        .client()
        .get(&authorize_url)
        .send()
        .await
        .expect("authorize failed");

    // Should redirect to login page (not logged in)
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("/realms/master/login"));
}

// ===================================================================
// Per-Realm Certs (JWKS)
// ===================================================================

#[tokio::test]
async fn test_per_realm_certs() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(&format!(
            "{}/realms/master/protocol/openid-connect/certs",
            app.url()
        ))
        .send()
        .await
        .expect("certs request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("certs response should be JSON");
    let keys = body["keys"]
        .as_array()
        .expect("JWKS should have keys array");
    assert!(!keys.is_empty());
}

#[tokio::test]
async fn test_per_realm_certs_not_found() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(&format!(
            "{}/realms/nonexistent/protocol/openid-connect/certs",
            app.url()
        ))
        .send()
        .await
        .expect("certs request failed");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
