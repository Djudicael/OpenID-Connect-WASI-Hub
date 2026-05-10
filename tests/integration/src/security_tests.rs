//! Security-focused integration tests for the OIDC implementation.
//!
//! These tests verify resistance to common attacks:
//! - JWT algorithm confusion (alg: none, HS256)
//! - PKCE bypass attempts
//! - Open redirect via redirect_uri manipulation
//! - Refresh token replay detection
//! - SQL injection in login fields
//! - Input validation (empty fields, missing body)
//! - Rate limiting on login endpoint

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::helpers::app::TestApp;
use crate::helpers::fixtures;

// ===================================================================
// Helpers
// ===================================================================

/// Compute a PKCE S256 code challenge from a verifier:
///   challenge = base64url_no_pad(sha256(verifier))
fn pkce_s256_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}

/// Craft a bare JWT with a custom header and claims, signed with an empty
/// signature.  This is intentionally **not** a valid token — the point is
/// to verify the server *rejects* it.
fn craft_jwt(header: &serde_json::Value, claims: &serde_json::Value) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    // Empty signature — three parts separated by dots
    format!("{header_b64}.{claims_b64}.")
}

/// Login via the direct password grant and return the full response body.
async fn login(app: &TestApp) -> Value {
    let resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": fixtures::TEST_USER_PASSWORD,
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(resp.status(), StatusCode::OK, "login should succeed");
    resp.json().await.expect("login response should be JSON")
}

/// Run the full authorization code + PKCE flow and return the token
/// response body.  This is the "happy path" used as a baseline before
/// the security test mutates one of the parameters.
async fn full_auth_code_flow_with_pkce(
    app: &TestApp,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Value {
    let code_challenge = pkce_s256_challenge(code_verifier);
    let state = "sec-test-state";

    // 1. Authorize
    let authorize_url = format!(
        "{}/oidc/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid+profile&state={}&code_challenge={}&code_challenge_method=S256&login_hint={}",
        app.url(),
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(state),
        urlencoding::encode(&code_challenge),
        urlencoding::encode(fixtures::TEST_USER_EMAIL),
    );

    let resp = app
        .client()
        .get(&authorize_url)
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

    let url = url::Url::parse(location).expect("invalid redirect URL");
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("authorization code must be present");

    // 2. Exchange code for tokens
    let token_resp = app
        .client()
        .post(&format!("{}/oidc/token", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
            urlencoding::encode(&code),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(client_id),
            urlencoding::encode(client_secret),
            urlencoding::encode(code_verifier),
        ))
        .send()
        .await
        .expect("token request failed");

    assert_eq!(
        token_resp.status(),
        StatusCode::OK,
        "token exchange should succeed"
    );
    token_resp
        .json()
        .await
        .expect("token response should be JSON")
}

// ===================================================================
// Group 1: JWT Algorithm Confusion
// ===================================================================

#[tokio::test]
async fn test_jwt_alg_none_rejected() {
    let app = TestApp::new().await;

    // Craft a JWT with alg: "none" — classic algorithm confusion attack
    let header = json!({
        "alg": "none",
        "typ": "JWT",
        "kid": "key-1"
    });
    let claims = json!({
        "sub": "attacker",
        "email": "attacker@evil.com",
        "iss": app.url(),
        "aud": "admin-ui",
        "exp": 9999999999_u64,
        "iat": 1000000000_u64
    });
    let fake_token = craft_jwt(&header, &claims);

    let resp = app
        .client()
        .get(&format!("{}/oidc/userinfo", app.url()))
        .header("authorization", format!("Bearer {fake_token}"))
        .send()
        .await
        .expect("userinfo request failed");

    // Must be rejected — 401 Unauthorized
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "JWT with alg:none must be rejected"
    );
}

#[tokio::test]
async fn test_jwt_alg_hs256_rejected() {
    let app = TestApp::new().await;

    // Craft a JWT with alg: "HS256" — algorithm substitution attack
    // (attacker hopes the server will verify with the public RSA key as an HMAC secret)
    let header = json!({
        "alg": "HS256",
        "typ": "JWT",
        "kid": "key-1"
    });
    let claims = json!({
        "sub": "attacker",
        "email": "attacker@evil.com",
        "iss": app.url(),
        "aud": "admin-ui",
        "exp": 9999999999_u64,
        "iat": 1000000000_u64
    });
    let fake_token = craft_jwt(&header, &claims);

    let resp = app
        .client()
        .get(&format!("{}/oidc/userinfo", app.url()))
        .header("authorization", format!("Bearer {fake_token}"))
        .send()
        .await
        .expect("userinfo request failed");

    // Must be rejected — RS256 is the only accepted algorithm
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "JWT with alg:HS256 must be rejected (only RS256 is accepted)"
    );
}

// ===================================================================
// Group 2: PKCE Bypass
// ===================================================================

#[tokio::test]
async fn test_authorize_pkce_required_for_public_client() {
    let app = TestApp::new().await;

    // Seed a public client with pkce_required=true
    let client_id = "public-pkce-client";
    let redirect_uri = "https://app.example.com/callback";
    app.seed_client(client_id, "public", &[redirect_uri]).await;

    // Attempt to authorize WITHOUT code_challenge
    let authorize_url = format!(
        "{}/oidc/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid&state=abc&login_hint={}",
        app.url(),
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(fixtures::TEST_USER_EMAIL),
    );

    let resp = app
        .client()
        .get(&authorize_url)
        .send()
        .await
        .expect("authorize request failed");

    // Should NOT succeed — must return an error (302 to error page or 400)
    let status = resp.status();
    assert!(
        status != StatusCode::TEMPORARY_REDIRECT || {
            // If it's a redirect, it must NOT be to the legitimate callback with a code
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            // Either redirect to error page, or redirect to callback with error param
            !location.starts_with(redirect_uri) || location.contains("error=")
        },
        "PKCE-required public client must reject authorize without code_challenge, got status {status}"
    );

    // Verify error is present in the response
    if status == StatusCode::TEMPORARY_REDIRECT {
        let location = resp
            .headers()
            .get("location")
            .expect("redirect must have Location")
            .to_str()
            .expect("Location must be valid UTF-8");
        assert!(
            location.contains("error=") || location.contains("/oidc/error"),
            "redirect should contain error parameter or point to error page, got: {location}"
        );
    } else {
        // Non-redirect error response
        assert!(
            status.is_client_error(),
            "expected 4xx error for missing PKCE, got {status}"
        );
    }
}

#[tokio::test]
async fn test_authorize_code_exchange_wrong_verifier() {
    let app = TestApp::new().await;

    // Seed a confidential client with a known secret
    let client_id = "pkce-wrong-verifier";
    let client_secret = "VerifierSecret123!";
    let redirect_uri = "https://app.example.com/callback";
    app.seed_client_with_secret(client_id, client_secret, &[redirect_uri])
        .await;

    // Use a legitimate code_verifier for the authorize step
    let real_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = pkce_s256_challenge(real_verifier);
    let state = "wrong-verifier-test";

    // 1. Authorize with the real verifier's challenge
    let authorize_url = format!(
        "{}/oidc/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid+profile&state={}&code_challenge={}&code_challenge_method=S256&login_hint={}",
        app.url(),
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(state),
        urlencoding::encode(&code_challenge),
        urlencoding::encode(fixtures::TEST_USER_EMAIL),
    );

    let resp = app
        .client()
        .get(&authorize_url)
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

    let url = url::Url::parse(location).expect("invalid redirect URL");
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("authorization code must be present");

    // 2. Exchange code with a WRONG verifier
    let wrong_verifier = "completely_wrong_verifier_value_that_does_not_match";
    let token_resp = app
        .client()
        .post(&format!("{}/oidc/token", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
            urlencoding::encode(&code),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(client_id),
            urlencoding::encode(client_secret),
            urlencoding::encode(wrong_verifier),
        ))
        .send()
        .await
        .expect("token request failed");

    // Must be rejected — 400 invalid_grant
    assert_eq!(
        token_resp.status(),
        StatusCode::BAD_REQUEST,
        "wrong code_verifier must be rejected with 400"
    );
    let body: Value = token_resp.json().await.expect("response should be JSON");
    assert_eq!(
        body["error"].as_str(),
        Some("invalid_grant"),
        "error should be invalid_grant, got: {body:?}"
    );
}

#[tokio::test]
async fn test_authorize_code_exchange_without_verifier() {
    let app = TestApp::new().await;

    // Seed a confidential client with a known secret
    let client_id = "pkce-no-verifier";
    let client_secret = "NoVerifierSecret123!";
    let redirect_uri = "https://app.example.com/callback";
    app.seed_client_with_secret(client_id, client_secret, &[redirect_uri])
        .await;

    // Use a legitimate code_verifier for the authorize step
    let real_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = pkce_s256_challenge(real_verifier);
    let state = "no-verifier-test";

    // 1. Authorize with PKCE challenge
    let authorize_url = format!(
        "{}/oidc/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid+profile&state={}&code_challenge={}&code_challenge_method=S256&login_hint={}",
        app.url(),
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(state),
        urlencoding::encode(&code_challenge),
        urlencoding::encode(fixtures::TEST_USER_EMAIL),
    );

    let resp = app
        .client()
        .get(&authorize_url)
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

    let url = url::Url::parse(location).expect("invalid redirect URL");
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("authorization code must be present");

    // 2. Exchange code WITHOUT code_verifier (omit it entirely)
    let token_resp = app
        .client()
        .post(&format!("{}/oidc/token", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}",
            urlencoding::encode(&code),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(client_id),
            urlencoding::encode(client_secret),
        ))
        .send()
        .await
        .expect("token request failed");

    // Must be rejected — 400 invalid_grant
    assert_eq!(
        token_resp.status(),
        StatusCode::BAD_REQUEST,
        "missing code_verifier must be rejected with 400"
    );
    let body: Value = token_resp.json().await.expect("response should be JSON");
    assert_eq!(
        body["error"].as_str(),
        Some("invalid_grant"),
        "error should be invalid_grant, got: {body:?}"
    );
}

// ===================================================================
// Group 3: Redirect URI Validation
// ===================================================================

#[tokio::test]
async fn test_authorize_open_redirect_rejected() {
    let app = TestApp::new().await;

    // Seed a client with a specific redirect_uri
    let client_id = "redirect-test-client";
    let client_secret = "RedirectSecret123!";
    let legitimate_redirect = "https://app.example.com/callback";
    app.seed_client_with_secret(client_id, client_secret, &[legitimate_redirect])
        .await;

    // Attempt to authorize with a different (evil) redirect_uri
    let evil_redirect = "https://evil.com/callback";
    let authorize_url = format!(
        "{}/oidc/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid&state=abc&login_hint={}",
        app.url(),
        urlencoding::encode(client_id),
        urlencoding::encode(evil_redirect),
        urlencoding::encode(fixtures::TEST_USER_EMAIL),
    );

    let resp = app
        .client()
        .get(&authorize_url)
        .send()
        .await
        .expect("authorize request failed");

    // The server must NOT redirect to the attacker's URL
    if resp.status() == StatusCode::TEMPORARY_REDIRECT {
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            !location.starts_with(evil_redirect),
            "server must NOT redirect to attacker's URL, got: {location}"
        );
        // The redirect should either go to an error page or to the legitimate callback with error
        assert!(
            location.contains("error=")
                || location.contains("/oidc/error")
                || location.starts_with(legitimate_redirect),
            "redirect should go to error page or legitimate callback with error, got: {location}"
        );
    } else {
        // Non-redirect error — also acceptable
        assert!(
            resp.status().is_client_error(),
            "expected 4xx error for open redirect attempt, got {}",
            resp.status()
        );
    }
}

// ===================================================================
// Group 4: Token Replay
// ===================================================================

#[tokio::test]
async fn test_refresh_token_replay_detected() {
    let app = TestApp::new().await;

    // 1. Login to get initial tokens
    let login_body = login(&app).await;
    let old_refresh_token = login_body["refresh_token"]
        .as_str()
        .expect("refresh_token must be present")
        .to_string();

    // 2. Use the refresh token to get new tokens (rotation)
    let refresh_resp = app
        .client()
        .post(&format!("{}/oidc/token", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret=dummy",
            urlencoding::encode(&old_refresh_token),
            urlencoding::encode(fixtures::TEST_CLIENT_ID),
        ))
        .send()
        .await
        .expect("refresh token request failed");

    assert_eq!(refresh_resp.status(), StatusCode::OK);
    let refresh_body: Value = refresh_resp.json().await.expect("response should be JSON");

    let new_refresh_token = refresh_body["refresh_token"]
        .as_str()
        .expect("new refresh_token must be present");
    assert_ne!(
        new_refresh_token, old_refresh_token,
        "refresh token must rotate"
    );

    // 3. Replay the OLD refresh_token — should be detected
    let replay_resp = app
        .client()
        .post(&format!("{}/oidc/token", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret=dummy",
            urlencoding::encode(&old_refresh_token),
            urlencoding::encode(fixtures::TEST_CLIENT_ID),
        ))
        .send()
        .await
        .expect("replay refresh token request failed");

    let status = replay_resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "replayed refresh token should be rejected, got status {status}"
    );
    let body: Value = replay_resp.json().await.expect("response should be JSON");
    assert!(
        body["error"].as_str().is_some(),
        "replay response should contain error field"
    );

    // 4. The entire token family should be revoked — even the NEW token should fail
    let family_revoke_resp = app
        .client()
        .post(&format!("{}/oidc/token", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret=dummy",
            urlencoding::encode(new_refresh_token),
            urlencoding::encode(fixtures::TEST_CLIENT_ID),
        ))
        .send()
        .await
        .expect("family revoke check request failed");

    let family_status = family_revoke_resp.status();
    assert!(
        family_status == StatusCode::BAD_REQUEST || family_status == StatusCode::UNAUTHORIZED,
        "after replay detection, the entire token family should be revoked — \
         new token should also be rejected, got status {family_status}"
    );
}

// ===================================================================
// Group 5: SQL Injection
// ===================================================================

#[tokio::test]
async fn test_login_sql_injection_email() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": "' OR 1=1 --",
            "password": fixtures::TEST_USER_PASSWORD,
        }))
        .send()
        .await
        .expect("login request failed");

    // Must NOT return 200 — the injection should not bypass authentication
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "SQL injection in email must not bypass auth"
    );
    // Should get 400 invalid_grant (not 500, proving parameterized queries)
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "SQL injection in email should return 400 invalid_grant"
    );
    let body: Value = resp.json().await.expect("response should be JSON");
    assert_eq!(
        body["error"].as_str(),
        Some("invalid_grant"),
        "error should be invalid_grant for SQL injection attempt"
    );
}

#[tokio::test]
async fn test_login_sql_injection_password() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": "' OR 1=1 --",
        }))
        .send()
        .await
        .expect("login request failed");

    // Must NOT return 200 — the injection should not bypass authentication
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "SQL injection in password must not bypass auth"
    );
    // Should get 400 invalid_grant (not 500, proving parameterized queries)
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "SQL injection in password should return 400 invalid_grant"
    );
    let body: Value = resp.json().await.expect("response should be JSON");
    assert_eq!(
        body["error"].as_str(),
        Some("invalid_grant"),
        "error should be invalid_grant for SQL injection attempt"
    );
}

// ===================================================================
// Group 6: Input Validation
// ===================================================================

#[tokio::test]
async fn test_login_empty_email() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": "",
            "password": fixtures::TEST_USER_PASSWORD,
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "empty email must return 400"
    );
}

#[tokio::test]
async fn test_login_empty_password() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": "",
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "empty password must return 400"
    );
}

#[tokio::test]
async fn test_register_missing_fields() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/register", app.url()))
        .json(&json!({}))
        .send()
        .await
        .expect("register request failed");

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "register with empty body must return 400"
    );
}

// ===================================================================
// Group 7: Rate Limiting
// ===================================================================

#[tokio::test]
async fn test_rate_limiting_on_login() {
    let app = TestApp::new().await;

    // The rate limiter is per-IP with default 100 req/60s.
    // Send 110 rapid login requests; some should get 429.
    let mut rate_limited_count = 0usize;
    let total_requests = 110;

    for i in 0..total_requests {
        let resp = app
            .client()
            .post(&format!("{}/oidc/login", app.url()))
            .json(&json!({
                "email": format!("ratelimit-test-{i}@localhost"),
                "password": "SomePassword1!",
            }))
            .send()
            .await
            .expect("login request failed");

        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            rate_limited_count += 1;
        }
    }

    assert!(
        rate_limited_count > 0,
        "at least one request should be rate-limited (429) after {total_requests} rapid requests, \
         but none were"
    );
}
