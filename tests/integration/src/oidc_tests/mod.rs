//! OIDC end-to-end integration tests.
//!
//! Tests the full OIDC flow against a real HTTP server backed by PostgreSQL.
//! Each test spawns a fresh `TestApp` instance with a clean database.

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

/// Extract the `code` and `state` query parameters from a redirect Location header.
fn parse_redirect_params(location: &str) -> (String, Option<String>) {
    let url =
        url::Url::parse(location).unwrap_or_else(|_| panic!("invalid redirect URL: {location}"));
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string());
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string());
    (code.unwrap_or_default(), state)
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

// ===================================================================
// Group 1: Discovery & JWKS
// ===================================================================

#[tokio::test]
async fn test_discovery_document_complete() {
    let app = TestApp::new().await;
    let resp = app
        .client()
        .get(&format!("{}/.well-known/openid-configuration", app.url()))
        .send()
        .await
        .expect("discovery request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp
        .json()
        .await
        .expect("discovery response should be JSON");

    // Required OIDC Discovery fields
    let issuer = body["issuer"].as_str().expect("issuer must be a string");
    assert!(!issuer.is_empty(), "issuer must not be empty");

    // All endpoint URLs must contain the issuer as prefix
    for field in [
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "registration_endpoint",
        "end_session_endpoint",
    ] {
        let url = body[field].as_str().expect("{field} must be a string");
        assert!(
            url.starts_with(issuer),
            "{field} should start with issuer: {url}"
        );
    }

    // Arrays
    assert!(body["scopes_supported"].as_array().is_some());
    assert!(body["response_types_supported"].as_array().is_some());
    assert!(body["grant_types_supported"].as_array().is_some());
    assert!(
        body["id_token_signing_alg_values_supported"]
            .as_array()
            .is_some()
    );
    assert!(
        body["code_challenge_methods_supported"]
            .as_array()
            .is_some()
    );
    assert!(body["claims_supported"].as_array().is_some());
    assert!(
        body["token_endpoint_auth_methods_supported"]
            .as_array()
            .is_some()
    );
    assert!(body["subject_types_supported"].as_array().is_some());

    // Verify specific values
    let scopes = body["scopes_supported"].as_array().unwrap();
    assert!(scopes.contains(&json!("openid")));

    let response_types = body["response_types_supported"].as_array().unwrap();
    assert!(response_types.contains(&json!("code")));

    let grant_types = body["grant_types_supported"].as_array().unwrap();
    assert!(grant_types.contains(&json!("authorization_code")));
    assert!(grant_types.contains(&json!("client_credentials")));
    assert!(grant_types.contains(&json!("refresh_token")));

    let algs = body["id_token_signing_alg_values_supported"]
        .as_array()
        .unwrap();
    assert!(algs.contains(&json!("RS256")));

    let challenge_methods = body["code_challenge_methods_supported"].as_array().unwrap();
    assert!(challenge_methods.contains(&json!("S256")));
}

#[tokio::test]
async fn test_jwks_has_rsa_key() {
    let app = TestApp::new().await;
    let resp = app
        .client()
        .get(&format!("{}/oidc/jwks", app.url()))
        .send()
        .await
        .expect("jwks request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("jwks response should be JSON");

    let keys = body["keys"].as_array().expect("JWKS must have keys array");
    assert!(!keys.is_empty(), "JWKS must contain at least one key");

    let key = &keys[0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["alg"], "RS256");
    assert_eq!(key["use"], "sig");
    assert!(key["kid"].as_str().is_some(), "key must have kid");
    assert!(key["n"].as_str().is_some(), "RSA key must have n");
    assert!(key["e"].as_str().is_some(), "RSA key must have e");
}

// ===================================================================
// Group 2: Login Flow (Password Grant)
// ===================================================================

#[tokio::test]
async fn test_login_success() {
    let app = TestApp::new().await;
    let body = login(&app).await;

    // Verify all token fields present
    assert!(
        body["access_token"].as_str().is_some_and(|t| !t.is_empty()),
        "access_token must be non-empty"
    );
    assert!(
        body["refresh_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "refresh_token must be non-empty"
    );
    assert!(
        body["id_token"].as_str().is_some_and(|t| !t.is_empty()),
        "id_token must be non-empty"
    );
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 900);

    // Verify user info
    assert!(body["user"]["id"].as_str().is_some());
    assert_eq!(body["user"]["email"], fixtures::TEST_USER_EMAIL);
}

#[tokio::test]
async fn test_login_invalid_email() {
    let app = TestApp::new().await;
    let resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": "nonexistent@example.com",
            "password": "SomePass123!",
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.expect("response should be JSON");
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_login_wrong_password() {
    let app = TestApp::new().await;
    let resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": "WrongPassword1!",
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.expect("response should be JSON");
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_login_short_password() {
    let app = TestApp::new().await;
    let resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": "short",
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.expect("response should be JSON");
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_login_disabled_user() {
    let app = TestApp::new().await;

    // Seed a disabled user
    let email = "disabled@example.com";
    let password = "DisabledPass1!";
    app.seed_disabled_user(email, password).await;

    let resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": email,
            "password": password,
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.expect("response should be JSON");
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn test_login_brute_force_protection() {
    let app = TestApp::new().await;

    // Make 5 failed login attempts
    for _ in 0..5 {
        let resp = app
            .client()
            .post(&format!("{}/oidc/login", app.url()))
            .json(&json!({
                "email": fixtures::TEST_USER_EMAIL,
                "password": "WrongPassword1!",
            }))
            .send()
            .await
            .expect("login request failed");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // The 6th attempt should be blocked by brute-force protection
    let resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": "WrongPassword1!",
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.expect("response should be JSON");
    assert_eq!(body["error"], "access_denied");
}

// ===================================================================
// Group 3: Full Authorization Code + PKCE Flow
// ===================================================================

#[tokio::test]
async fn test_authorization_code_flow_with_pkce() {
    let app = TestApp::new().await;

    // 1. Seed a confidential client with a known secret
    let client_id = "test-confidential";
    let client_secret = "SuperSecret123!";
    let redirect_uri = "https://app.example.com/callback";
    app.seed_client_with_secret(client_id, client_secret, &[redirect_uri])
        .await;

    // 2. Generate PKCE verifier + challenge
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = pkce_s256_challenge(code_verifier);
    let state = "test-state-xyz";

    // 3. GET /oidc/authorize
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

    // 4. Verify 302 redirect with code and state
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp
        .headers()
        .get("location")
        .expect("redirect must have Location header")
        .to_str()
        .expect("Location header must be valid UTF-8");

    let (code, returned_state) = parse_redirect_params(location);
    assert!(!code.is_empty(), "authorization code must be present");
    assert_eq!(
        returned_state.as_deref(),
        Some(state),
        "state must match the one we sent"
    );

    // 5. POST /oidc/token with authorization_code grant
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

    // 7. Verify 200 + tokens
    assert_eq!(token_resp.status(), StatusCode::OK);
    let token_body: Value = token_resp
        .json()
        .await
        .expect("token response should be JSON");

    let access_token = token_body["access_token"]
        .as_str()
        .expect("access_token must be present");
    assert!(!access_token.is_empty());
    assert!(
        token_body["id_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty())
    );
    assert!(
        token_body["refresh_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty())
    );
    assert_eq!(token_body["token_type"], "Bearer");

    // 8. GET /oidc/userinfo with Bearer token
    let userinfo_resp = app
        .client()
        .get(&format!("{}/oidc/userinfo", app.url()))
        .header("authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("userinfo request failed");

    assert_eq!(userinfo_resp.status(), StatusCode::OK);
    let userinfo: Value = userinfo_resp.json().await.expect("userinfo should be JSON");
    assert!(
        userinfo["sub"].as_str().is_some(),
        "sub claim must be present"
    );
    assert_eq!(userinfo["email"], fixtures::TEST_USER_EMAIL);

    // 9. POST /oidc/introspect — verify active
    let introspect_resp = app
        .client()
        .post(&format!("{}/oidc/introspect", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "token={}&client_id={}&client_secret={}",
            urlencoding::encode(access_token),
            urlencoding::encode(client_id),
            urlencoding::encode(client_secret),
        ))
        .send()
        .await
        .expect("introspect request failed");

    assert_eq!(introspect_resp.status(), StatusCode::OK);
    let introspect_body: Value = introspect_resp
        .json()
        .await
        .expect("introspect should be JSON");
    assert_eq!(introspect_body["active"], true);

    // 10. POST /oidc/revoke
    let revoke_resp = app
        .client()
        .post(&format!("{}/oidc/revoke", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "token={}&client_id={}&client_secret={}",
            urlencoding::encode(access_token),
            urlencoding::encode(client_id),
            urlencoding::encode(client_secret),
        ))
        .send()
        .await
        .expect("revoke request failed");

    assert_eq!(revoke_resp.status(), StatusCode::OK);

    // 11. POST /oidc/introspect again — verify inactive
    let introspect_resp2 = app
        .client()
        .post(&format!("{}/oidc/introspect", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "token={}&client_id={}&client_secret={}",
            urlencoding::encode(access_token),
            urlencoding::encode(client_id),
            urlencoding::encode(client_secret),
        ))
        .send()
        .await
        .expect("introspect request failed");

    assert_eq!(introspect_resp2.status(), StatusCode::OK);
    let introspect_body2: Value = introspect_resp2
        .json()
        .await
        .expect("introspect should be JSON");
    assert_eq!(introspect_body2["active"], false);
}

// ===================================================================
// Group 4: Refresh Token Rotation
// ===================================================================

#[tokio::test]
async fn test_refresh_token_rotation() {
    let app = TestApp::new().await;

    // 1. Login to get initial tokens
    let login_body = login(&app).await;
    let old_refresh_token = login_body["refresh_token"]
        .as_str()
        .expect("refresh_token must be present")
        .to_string();

    // 2. Use the refresh token to get new tokens
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

    let new_access_token = refresh_body["access_token"]
        .as_str()
        .expect("new access_token must be present");
    let new_refresh_token = refresh_body["refresh_token"]
        .as_str()
        .expect("new refresh_token must be present");
    assert!(!new_access_token.is_empty());
    assert!(!new_refresh_token.is_empty());

    // The new tokens should differ from the old ones
    assert_ne!(
        new_refresh_token, old_refresh_token,
        "refresh token must rotate"
    );

    // 3. Try using the OLD refresh_token again — should fail (replay detection)
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

    // The replayed token should be rejected (400 or error response)
    let status = replay_resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "replayed refresh token should be rejected, got status {status}"
    );
}

// ===================================================================
// Group 5: Token Introspection & Revocation
// ===================================================================

#[tokio::test]
async fn test_introspect_revoked_token() {
    let app = TestApp::new().await;

    // Login and get tokens
    let login_body = login(&app).await;
    let access_token = login_body["access_token"]
        .as_str()
        .expect("access_token must be present")
        .to_string();

    // Revoke the access token
    let client_id = fixtures::TEST_CLIENT_ID;
    let client_secret = "dummy"; // admin-ui client has no secret, but revoke expects one

    // We need a client with a secret for introspect/revoke. Seed one.
    let conf_client_id = "introspect-client";
    let conf_client_secret = "IntrospectSecret1!";
    app.seed_client_with_secret(conf_client_id, conf_client_secret, &[])
        .await;

    // Login again using the confidential client to get a token we can introspect/revoke
    let login_resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": fixtures::TEST_USER_PASSWORD,
            "client_id": conf_client_id,
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(login_resp.status(), StatusCode::OK);
    let login_body2: Value = login_resp
        .json()
        .await
        .expect("login response should be JSON");
    let access_token2 = login_body2["access_token"]
        .as_str()
        .expect("access_token must be present")
        .to_string();

    // Introspect — should be active
    let intro_resp = app
        .client()
        .post(&format!("{}/oidc/introspect", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "token={}&client_id={}&client_secret={}",
            urlencoding::encode(&access_token2),
            urlencoding::encode(conf_client_id),
            urlencoding::encode(conf_client_secret),
        ))
        .send()
        .await
        .expect("introspect request failed");

    assert_eq!(intro_resp.status(), StatusCode::OK);
    let intro_body: Value = intro_resp.json().await.expect("introspect should be JSON");
    assert_eq!(intro_body["active"], true);

    // Revoke
    let revoke_resp = app
        .client()
        .post(&format!("{}/oidc/revoke", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "token={}&client_id={}&client_secret={}",
            urlencoding::encode(&access_token2),
            urlencoding::encode(conf_client_id),
            urlencoding::encode(conf_client_secret),
        ))
        .send()
        .await
        .expect("revoke request failed");

    assert_eq!(revoke_resp.status(), StatusCode::OK);

    // Introspect again — should be inactive
    let intro_resp2 = app
        .client()
        .post(&format!("{}/oidc/introspect", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "token={}&client_id={}&client_secret={}",
            urlencoding::encode(&access_token2),
            urlencoding::encode(conf_client_id),
            urlencoding::encode(conf_client_secret),
        ))
        .send()
        .await
        .expect("introspect request failed");

    assert_eq!(intro_resp2.status(), StatusCode::OK);
    let intro_body2: Value = intro_resp2.json().await.expect("introspect should be JSON");
    assert_eq!(intro_body2["active"], false);
}

#[tokio::test]
async fn test_revoke_idempotent() {
    let app = TestApp::new().await;

    // Seed a confidential client
    let client_id = "revoke-idempotent-client";
    let client_secret = "RevokeSecret1!";
    app.seed_client_with_secret(client_id, client_secret, &[])
        .await;

    // Login to get a token
    let login_resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": fixtures::TEST_USER_PASSWORD,
            "client_id": client_id,
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(login_resp.status(), StatusCode::OK);
    let login_body: Value = login_resp
        .json()
        .await
        .expect("login response should be JSON");
    let access_token = login_body["access_token"]
        .as_str()
        .expect("access_token must be present")
        .to_string();

    // Revoke the token
    let revoke_body = format!(
        "token={}&client_id={}&client_secret={}",
        urlencoding::encode(&access_token),
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret),
    );

    let resp1 = app
        .client()
        .post(&format!("{}/oidc/revoke", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(&revoke_body)
        .send()
        .await
        .expect("first revoke request failed");

    assert_eq!(resp1.status(), StatusCode::OK);

    // Revoke again — should still return 200 (idempotent per RFC 7009)
    let resp2 = app
        .client()
        .post(&format!("{}/oidc/revoke", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(&revoke_body)
        .send()
        .await
        .expect("second revoke request failed");

    assert_eq!(resp2.status(), StatusCode::OK);
}

// ===================================================================
// Group 6: UserInfo
// ===================================================================

#[tokio::test]
async fn test_userinfo_no_auth() {
    let app = TestApp::new().await;
    let resp = app
        .client()
        .get(&format!("{}/oidc/userinfo", app.url()))
        .send()
        .await
        .expect("userinfo request failed");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_userinfo_invalid_token() {
    let app = TestApp::new().await;
    let resp = app
        .client()
        .get(&format!("{}/oidc/userinfo", app.url()))
        .header("authorization", "Bearer garbage_token_value")
        .send()
        .await
        .expect("userinfo request failed");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_userinfo_success() {
    let app = TestApp::new().await;
    let login_body = login(&app).await;
    let access_token = login_body["access_token"]
        .as_str()
        .expect("access_token must be present");

    let resp = app
        .client()
        .get(&format!("{}/oidc/userinfo", app.url()))
        .header("authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("userinfo request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("userinfo should be JSON");

    // Must have sub and email claims
    assert!(body["sub"].as_str().is_some(), "sub claim must be present");
    assert_eq!(body["email"], fixtures::TEST_USER_EMAIL);
}

// ===================================================================
// Group 7: Logout
// ===================================================================

#[tokio::test]
async fn test_logout_redirect_to_home() {
    let app = TestApp::new().await;
    let resp = app
        .client()
        .get(&format!("{}/oidc/logout", app.url()))
        .send()
        .await
        .expect("logout request failed");

    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp
        .headers()
        .get("location")
        .expect("redirect must have Location header")
        .to_str()
        .expect("Location must be valid UTF-8");
    assert_eq!(location, "/");
}

#[tokio::test]
async fn test_logout_with_post_logout_redirect() {
    let app = TestApp::new().await;
    let post_logout_uri = "https://app.example.com/logged-out";
    let state = "abc123";

    let resp = app
        .client()
        .get(&format!(
            "{}/oidc/logout?post_logout_redirect_uri={}&state={}",
            app.url(),
            urlencoding::encode(post_logout_uri),
            urlencoding::encode(state),
        ))
        .send()
        .await
        .expect("logout request failed");

    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp
        .headers()
        .get("location")
        .expect("redirect must have Location header")
        .to_str()
        .expect("Location must be valid UTF-8");

    // Without a valid client_id + matching redirect_uri, the server falls back to "/"
    // If client_id is provided and the URI matches, it redirects to the URI with state.
    // We test the fallback path here (no client_id → redirect to /)
    if location == "/" {
        // This is the expected fallback when client_id is not provided or URI doesn't match
        return;
    }

    // If the server does support the redirect, verify it
    assert!(
        location.starts_with(post_logout_uri),
        "should redirect to post_logout_redirect_uri"
    );
    assert!(
        location.contains(&format!("state={}", urlencoding::encode(state))),
        "should include state parameter"
    );
}

// ===================================================================
// Group 8: Dynamic Client Registration
// ===================================================================

#[tokio::test]
async fn test_register_confidential_client() {
    let app = TestApp::new().await;
    let resp = app
        .client()
        .post(&format!("{}/oidc/register", app.url()))
        .json(&json!({
            "client_name": "Test Confidential App",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
            "scope": "openid profile",
            "token_endpoint_auth_method": "client_secret_basic",
        }))
        .send()
        .await
        .expect("register request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("register response should be JSON");

    assert!(body["client_id"].as_str().is_some_and(|t| !t.is_empty()));
    assert!(
        body["client_secret"]
            .as_str()
            .is_some_and(|t| !t.is_empty())
    );
    assert_eq!(body["client_name"], "Test Confidential App");
}

#[tokio::test]
async fn test_register_public_client() {
    let app = TestApp::new().await;
    let resp = app
        .client()
        .post(&format!("{}/oidc/register", app.url()))
        .json(&json!({
            "client_name": "SPA Public App",
            "redirect_uris": ["https://spa.example.com/callback"],
            "grant_types": ["authorization_code"],
            "scope": "openid",
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .expect("register request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("register response should be JSON");

    assert!(body["client_id"].as_str().is_some_and(|t| !t.is_empty()));
    // Public client should NOT have a client_secret
    assert!(
        body.get("client_secret").is_none() || body["client_secret"].is_null(),
        "public client must not have a client_secret"
    );
}

// ===================================================================
// Group 9: Error Cases
// ===================================================================

#[tokio::test]
async fn test_authorize_missing_client_id() {
    let app = TestApp::new().await;
    let resp = app
        .client()
        .get(&format!(
            "{}/oidc/authorize?response_type=code&redirect_uri=https://app.example.com/callback",
            app.url()
        ))
        .send()
        .await
        .expect("authorize request failed");

    // Should redirect to error page when client_id is missing
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp
        .headers()
        .get("location")
        .expect("redirect must have Location header")
        .to_str()
        .expect("Location must be valid UTF-8");
    // Error redirect — either to the callback with error params or to /oidc/error
    assert!(
        location.contains("error=") || location.contains("/oidc/error"),
        "should redirect to error page or callback with error, got: {location}"
    );
}

#[tokio::test]
async fn test_token_invalid_grant_type() {
    let app = TestApp::new().await;
    let resp = app
        .client()
        .post(&format!("{}/oidc/token", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("grant_type=invalid_grant&client_id=admin-ui&client_secret=dummy")
        .send()
        .await
        .expect("token request failed");

    // Should return an error response
    assert_ne!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("response should be JSON");
    assert!(body["error"].as_str().is_some(), "should have error field");
}
