//! Realm-scoped OIDC integration tests (Phases 1–3).
//!
//! Tests per-realm login, discovery, authorization, and theming
//! introduced in the multi-tenancy phases.

use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::helpers::app::TestApp;
use crate::helpers::fixtures;

// ===================================================================
// Phase 1 — Per-Realm Login
// ===================================================================

#[tokio::test]
async fn test_per_realm_login_success() {
    let app = TestApp::new().await;

    // The baseline TestApp already seeds a "master" realm.
    // Use the Keycloak-compatible per-realm token endpoint.
    let resp = app
        .client()
        .post(&format!(
            "{}/realms/master/protocol/openid-connect/token",
            app.url()
        ))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": fixtures::TEST_USER_PASSWORD,
        }))
        .send()
        .await
        .expect("per-realm login request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("response should be JSON");

    assert!(
        body["access_token"].as_str().is_some_and(|t| !t.is_empty()),
        "access_token must be present"
    );
    assert!(
        body["id_token"].as_str().is_some_and(|t| !t.is_empty()),
        "id_token must be present"
    );
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["user"]["email"], fixtures::TEST_USER_EMAIL);
}

#[tokio::test]
async fn test_per_realm_login_wrong_realm() {
    let app = TestApp::new().await;

    // "nonexistent" realm should return authentication failed
    let resp = app
        .client()
        .post(&format!(
            "{}/realms/nonexistent/protocol/openid-connect/token",
            app.url()
        ))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": fixtures::TEST_USER_PASSWORD,
        }))
        .send()
        .await
        .expect("per-realm login request failed");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.expect("response should be JSON");
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_per_realm_convenience_login_post() {
    let app = TestApp::new().await;

    // POST /realms/{realm}/login (convenience path, same as token)
    let resp = app
        .client()
        .post(&format!("{}/realms/master/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": fixtures::TEST_USER_PASSWORD,
        }))
        .send()
        .await
        .expect("per-realm convenience login failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("response should be JSON");
    assert!(body["access_token"].as_str().is_some());
}

// ===================================================================
// Phase 2 — Per-Realm Discovery & Authorize
// ===================================================================

#[tokio::test]
async fn test_realm_discovery_document() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(&format!(
            "{}/realms/master/.well-known/openid-configuration",
            app.url()
        ))
        .send()
        .await
        .expect("realm discovery request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("response should be JSON");

    // Realm-scoped issuer
    let issuer = body["issuer"].as_str().expect("issuer must be present");
    assert!(
        issuer.ends_with("/realms/master"),
        "realm issuer should end with /realms/master, got: {issuer}"
    );

    // Realm-scoped endpoints
    let authz = body["authorization_endpoint"]
        .as_str()
        .expect("authorization_endpoint must be present");
    assert!(
        authz.contains("/realms/master/protocol/openid-connect/auth"),
        "authorization_endpoint should be realm-scoped, got: {authz}"
    );

    let token = body["token_endpoint"]
        .as_str()
        .expect("token_endpoint must be present");
    assert!(
        token.contains("/realms/master/protocol/openid-connect/token"),
        "token_endpoint should be realm-scoped, got: {token}"
    );

    assert!(
        body.get("check_session_iframe").is_none(),
        "realm discovery must not advertise check_session_iframe until it is supported"
    );

    // Standard arrays still present
    assert!(body["scopes_supported"].as_array().is_some());
    assert!(body["response_types_supported"].as_array().is_some());
    assert!(body["grant_types_supported"].as_array().is_some());

    let response_types = body["response_types_supported"].as_array().unwrap();
    assert!(response_types.contains(&json!("code")));
    assert!(response_types.contains(&json!("token")));
    assert!(response_types.contains(&json!("id_token")));
    assert!(response_types.contains(&json!("code token")));
    assert!(response_types.contains(&json!("code id_token")));
    assert!(response_types.contains(&json!("id_token token")));
    assert!(response_types.contains(&json!("code id_token token")));
}

#[tokio::test]
async fn test_realm_authorize_redirects_to_realm_login() {
    let app = TestApp::new().await;

    // Use a public client (admin-ui) seeded by TestApp
    let client_id = fixtures::TEST_CLIENT_ID;
    let redirect_uri = "http://localhost:3000/callback";

    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = crate::oidc_tests::pkce_s256_challenge(code_verifier);

    let authorize_url = format!(
        "{}/realms/master/protocol/openid-connect/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid&state=xyz&code_challenge={}&code_challenge_method=S256",
        app.url(),
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(&code_challenge),
    );

    let resp = app
        .client()
        .get(&authorize_url)
        .send()
        .await
        .expect("realm authorize request failed");

    // When no session cookie exists, the server redirects to the realm login page
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp
        .headers()
        .get("location")
        .expect("redirect must have Location header")
        .to_str()
        .expect("Location must be valid UTF-8");

    assert!(
        location.starts_with("/realms/master/login"),
        "should redirect to realm-scoped login page, got: {location}"
    );
}

#[tokio::test]
async fn test_realm_authorize_with_login_hint_success() {
    let app = TestApp::new().await;

    let client_id = fixtures::TEST_CLIENT_ID;
    let redirect_uri = "http://localhost:3000/callback";

    // Build the realm-scoped authorize URL with login_hint
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = crate::oidc_tests::pkce_s256_challenge(code_verifier);
    let authorize_url = format!(
        "{}/realms/master/protocol/openid-connect/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid&state=abc&login_hint={}&code_challenge={}&code_challenge_method=S256",
        app.url(),
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(fixtures::TEST_USER_EMAIL),
        urlencoding::encode(&code_challenge),
    );

    let resp = app
        .client()
        .get(&authorize_url)
        .send()
        .await
        .expect("realm authorize request failed");

    // With login_hint, the user is auto-authenticated and redirected back with a code
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp
        .headers()
        .get("location")
        .expect("redirect must have Location header")
        .to_str()
        .expect("Location must be valid UTF-8");

    assert!(
        location.starts_with(redirect_uri),
        "should redirect back to callback, got: {location}"
    );
    assert!(
        location.contains("code="),
        "redirect should contain authorization code, got: {location}"
    );
}

// ===================================================================
// Phase 4 — Realm Branded Login Page
// ===================================================================

#[tokio::test]
async fn test_realm_login_page_html() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(&format!("{}/realms/master/login", app.url()))
        .send()
        .await
        .expect("realm login page request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("response should be text");

    // Should be a self-contained HTML page
    assert!(
        body.contains("<!DOCTYPE html>"),
        "should return HTML document"
    );
    assert!(body.contains("<form"), "should contain a login form");
    assert!(
        body.contains("/realms/master/protocol/openid-connect/token"),
        "form should POST to realm token endpoint"
    );
}

#[tokio::test]
async fn test_realm_login_page_not_found() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(&format!("{}/realms/nonexistent/login", app.url()))
        .send()
        .await
        .expect("realm login page request failed");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_realm_login_page_disabled_realm() {
    let app = TestApp::new().await;

    // Seed a new realm and disable it
    let mut conn = app.db_conn().await;
    let disabled_realm = crate::helpers::fixtures::test_realm("disabled-realm");
    let _realm_id = disabled_realm.id;
    oidc_repository::repositories::realm_repo::RealmRepo
        .create(&mut conn, &disabled_realm)
        .await
        .expect("create realm");
    oidc_repository::repositories::realm_repo::RealmRepo
        .update(
            &mut conn,
            &oidc_core::models::Realm {
                enabled: false,
                ..disabled_realm
            },
        )
        .await
        .expect("disable realm");
    let _ = conn.close().await;

    let resp = app
        .client()
        .get(&format!("{}/realms/disabled-realm/login", app.url()))
        .send()
        .await
        .expect("realm login page request failed");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_realm_login_page_theming() {
    let app = TestApp::new().await;

    // Update master realm with a custom theme via admin API
    let admin_login = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": fixtures::TEST_USER_PASSWORD,
        }))
        .send()
        .await
        .expect("admin login failed");
    assert_eq!(admin_login.status(), StatusCode::OK);
    let admin_body: Value = admin_login.json().await.expect("json");
    let admin_token = admin_body["access_token"]
        .as_str()
        .expect("token")
        .to_string();

    // Get master realm ID
    let list_resp = app
        .client()
        .get(&format!("{}/api/realms?limit=1", app.url()))
        .header("authorization", format!("Bearer {admin_token}"))
        .send()
        .await
        .expect("realm list failed");
    let list_body: Value = list_resp.json().await.expect("json");
    let master_id = list_body["items"][0]["id"].as_str().expect("realm id");

    // Update theme config
    let update_resp = app
        .client()
        .put(&format!("{}/api/realms/{master_id}", app.url()))
        .header("authorization", format!("Bearer {admin_token}"))
        .json(&json!({
            "config": {
                "theme": {
                    "login_title": "Master Realm Custom Title",
                    "logo_url": "https://example.com/logo.png",
                    "primary_color": "#ff0000",
                    "bg_color": "#000000"
                }
            }
        }))
        .send()
        .await
        .expect("realm update failed");
    assert_eq!(update_resp.status(), StatusCode::OK);

    // Fetch the login page and verify theme is applied
    let resp = app
        .client()
        .get(&format!("{}/realms/master/login", app.url()))
        .send()
        .await
        .expect("realm login page request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("response should be text");

    assert!(
        body.contains("Master Realm Custom Title"),
        "login page should contain custom title"
    );
    assert!(
        body.contains("https://example.com/logo.png"),
        "login page should contain logo URL"
    );
    assert!(
        body.contains("#ff0000"),
        "login page should contain custom primary color"
    );
    assert!(
        body.contains("#000000"),
        "login page should contain custom bg color"
    );
}

#[tokio::test]
async fn test_realm_certs_endpoint() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(&format!(
            "{}/realms/master/protocol/openid-connect/certs",
            app.url()
        ))
        .send()
        .await
        .expect("realm certs request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("certs should be JSON");

    let keys = body["keys"].as_array().expect("JWKS must have keys array");
    assert_eq!(
        keys.len(),
        2,
        "realm JWKS should contain 2 keys (RSA + EdDSA)"
    );

    let has_rsa = keys
        .iter()
        .any(|k| k["kty"] == "RSA" && k["alg"] == "RS256");
    let has_okp = keys
        .iter()
        .any(|k| k["kty"] == "OKP" && k["alg"] == "EdDSA");
    assert!(has_rsa, "realm certs should contain RSA key");
    assert!(has_okp, "realm certs should contain EdDSA key");
}

#[tokio::test]
async fn test_realm_certs_unknown_realm() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(&format!(
            "{}/realms/nonexistent/protocol/openid-connect/certs",
            app.url()
        ))
        .send()
        .await
        .expect("realm certs request failed");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
