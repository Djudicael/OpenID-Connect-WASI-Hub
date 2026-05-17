//! Admin API endpoint integration tests.
//!
//! Covers: Stats, Users CRUD, Clients CRUD, Realms CRUD, Sessions, Audit Events.

mod policy_tests;
mod rbac_tests;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::StatusCode;
use serde_json::{Value, json};

fn extract_cookie_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookie| {
            cookie
                .strip_prefix(&format!("{name}="))
                .and_then(|rest| rest.split(';').next())
                .map(|value| value.to_string())
        })
}

use crate::helpers::app::TestApp;
use crate::helpers::fixtures;

// ===================================================================
// Helpers
// ===================================================================

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

fn admin_client(_app: &TestApp, _token: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

// ===================================================================
// Stats
// ===================================================================

#[tokio::test]
async fn test_stats_endpoint() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let resp = admin_client(&app, &token)
        .get(&format!("{}/api/stats", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .expect("stats request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("stats response should be JSON");
    assert!(body["users"].as_i64().is_some());
    assert!(body["clients"].as_i64().is_some());
    assert!(body["realms"].as_i64().is_some());
    assert!(body["active_sessions"].as_i64().is_some());
}

#[tokio::test]
async fn test_admin_routes_set_server_issued_csrf_cookie_and_reject_mismatched_header() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let browser_post_without_csrf = admin_client(&app, &token)
        .post(&format!("{}/api/realms", app.url()))
        .bearer_auth(&token)
        .header(reqwest::header::ORIGIN, "https://app.example.com")
        .json(&json!({
            "name": "csrf-browser-without-cookie",
            "display_name": "CSRF Browser Without Cookie",
            "enabled": true,
        }))
        .send()
        .await
        .expect("browser-like realm create request failed");

    assert_eq!(browser_post_without_csrf.status(), StatusCode::FORBIDDEN);
    let browser_body: Value = browser_post_without_csrf
        .json()
        .await
        .expect("response should be JSON");
    assert_eq!(browser_body["error"], "csrf_validation_failed");

    let get_resp = admin_client(&app, &token)
        .get(&format!("{}/api/realms?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .expect("realms request failed");

    assert_eq!(get_resp.status(), StatusCode::OK);
    let csrf_cookie = extract_cookie_value(get_resp.headers(), "oidc_csrf_token")
        .expect("server should issue a CSRF cookie on admin GET requests");

    let bad_post = admin_client(&app, &token)
        .post(&format!("{}/api/realms", app.url()))
        .bearer_auth(&token)
        .header(
            reqwest::header::COOKIE,
            format!("oidc_csrf_token={csrf_cookie}"),
        )
        .header("X-CSRF-Token", "wrong-token")
        .json(&json!({
            "name": "csrf-guarded-realm",
            "display_name": "CSRF Guarded Realm",
            "enabled": true,
        }))
        .send()
        .await
        .expect("realm create request failed");

    assert_eq!(bad_post.status(), StatusCode::FORBIDDEN);
    let body: Value = bad_post.json().await.expect("response should be JSON");
    assert_eq!(body["error"], "csrf_validation_failed");

    let ok_post = admin_client(&app, &token)
        .post(&format!("{}/api/realms", app.url()))
        .bearer_auth(&token)
        .header(
            reqwest::header::COOKIE,
            format!("oidc_csrf_token={csrf_cookie}"),
        )
        .header("X-CSRF-Token", csrf_cookie)
        .json(&json!({
            "name": "csrf-valid-realm",
            "display_name": "CSRF Valid Realm",
            "enabled": true,
        }))
        .send()
        .await
        .expect("realm create request failed");

    assert_eq!(ok_post.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_reencrypt_legacy_secrets_maintenance_endpoint() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let csrf_get = admin_client(&app, &token)
        .get(&format!("{}/api/realms?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .expect("csrf bootstrap request failed");
    assert_eq!(csrf_get.status(), StatusCode::OK);
    let csrf_cookie = extract_cookie_value(csrf_get.headers(), "oidc_csrf_token")
        .expect("server should issue a CSRF cookie");

    let legacy_realm_resp = admin_client(&app, &token)
        .post(&format!("{}/api/realms", app.url()))
        .bearer_auth(&token)
        .header(
            reqwest::header::COOKIE,
            format!("oidc_csrf_token={csrf_cookie}"),
        )
        .header("X-CSRF-Token", csrf_cookie.clone())
        .json(&json!({
            "name": "legacy-secret-realm",
            "display_name": "Legacy Secret Realm",
            "enabled": true,
        }))
        .send()
        .await
        .expect("create realm failed");
    assert_eq!(legacy_realm_resp.status(), StatusCode::OK);
    let realm_body: Value = legacy_realm_resp.json().await.unwrap();
    let realm_id = realm_body["id"].as_str().expect("realm id must be present");
    let realm_id = uuid::Uuid::parse_str(realm_id).expect("realm id should parse");

    let realm_keys = {
        use pkcs8::EncodePrivateKey;
        use rand::RngCore;
        use rand::rngs::OsRng;
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let rsa_private = RsaPrivateKey::new(&mut OsRng, 2048).expect("failed to generate RSA key");
        let rsa_public = RsaPublicKey::from(&rsa_private);
        let rsa_private_pem = rsa_private
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("failed to encode RSA PEM")
            .to_string();

        let mut ed_secret = [0u8; 32];
        OsRng.fill_bytes(&mut ed_secret);
        let ed_signing = ed25519_dalek::SigningKey::from_bytes(&ed_secret);
        let ed_verifying = ed_signing.verifying_key();
        let ed_private_pem = ed_signing
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .expect("failed to encode Ed25519 PEM")
            .to_string();

        oidc_core::models::RealmSigningKeys {
            realm_id,
            rsa_private_pem,
            rsa_kid: "key-1".to_string(),
            rsa_public_n: URL_SAFE_NO_PAD.encode(rsa_public.n().to_bytes_be()),
            rsa_public_e: URL_SAFE_NO_PAD.encode(rsa_public.e().to_bytes_be()),
            ed25519_private_pem: ed_private_pem,
            ed25519_kid: "ed-key-1".to_string(),
            ed25519_public_x: URL_SAFE_NO_PAD.encode(ed_verifying.to_bytes()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    };

    let mut conn = app.db_conn().await;
    conn.execute_params(
        "UPDATE realm_signing_keys SET rsa_private_pem = $1, ed25519_private_pem = $2 WHERE realm_id = $3",
        &[&realm_keys.rsa_private_pem, &realm_keys.ed25519_private_pem, &realm_id],
    )
    .await
    .expect("failed to downgrade realm signing keys to plaintext");

    let idp_id = uuid::Uuid::new_v4();
    conn.execute_params(
        "INSERT INTO identity_providers (id, realm_id, alias, display_name, provider_type, enabled, issuer, authorization_url, token_url, userinfo_url, jwks_url, client_id, client_secret, scopes, auto_create_users, link_users_by_email, created_at) VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7, $8, $9, $10, $11, $12, $13, TRUE, TRUE, NOW())",
        &[
            &idp_id,
            &realm_id,
            &"legacy-plaintext-idp",
            &"Legacy Plaintext IdP",
            &"oidc",
            &"https://example.com",
            &"https://example.com/auth",
            &"https://example.com/token",
            &"https://example.com/userinfo",
            &"https://example.com/jwks",
            &"legacy-client",
            &"legacy-plaintext-secret",
            &serde_json::json!(["openid", "profile", "email"]),
        ],
    )
    .await
    .expect("failed to insert legacy plaintext identity provider");
    let _ = conn.close().await;

    let reencrypt_resp = admin_client(&app, &token)
        .post(&format!("{}/api/maintenance/reencrypt-secrets", app.url()))
        .bearer_auth(&token)
        .header(
            reqwest::header::COOKIE,
            format!("oidc_csrf_token={csrf_cookie}"),
        )
        .header("X-CSRF-Token", csrf_cookie)
        .send()
        .await
        .expect("reencrypt maintenance request failed");

    assert_eq!(reencrypt_resp.status(), StatusCode::OK);
    let maintenance_body: Value = reencrypt_resp.json().await.unwrap();
    assert_eq!(maintenance_body["identity_providers_reencrypted"], 1);
    assert_eq!(maintenance_body["realm_signing_keys_reencrypted"], 1);

    let mut conn = app.db_conn().await;
    let idp_row = conn
        .query_one_params(
            "SELECT client_secret FROM identity_providers WHERE id = $1",
            &[&idp_id],
        )
        .await
        .expect("identity provider lookup should succeed")
        .expect("identity provider should exist");
    let stored_secret = idp_row
        .get::<String>(0)
        .expect("client_secret should be readable");
    assert_ne!(stored_secret, "legacy-plaintext-secret");
    assert!(!stored_secret.contains("legacy-plaintext-secret"));

    let key_row = conn
        .query_one_params(
            "SELECT rsa_private_pem, ed25519_private_pem FROM realm_signing_keys WHERE realm_id = $1",
            &[&realm_id],
        )
        .await
        .expect("realm signing key lookup should succeed")
        .expect("realm signing keys should exist");
    let stored_rsa = key_row
        .get::<String>(0)
        .expect("rsa_private_pem should be readable");
    let stored_ed = key_row
        .get::<String>(1)
        .expect("ed25519_private_pem should be readable");
    assert!(!stored_rsa.contains("BEGIN RSA PRIVATE KEY"));
    assert!(!stored_ed.contains("BEGIN PRIVATE KEY"));
    let _ = conn.close().await;
}

#[tokio::test]
async fn test_stats_requires_auth() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(&format!("{}/api/stats", app.url()))
        .send()
        .await
        .expect("stats request failed");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ===================================================================
// Users CRUD
// ===================================================================

#[tokio::test]
async fn test_create_user() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    // Get realm ID
    let realms_resp = admin_client(&app, &token)
        .get(&format!("{}/api/realms?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .expect("realms list failed");
    let realms_body: Value = realms_resp.json().await.unwrap();
    let realm_id = realms_body["items"][0]["id"].as_str().unwrap();

    let resp = admin_client(&app, &token)
        .post(&format!("{}/api/users", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "email": "newuser@example.com",
            "password": "NewUser123!",
            "username": "newuser",
            "given_name": "New",
            "family_name": "User",
        }))
        .send()
        .await
        .expect("create user failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["email"], "newuser@example.com");
    assert_eq!(body["username"].as_str(), Some("newuser"));
    assert_eq!(body["given_name"].as_str(), Some("New"));
    assert!(body["id"].as_str().is_some());
}

#[tokio::test]
async fn test_create_user_invalid_email() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let realms_resp = admin_client(&app, &token)
        .get(&format!("{}/api/realms?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let realms_body: Value = realms_resp.json().await.unwrap();
    let realm_id = realms_body["items"][0]["id"].as_str().unwrap();

    let resp = admin_client(&app, &token)
        .post(&format!("{}/api/users", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "email": "not-an-email",
            "password": "NewUser123!",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_user_weak_password() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let realms_resp = admin_client(&app, &token)
        .get(&format!("{}/api/realms?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let realms_body: Value = realms_resp.json().await.unwrap();
    let realm_id = realms_body["items"][0]["id"].as_str().unwrap();

    let resp = admin_client(&app, &token)
        .post(&format!("{}/api/users", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "email": "weak@example.com",
            "password": "123",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_list_users() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let resp = admin_client(&app, &token)
        .get(&format!("{}/api/users?limit=10", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list users failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["items"].as_array().is_some());
    assert!(body["total"].as_i64().is_some());
    assert!(body["items"].as_array().unwrap().len() >= 1);
}

#[tokio::test]
async fn test_get_user() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    // First list users to get an ID
    let list_resp = admin_client(&app, &token)
        .get(&format!("{}/api/users?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let list_body: Value = list_resp.json().await.unwrap();
    let user_id = list_body["items"][0]["id"].as_str().unwrap();

    let resp = admin_client(&app, &token)
        .get(&format!("{}/api/users/{}", app.url(), user_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"], user_id);
    assert!(body["email"].as_str().is_some());
}

#[tokio::test]
async fn test_get_user_not_found() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let resp = admin_client(&app, &token)
        .get(&format!(
            "{}/api/users/00000000-0000-0000-0000-000000000000",
            app.url()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_user() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    // Create a user first
    let realms_resp = admin_client(&app, &token)
        .get(&format!("{}/api/realms?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let realms_body: Value = realms_resp.json().await.unwrap();
    let realm_id = realms_body["items"][0]["id"].as_str().unwrap();

    let create_resp = admin_client(&app, &token)
        .post(&format!("{}/api/users", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "email": "update-test@example.com",
            "password": "UpdateTest123!",
            "given_name": "Original",
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let user_id = create_body["id"].as_str().unwrap();

    // Update the user
    let resp = admin_client(&app, &token)
        .put(&format!("{}/api/users/{}", app.url(), user_id))
        .bearer_auth(&token)
        .json(&json!({
            "given_name": "Updated",
            "family_name": "Name",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    // Verify the update
    let get_resp = admin_client(&app, &token)
        .get(&format!("{}/api/users/{}", app.url(), user_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let get_body: Value = get_resp.json().await.unwrap();
    assert_eq!(get_body["given_name"].as_str(), Some("Updated"));
    assert_eq!(get_body["family_name"].as_str(), Some("Name"));
}

#[tokio::test]
async fn test_delete_user() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let realms_resp = admin_client(&app, &token)
        .get(&format!("{}/api/realms?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let realms_body: Value = realms_resp.json().await.unwrap();
    let realm_id = realms_body["items"][0]["id"].as_str().unwrap();

    let create_resp = admin_client(&app, &token)
        .post(&format!("{}/api/users", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "email": "delete-test@example.com",
            "password": "DeleteTest123!",
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let user_id = create_body["id"].as_str().unwrap();

    let resp = admin_client(&app, &token)
        .delete(&format!("{}/api/users/{}", app.url(), user_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);

    // Verify user is gone (soft delete)
    let get_resp = admin_client(&app, &token)
        .get(&format!("{}/api/users/{}", app.url(), user_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
}

// ===================================================================
// Clients CRUD
// ===================================================================

#[tokio::test]
async fn test_list_clients() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let resp = admin_client(&app, &token)
        .get(&format!("{}/api/clients?limit=10", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list clients failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["items"].as_array().is_some());
    assert!(body["total"].as_i64().is_some());
}

#[tokio::test]
async fn test_get_client() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let list_resp = admin_client(&app, &token)
        .get(&format!("{}/api/clients?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let list_body: Value = list_resp.json().await.unwrap();
    let client_id = list_body["items"][0]["id"].as_str().unwrap();

    let resp = admin_client(&app, &token)
        .get(&format!("{}/api/clients/{}", app.url(), client_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"], client_id);
    assert!(body["client_id"].as_str().is_some());
}

#[tokio::test]
async fn test_update_client() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let list_resp = admin_client(&app, &token)
        .get(&format!("{}/api/clients?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let list_body: Value = list_resp.json().await.unwrap();
    let client_id = list_body["items"][0]["id"].as_str().unwrap();

    let resp = admin_client(&app, &token)
        .put(&format!("{}/api/clients/{}", app.url(), client_id))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Updated Client Name",
            "enabled": false,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let get_resp = admin_client(&app, &token)
        .get(&format!("{}/api/clients/{}", app.url(), client_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let get_body: Value = get_resp.json().await.unwrap();
    assert_eq!(get_body["name"], "Updated Client Name");
    assert_eq!(get_body["enabled"], false);
}

#[tokio::test]
async fn test_delete_client() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let realms_resp = admin_client(&app, &token)
        .get(&format!("{}/api/realms?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let realms_body: Value = realms_resp.json().await.unwrap();
    let realm_id = realms_body["items"][0]["id"].as_str().unwrap();

    let create_resp = admin_client(&app, &token)
        .post(&format!("{}/api/clients", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "client_id": "delete-test-client",
            "name": "Delete Test Client",
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let client_id = create_body["id"].as_str().unwrap();

    let resp = admin_client(&app, &token)
        .delete(&format!("{}/api/clients/{}", app.url(), client_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);
}

// ===================================================================
// Realms CRUD
// ===================================================================

#[tokio::test]
async fn test_create_realm_encrypts_signing_keys_at_rest() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let resp = admin_client(&app, &token)
        .post(&format!("{}/api/realms", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "name": "encrypted-keys-realm",
            "display_name": "Encrypted Keys Realm",
            "enabled": true,
        }))
        .send()
        .await
        .expect("create realm failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let realm_id = body["id"].as_str().expect("realm id must be present");

    let mut conn = app.db_conn().await;
    let row = conn
        .query_one_params(
            "SELECT rsa_private_pem, ed25519_private_pem FROM realm_signing_keys WHERE realm_id = $1",
            &[&uuid::Uuid::parse_str(realm_id).expect("realm id should parse")],
        )
        .await
        .expect("realm signing keys lookup should succeed")
        .expect("realm signing keys should exist");
    let rsa_private = row
        .get::<String>(0)
        .expect("rsa_private_pem should be readable");
    let ed_private = row
        .get::<String>(1)
        .expect("ed25519_private_pem should be readable");
    assert!(!rsa_private.contains("BEGIN RSA PRIVATE KEY"));
    assert!(!ed_private.contains("BEGIN PRIVATE KEY"));
    let _ = conn.close().await;
}

#[tokio::test]
async fn test_create_realm() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let resp = admin_client(&app, &token)
        .post(&format!("{}/api/realms", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "name": "test-realm-create",
            "display_name": "Test Realm",
            "enabled": true,
        }))
        .send()
        .await
        .expect("create realm failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "test-realm-create");
    assert_eq!(body["display_name"], "Test Realm");
    assert_eq!(body["enabled"], true);
}

#[tokio::test]
async fn test_get_realm() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let list_resp = admin_client(&app, &token)
        .get(&format!("{}/api/realms?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let list_body: Value = list_resp.json().await.unwrap();
    let realm_id = list_body["items"][0]["id"].as_str().unwrap();

    let resp = admin_client(&app, &token)
        .get(&format!("{}/api/realms/{}", app.url(), realm_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"], realm_id);
    assert!(body["name"].as_str().is_some());
}

#[tokio::test]
async fn test_delete_realm() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let create_resp = admin_client(&app, &token)
        .post(&format!("{}/api/realms", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "name": "delete-test-realm",
            "display_name": "Delete Test",
            "enabled": true,
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let realm_id = create_body["id"].as_str().unwrap();

    let resp = admin_client(&app, &token)
        .delete(&format!("{}/api/realms/{}", app.url(), realm_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);
}

// ===================================================================
// Sessions
// ===================================================================

#[tokio::test]
async fn test_list_sessions() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let resp = admin_client(&app, &token)
        .get(&format!("{}/api/sessions?limit=10", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list sessions failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["items"].as_array().is_some());
    assert!(body["total"].as_i64().is_some());
}

#[tokio::test]
async fn test_revoke_session() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    // Login to create a session
    let login_resp = app
        .client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": fixtures::TEST_USER_PASSWORD,
        }))
        .send()
        .await
        .unwrap();
    let _login_body: Value = login_resp.json().await.unwrap();

    // List sessions to find the one we just created
    let list_resp = admin_client(&app, &token)
        .get(&format!("{}/api/sessions?limit=10", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let list_body: Value = list_resp.json().await.unwrap();

    if let Some(session) = list_body["items"].as_array().and_then(|arr| arr.first()) {
        let session_id = session["id"].as_str().unwrap();

        let resp = admin_client(&app, &token)
            .post(&format!("{}/api/sessions/{}/revoke", app.url(), session_id))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["revoked"], true);
    }
}

// ===================================================================
// Audit Events
// ===================================================================

#[tokio::test]
async fn test_list_audit_events() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let resp = admin_client(&app, &token)
        .get(&format!("{}/api/audit/events?limit=10", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list audit events failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["items"].as_array().is_some());
    assert!(body["total"].as_i64().is_some());
}

#[tokio::test]
async fn test_list_audit_events_with_filter() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    // Login creates an audit event
    app.client()
        .post(&format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": fixtures::TEST_USER_PASSWORD,
        }))
        .send()
        .await
        .unwrap();

    let resp = admin_client(&app, &token)
        .get(&format!(
            "{}/api/audit/events?limit=10&event_type=user.login",
            app.url()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["items"].as_array().is_some());
}
