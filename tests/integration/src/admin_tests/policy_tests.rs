//! Admin Identity Provider and Password Policy endpoint tests.

use reqwest::StatusCode;
use serde_json::{Value, json};

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

async fn get_master_realm_id(app: &TestApp, token: &str) -> String {
    let resp = app
        .client()
        .get(&format!("{}/api/realms?limit=1", app.url()))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    body["items"][0]["id"].as_str().unwrap().to_string()
}

// ===================================================================
// Password Policy
// ===================================================================

#[tokio::test]
async fn test_get_password_policy() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let resp = app
        .client()
        .get(&format!("{}/api/realms/{}/password-policy", app.url(), realm_id))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get password policy failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["min_length"].as_i64().is_some());
}

#[tokio::test]
async fn test_update_password_policy() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let resp = app
        .client()
        .put(&format!("{}/api/realms/{}/password-policy", app.url(), realm_id))
        .bearer_auth(&token)
        .json(&json!({
            "min_length": 12,
            "require_uppercase": true,
            "require_lowercase": true,
            "require_digit": true,
            "require_special": true,
            "max_age_days": 90,
            "history_size": 5,
        }))
        .send()
        .await
        .expect("update password policy failed");

    assert_eq!(resp.status(), StatusCode::OK);

    // Verify the update
    let get_resp = app
        .client()
        .get(&format!("{}/api/realms/{}/password-policy", app.url(), realm_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let get_body: Value = get_resp.json().await.unwrap();
    assert_eq!(get_body["min_length"], 12);
    assert_eq!(get_body["require_uppercase"], true);
    assert_eq!(get_body["require_lowercase"], true);
    assert_eq!(get_body["require_digit"], true);
    assert_eq!(get_body["require_special"], true);
}

// ===================================================================
// Identity Providers
// ===================================================================

#[tokio::test]
async fn test_create_identity_provider() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let resp = app
        .client()
        .post(&format!("{}/api/identity-providers", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "alias": "google-test",
            "display_name": "Google",
            "provider_type": "oidc",
            "enabled": true,
            "issuer": "https://accounts.google.com",
            "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "scopes": ["openid", "email", "profile"],
        }))
        .send()
        .await
        .expect("create identity provider failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["alias"], "google-test");
    assert_eq!(body["provider_type"], "oidc");
    assert_eq!(body["enabled"], true);
    assert!(body["id"].as_str().is_some());
}

#[tokio::test]
async fn test_list_identity_providers() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    // Create an IdP first
    app.client()
        .post(&format!("{}/api/identity-providers", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "alias": "list-test-idp",
            "display_name": "List Test",
            "provider_type": "oidc",
            "enabled": true,
            "issuer": "https://example.com",
            "authorization_url": "https://example.com/auth",
            "token_url": "https://example.com/token",
            "userinfo_url": "https://example.com/userinfo",
            "client_id": "test",
            "client_secret": "test",
            "scopes": ["openid"],
        }))
        .send()
        .await
        .unwrap();

    let resp = app
        .client()
        .get(&format!("{}/api/identity-providers?realm_id={}", app.url(), realm_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["items"].as_array().is_some());
    assert!(body["total"].as_i64().is_some());
}

#[tokio::test]
async fn test_get_identity_provider() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let create_resp = app
        .client()
        .post(&format!("{}/api/identity-providers", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "alias": "get-test-idp",
            "display_name": "Get Test",
            "provider_type": "oidc",
            "enabled": true,
            "issuer": "https://example.com",
            "authorization_url": "https://example.com/auth",
            "token_url": "https://example.com/token",
            "userinfo_url": "https://example.com/userinfo",
            "client_id": "test",
            "client_secret": "test",
            "scopes": ["openid"],
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let idp_id = create_body["id"].as_str().unwrap();

    let resp = app
        .client()
        .get(&format!("{}/api/identity-providers/{}", app.url(), idp_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"], idp_id);
    assert_eq!(body["alias"], "get-test-idp");
}

#[tokio::test]
async fn test_update_identity_provider() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let create_resp = app
        .client()
        .post(&format!("{}/api/identity-providers", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "alias": "update-test-idp",
            "display_name": "Original",
            "provider_type": "oidc",
            "enabled": true,
            "issuer": "https://example.com",
            "authorization_url": "https://example.com/auth",
            "token_url": "https://example.com/token",
            "userinfo_url": "https://example.com/userinfo",
            "client_id": "test",
            "client_secret": "test",
            "scopes": ["openid"],
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let idp_id = create_body["id"].as_str().unwrap();

    let resp = app
        .client()
        .put(&format!("{}/api/identity-providers/{}", app.url(), idp_id))
        .bearer_auth(&token)
        .json(&json!({
            "display_name": "Updated IdP",
            "enabled": false,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let get_resp = app
        .client()
        .get(&format!("{}/api/identity-providers/{}", app.url(), idp_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let get_body: Value = get_resp.json().await.unwrap();
    assert_eq!(get_body["display_name"], "Updated IdP");
    assert_eq!(get_body["enabled"], false);
}

#[tokio::test]
async fn test_delete_identity_provider() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let create_resp = app
        .client()
        .post(&format!("{}/api/identity-providers", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "alias": "delete-test-idp",
            "display_name": "Delete Test",
            "provider_type": "oidc",
            "enabled": true,
            "issuer": "https://example.com",
            "authorization_url": "https://example.com/auth",
            "token_url": "https://example.com/token",
            "userinfo_url": "https://example.com/userinfo",
            "client_id": "test",
            "client_secret": "test",
            "scopes": ["openid"],
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let idp_id = create_body["id"].as_str().unwrap();

    let resp = app
        .client()
        .delete(&format!("{}/api/identity-providers/{}", app.url(), idp_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);
}

// ===================================================================
// User Impersonation
// ===================================================================

#[tokio::test]
async fn test_impersonate_user() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    // Get the admin user ID
    let list_resp = app
        .client()
        .get(&format!("{}/api/users?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let list_body: Value = list_resp.json().await.unwrap();
    let user_id = list_body["items"][0]["id"].as_str().unwrap();

    let resp = app
        .client()
        .post(&format!("{}/api/users/{}/impersonate", app.url(), user_id))
        .bearer_auth(&token)
        .send()
        .await
        .expect("impersonate request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["access_token"].as_str().is_some());
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["impersonated_user_id"].as_str().is_some());
}

// ===================================================================
// Maintenance Cleanup
// ===================================================================

#[tokio::test]
async fn test_cleanup_expired() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    let resp = app
        .client()
        .post(&format!("{}/api/maintenance/cleanup", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .expect("cleanup request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["sessions_deleted"].as_i64().is_some());
    assert!(body["auth_codes_deleted"].as_i64().is_some());
}

// ===================================================================
// Account Recovery (Admin-initiated)
// ===================================================================

#[tokio::test]
async fn test_initiate_account_recovery() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    // Get the admin user ID
    let list_resp = app
        .client()
        .get(&format!("{}/api/users?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let list_body: Value = list_resp.json().await.unwrap();
    let user_id = list_body["items"][0]["id"].as_str().unwrap();

    let resp = app
        .client()
        .post(&format!("{}/api/users/{}/account-recovery", app.url(), user_id))
        .bearer_auth(&token)
        .send()
        .await
        .expect("account recovery request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["recovery_token"].as_str().is_some());
}
