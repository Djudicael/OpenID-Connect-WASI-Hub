//! Admin API endpoint integration tests.
//!
//! Covers: Stats, Users CRUD, Clients CRUD, Realms CRUD, Sessions, Audit Events.

mod policy_tests;
mod rbac_tests;

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

fn admin_client(app: &TestApp, token: &str) -> reqwest::Client {
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
    let login_body: Value = login_resp.json().await.unwrap();

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
