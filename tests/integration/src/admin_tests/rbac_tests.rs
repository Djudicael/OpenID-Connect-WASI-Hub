//! Admin RBAC endpoint integration tests.
//!
//! Covers: Roles CRUD, Groups CRUD, User-Role assignments, User-Group assignments,
//! Group-Role assignments.

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

async fn get_admin_user_id(app: &TestApp, token: &str) -> String {
    let resp = app
        .client()
        .get(&format!("{}/api/users?limit=1", app.url()))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    body["items"][0]["id"].as_str().unwrap().to_string()
}

// ===================================================================
// Roles CRUD
// ===================================================================

#[tokio::test]
async fn test_create_role() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let resp = app
        .client()
        .post(&format!("{}/api/roles", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "admin-role",
            "description": "Full admin access",
            "permissions": ["read", "write", "delete"],
        }))
        .send()
        .await
        .expect("create role failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "admin-role");
    assert!(body["id"].as_str().is_some());
}

#[tokio::test]
async fn test_list_roles() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    // Create a role first
    app.client()
        .post(&format!("{}/api/roles", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "list-test-role",
            "permissions": ["read"],
        }))
        .send()
        .await
        .unwrap();

    let resp = app
        .client()
        .get(&format!("{}/api/roles?realm_id={}", app.url(), realm_id))
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
async fn test_get_role() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let create_resp = app
        .client()
        .post(&format!("{}/api/roles", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "get-test-role",
            "permissions": ["read"],
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let role_id = create_body["id"].as_str().unwrap();

    let resp = app
        .client()
        .get(&format!("{}/api/roles/{}", app.url(), role_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"], role_id);
    assert_eq!(body["name"], "get-test-role");
}

#[tokio::test]
async fn test_update_role() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let create_resp = app
        .client()
        .post(&format!("{}/api/roles", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "update-test-role",
            "permissions": ["read", "write"],
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let role_id = create_body["id"].as_str().unwrap();

    let resp = app
        .client()
        .put(&format!("{}/api/roles/{}", app.url(), role_id))
        .bearer_auth(&token)
        .json(&json!({
            "description": "New description",
            "permissions": ["read", "write", "admin"],
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let get_resp = app
        .client()
        .get(&format!("{}/api/roles/{}", app.url(), role_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let get_body: Value = get_resp.json().await.unwrap();
    assert_eq!(get_body["description"].as_str(), Some("New description"));
}

#[tokio::test]
async fn test_delete_role() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let create_resp = app
        .client()
        .post(&format!("{}/api/roles", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "delete-test-role",
            "permissions": ["read"],
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let role_id = create_body["id"].as_str().unwrap();

    let resp = app
        .client()
        .delete(&format!("{}/api/roles/{}", app.url(), role_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);
}

// ===================================================================
// Groups CRUD
// ===================================================================

#[tokio::test]
async fn test_create_group() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let resp = app
        .client()
        .post(&format!("{}/api/groups", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "admin-group",
            "description": "Admin group",
        }))
        .send()
        .await
        .expect("create group failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "admin-group");
    assert!(body["id"].as_str().is_some());
}

#[tokio::test]
async fn test_list_groups() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    app.client()
        .post(&format!("{}/api/groups", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "list-test-group",
        }))
        .send()
        .await
        .unwrap();

    let resp = app
        .client()
        .get(&format!("{}/api/groups?realm_id={}", app.url(), realm_id))
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
async fn test_get_group() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let create_resp = app
        .client()
        .post(&format!("{}/api/groups", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "get-test-group",
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let group_id = create_body["id"].as_str().unwrap();

    let resp = app
        .client()
        .get(&format!("{}/api/groups/{}", app.url(), group_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"], group_id);
}

#[tokio::test]
async fn test_update_group() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let create_resp = app
        .client()
        .post(&format!("{}/api/groups", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "update-test-group",
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let group_id = create_body["id"].as_str().unwrap();

    let resp = app
        .client()
        .put(&format!("{}/api/groups/{}", app.url(), group_id))
        .bearer_auth(&token)
        .json(&json!({
            "description": "New group description",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let get_resp = app
        .client()
        .get(&format!("{}/api/groups/{}", app.url(), group_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let get_body: Value = get_resp.json().await.unwrap();
    assert_eq!(get_body["description"].as_str(), Some("New group description"));
}

#[tokio::test]
async fn test_delete_group() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let create_resp = app
        .client()
        .post(&format!("{}/api/groups", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "delete-test-group",
        }))
        .send()
        .await
        .unwrap();
    let create_body: Value = create_resp.json().await.unwrap();
    let group_id = create_body["id"].as_str().unwrap();

    let resp = app
        .client()
        .delete(&format!("{}/api/groups/{}", app.url(), group_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);
}

// ===================================================================
// User-Role Assignments
// ===================================================================

#[tokio::test]
async fn test_assign_role_to_user() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;
    let user_id = get_admin_user_id(&app, &token).await;

    let role_resp = app
        .client()
        .post(&format!("{}/api/roles", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "user-role-test",
            "permissions": ["users:read"],
        }))
        .send()
        .await
        .unwrap();
    let role_body: Value = role_resp.json().await.unwrap();
    let role_id = role_body["id"].as_str().unwrap();

    let resp = app
        .client()
        .post(&format!("{}/api/users/{}/roles", app.url(), user_id))
        .bearer_auth(&token)
        .json(&json!({
            "role_id": role_id,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_list_user_roles() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;
    let user_id = get_admin_user_id(&app, &token).await;

    let role_resp = app
        .client()
        .post(&format!("{}/api/roles", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "list-user-role",
            "permissions": ["users:read"],
        }))
        .send()
        .await
        .unwrap();
    let role_body: Value = role_resp.json().await.unwrap();
    let role_id = role_body["id"].as_str().unwrap();

    // Assign role
    app.client()
        .post(&format!("{}/api/users/{}/roles", app.url(), user_id))
        .bearer_auth(&token)
        .json(&json!({"role_id": role_id}))
        .send()
        .await
        .unwrap();

    let resp = app
        .client()
        .get(&format!("{}/api/users/{}/roles", app.url(), user_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["items"].as_array().is_some());
    assert!(body["items"].as_array().unwrap().len() >= 1);
}

#[tokio::test]
async fn test_unassign_role_from_user() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;
    let user_id = get_admin_user_id(&app, &token).await;

    let role_resp = app
        .client()
        .post(&format!("{}/api/roles", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "unassign-role-test",
            "permissions": ["users:read"],
        }))
        .send()
        .await
        .unwrap();
    let role_body: Value = role_resp.json().await.unwrap();
    let role_id = role_body["id"].as_str().unwrap();

    // Assign role
    app.client()
        .post(&format!("{}/api/users/{}/roles", app.url(), user_id))
        .bearer_auth(&token)
        .json(&json!({"role_id": role_id}))
        .send()
        .await
        .unwrap();

    let resp = app
        .client()
        .delete(&format!("{}/api/users/{}/roles/{}", app.url(), user_id, role_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

// ===================================================================
// User-Group Assignments
// ===================================================================

#[tokio::test]
async fn test_assign_group_to_user() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;
    let user_id = get_admin_user_id(&app, &token).await;

    let group_resp = app
        .client()
        .post(&format!("{}/api/groups", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "user-group-test",
        }))
        .send()
        .await
        .unwrap();
    let group_body: Value = group_resp.json().await.unwrap();
    let group_id = group_body["id"].as_str().unwrap();

    let resp = app
        .client()
        .post(&format!("{}/api/users/{}/groups", app.url(), user_id))
        .bearer_auth(&token)
        .json(&json!({
            "group_id": group_id,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_list_user_groups() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;
    let user_id = get_admin_user_id(&app, &token).await;

    let group_resp = app
        .client()
        .post(&format!("{}/api/groups", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "list-user-group",
        }))
        .send()
        .await
        .unwrap();
    let group_body: Value = group_resp.json().await.unwrap();
    let group_id = group_body["id"].as_str().unwrap();

    app.client()
        .post(&format!("{}/api/users/{}/groups", app.url(), user_id))
        .bearer_auth(&token)
        .json(&json!({"group_id": group_id}))
        .send()
        .await
        .unwrap();

    let resp = app
        .client()
        .get(&format!("{}/api/users/{}/groups", app.url(), user_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["items"].as_array().is_some());
    assert!(body["items"].as_array().unwrap().len() >= 1);
}

#[tokio::test]
async fn test_unassign_group_from_user() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;
    let user_id = get_admin_user_id(&app, &token).await;

    let group_resp = app
        .client()
        .post(&format!("{}/api/groups", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "unassign-group-test",
        }))
        .send()
        .await
        .unwrap();
    let group_body: Value = group_resp.json().await.unwrap();
    let group_id = group_body["id"].as_str().unwrap();

    app.client()
        .post(&format!("{}/api/users/{}/groups", app.url(), user_id))
        .bearer_auth(&token)
        .json(&json!({"group_id": group_id}))
        .send()
        .await
        .unwrap();

    let resp = app
        .client()
        .delete(&format!("{}/api/users/{}/groups/{}", app.url(), user_id, group_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

// ===================================================================
// Group-Role Assignments
// ===================================================================

#[tokio::test]
async fn test_assign_role_to_group() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let group_resp = app
        .client()
        .post(&format!("{}/api/groups", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "group-role-test",
        }))
        .send()
        .await
        .unwrap();
    let group_body: Value = group_resp.json().await.unwrap();
    let group_id = group_body["id"].as_str().unwrap();

    let role_resp = app
        .client()
        .post(&format!("{}/api/roles", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "group-role-assign",
            "permissions": ["groups:read"],
        }))
        .send()
        .await
        .unwrap();
    let role_body: Value = role_resp.json().await.unwrap();
    let role_id = role_body["id"].as_str().unwrap();

    let resp = app
        .client()
        .post(&format!("{}/api/groups/{}/roles", app.url(), group_id))
        .bearer_auth(&token)
        .json(&json!({
            "role_id": role_id,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_list_group_roles() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let group_resp = app
        .client()
        .post(&format!("{}/api/groups", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "list-group-roles",
        }))
        .send()
        .await
        .unwrap();
    let group_body: Value = group_resp.json().await.unwrap();
    let group_id = group_body["id"].as_str().unwrap();

    let role_resp = app
        .client()
        .post(&format!("{}/api/roles", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "list-group-role",
            "permissions": ["groups:read"],
        }))
        .send()
        .await
        .unwrap();
    let role_body: Value = role_resp.json().await.unwrap();
    let role_id = role_body["id"].as_str().unwrap();

    app.client()
        .post(&format!("{}/api/groups/{}/roles", app.url(), group_id))
        .bearer_auth(&token)
        .json(&json!({"role_id": role_id}))
        .send()
        .await
        .unwrap();

    let resp = app
        .client()
        .get(&format!("{}/api/groups/{}/roles", app.url(), group_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["items"].as_array().is_some());
    assert!(body["items"].as_array().unwrap().len() >= 1);
}

#[tokio::test]
async fn test_unassign_role_from_group() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm_id = get_master_realm_id(&app, &token).await;

    let group_resp = app
        .client()
        .post(&format!("{}/api/groups", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "unassign-group-role",
        }))
        .send()
        .await
        .unwrap();
    let group_body: Value = group_resp.json().await.unwrap();
    let group_id = group_body["id"].as_str().unwrap();

    let role_resp = app
        .client()
        .post(&format!("{}/api/roles", app.url()))
        .bearer_auth(&token)
        .json(&json!({
            "realm_id": realm_id,
            "name": "unassign-from-group",
            "permissions": ["groups:read"],
        }))
        .send()
        .await
        .unwrap();
    let role_body: Value = role_resp.json().await.unwrap();
    let role_id = role_body["id"].as_str().unwrap();

    app.client()
        .post(&format!("{}/api/groups/{}/roles", app.url(), group_id))
        .bearer_auth(&token)
        .json(&json!({"role_id": role_id}))
        .send()
        .await
        .unwrap();

    let resp = app
        .client()
        .delete(&format!("{}/api/groups/{}/roles/{}", app.url(), group_id, role_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}
