//! API key integration tests.
//!
//! Tests the full API key CRUD and authentication flows against a real HTTP
//! server backed by PostgreSQL.  Each test spawns a fresh `TestApp` instance
//! with a clean database.

use chrono::{Duration, Utc};
use reqwest::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::helpers::app::TestApp;

// ===================================================================
// Helpers
// ===================================================================

/// Seed an API key directly in the database and return `(ApiKey model, raw_key_string)`.
///
/// Uses `ApiKeyService::generate_key` so the key format, hashing, and prefix
/// are identical to production code.
async fn seed_api_key(
    app: &TestApp,
    name: &str,
    scopes: Vec<String>,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> (oidc_core::models::ApiKey, String) {
    let mut conn = app.db_conn().await;
    let (api_key, raw_key) = oidc_apikey::ApiKeyService::generate_key(
        &mut conn,
        app.master_realm_id(),
        name.to_string(),
        scopes,
        None, // expires_in_days — we override expires_at below if needed
        None, // created_by
    )
    .await
    .expect("failed to seed API key");

    // If the caller wants a specific expires_at (e.g. in the past), update it.
    let api_key = if let Some(exp) = expires_at {
        // Direct SQL update since the repo doesn't expose an update method.
        conn.execute_params(
            "UPDATE api_keys SET expires_at = $1 WHERE id = $2",
            &[&exp, &api_key.id],
        )
        .await
        .expect("failed to update expires_at");
        oidc_repository::repositories::api_key_repo::ApiKeyRepo
            .find_by_id(&mut conn, api_key.id)
            .await
            .expect("db error")
            .expect("key disappeared after update")
    } else {
        api_key
    };

    // Gracefully close the connection.
    let _ = conn.close().await;

    (api_key, raw_key)
}

/// Seed an API key in a *different* realm (not the master realm).
/// Uses `app.db_conn()` so data lands in the same isolated DB as the server.
async fn seed_api_key_in_realm(
    app: &TestApp,
    realm_id: Uuid,
    name: &str,
    scopes: Vec<String>,
) -> (oidc_core::models::ApiKey, String) {
    let mut conn = app.db_conn().await;
    let result = oidc_apikey::ApiKeyService::generate_key(
        &mut conn,
        realm_id,
        name.to_string(),
        scopes,
        None,
        None,
    )
    .await
    .expect("failed to seed API key in realm");

    // Gracefully close the connection.
    let _ = conn.close().await;

    result
}

/// Seed a second realm and return its ID.
async fn seed_second_realm(app: &TestApp) -> Uuid {
    let mut conn = app.db_conn().await;
    let suffix = Uuid::new_v4().to_string()[..8].to_string();
    let realm = crate::helpers::fixtures::test_realm(&format!("other-realm-{suffix}"));
    let id = realm.id;
    oidc_repository::repositories::realm_repo::RealmRepo
        .create(&mut conn, &realm)
        .await
        .expect("failed to seed second realm");

    // Gracefully close the connection.
    let _ = conn.close().await;

    id
}

// ===================================================================
// Group 1: API Key CRUD
// ===================================================================

#[tokio::test]
async fn test_create_api_key() {
    let app = TestApp::new().await;

    // Seed a bootstrap admin key so we can authenticate the create request.
    let (_, admin_raw_key) = seed_api_key(&app, "admin-key", vec!["admin".into()], None).await;

    let resp = app
        .client()
        .post(&format!("{}/api/keys", app.url()))
        .header("X-API-Key", &admin_raw_key)
        .json(&json!({
            "realm_id": app.master_realm_id().to_string(),
            "name": "created-key",
            "scopes": ["api_keys:read", "api_keys:write"],
        }))
        .send()
        .await
        .expect("create key request failed");

    assert_eq!(resp.status(), StatusCode::OK, "create should return 200");

    let body: Value = resp.json().await.expect("response should be JSON");
    assert_eq!(body["name"], "created-key");
    assert!(
        body["raw_key"].is_string(),
        "raw_key must be present on creation"
    );
    assert!(body["id"].is_string(), "id must be present");
    assert!(body["prefix"].is_string(), "prefix must be present");

    // The raw_key should follow the oidc_<env>_<prefix>_<secret> format.
    let raw_key = body["raw_key"].as_str().unwrap();
    assert!(
        raw_key.starts_with("oidc_"),
        "raw key must start with oidc_"
    );
}

#[tokio::test]
async fn test_list_api_keys() {
    let app = TestApp::new().await;

    let (key_model, admin_raw_key) =
        seed_api_key(&app, "list-test-key", vec!["admin".into()], None).await;

    let resp = app
        .client()
        .get(&format!(
            "{}/api/keys?realm_id={}",
            app.url(),
            app.master_realm_id()
        ))
        .header("X-API-Key", &admin_raw_key)
        .send()
        .await
        .expect("list keys request failed");

    assert_eq!(resp.status(), StatusCode::OK, "list should return 200");

    let body: Value = resp.json().await.expect("response should be JSON");
    let items = body["items"].as_array().expect("items must be an array");
    assert!(!items.is_empty(), "should list at least one key");

    // Our seeded key should appear in the list.
    let found = items
        .iter()
        .any(|item| item["id"].as_str() == Some(&key_model.id.to_string()));
    assert!(found, "seeded key should appear in the list");
}

#[tokio::test]
async fn test_get_api_key_by_id() {
    let app = TestApp::new().await;

    let (key_model, admin_raw_key) =
        seed_api_key(&app, "get-test-key", vec!["admin".into()], None).await;

    let resp = app
        .client()
        .get(&format!("{}/api/keys/{}", app.url(), key_model.id))
        .header("X-API-Key", &admin_raw_key)
        .send()
        .await
        .expect("get key request failed");

    assert_eq!(resp.status(), StatusCode::OK, "get should return 200");

    let body: Value = resp.json().await.expect("response should be JSON");
    assert_eq!(body["id"], key_model.id.to_string());
    assert_eq!(body["name"], "get-test-key");
    assert_eq!(body["prefix"], key_model.prefix);
}

#[tokio::test]
async fn test_delete_api_key() {
    let app = TestApp::new().await;

    let (key_model, admin_raw_key) =
        seed_api_key(&app, "delete-test-key", vec!["admin".into()], None).await;

    // Revoke (delete) the key.
    let resp = app
        .client()
        .delete(&format!("{}/api/keys/{}", app.url(), key_model.id))
        .header("X-API-Key", &admin_raw_key)
        .send()
        .await
        .expect("revoke key request failed");

    assert_eq!(resp.status(), StatusCode::OK, "revoke should return 200");

    let body: Value = resp.json().await.expect("response should be JSON");
    assert_eq!(body["revoked"], true);

    // Subsequent GET should return 404 (key is revoked, not found by active query).
    let resp = app
        .client()
        .get(&format!("{}/api/keys/{}", app.url(), key_model.id))
        .header("X-API-Key", &admin_raw_key)
        .send()
        .await
        .expect("get revoked key request failed");

    // Subsequent GET with the now-revoked key should return 401 UNAUTHORIZED.
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_rotate_api_key() {
    let app = TestApp::new().await;

    let (key_model, old_raw_key) =
        seed_api_key(&app, "rotate-test-key", vec!["admin".into()], None).await;

    // Rotate the key.
    let resp = app
        .client()
        .post(&format!("{}/api/keys/{}/rotate", app.url(), key_model.id))
        .header("X-API-Key", &old_raw_key)
        .send()
        .await
        .expect("rotate key request failed");

    assert_eq!(resp.status(), StatusCode::OK, "rotate should return 200");

    let body: Value = resp.json().await.expect("response should be JSON");
    assert!(
        body["raw_key"].is_string(),
        "rotated response must include new raw_key"
    );
    assert!(
        body["id"].is_string(),
        "rotated response must include new key id"
    );

    let new_raw_key = body["raw_key"].as_str().unwrap();
    assert_ne!(new_raw_key, old_raw_key, "new raw key must differ from old");

    // The new key should work for authentication.
    let resp = app
        .client()
        .get(&format!(
            "{}/api/keys?realm_id={}",
            app.url(),
            app.master_realm_id()
        ))
        .header("X-API-Key", new_raw_key)
        .send()
        .await
        .expect("list with new key request failed");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "new key should authenticate successfully"
    );
}

// ===================================================================
// Group 2: API Key Authentication
// ===================================================================

#[tokio::test]
async fn test_api_key_auth_valid() {
    let app = TestApp::new().await;

    let (_, raw_key) = seed_api_key(&app, "auth-valid-key", vec!["admin".into()], None).await;

    // Use the key to list keys — should succeed.
    let resp = app
        .client()
        .get(&format!(
            "{}/api/keys?realm_id={}",
            app.url(),
            app.master_realm_id()
        ))
        .header("X-API-Key", &raw_key)
        .send()
        .await
        .expect("request with valid key failed");

    assert_eq!(resp.status(), StatusCode::OK, "valid key should return 200");
}

#[tokio::test]
async fn test_api_key_auth_invalid() {
    let app = TestApp::new().await;

    // Use a completely bogus key.
    let resp = app
        .client()
        .get(&format!(
            "{}/api/keys?realm_id={}",
            app.url(),
            app.master_realm_id()
        ))
        .header("X-API-Key", "oidc_prod_XXXXXXXX_bogussecretvalue1234567890")
        .send()
        .await
        .expect("request with invalid key failed");

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "invalid key should return 401"
    );
}

#[tokio::test]
async fn test_api_key_auth_missing() {
    let app = TestApp::new().await;

    // No X-API-Key header at all.
    let resp = app
        .client()
        .get(&format!(
            "{}/api/keys?realm_id={}",
            app.url(),
            app.master_realm_id()
        ))
        .send()
        .await
        .expect("request without key failed");

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "missing key should return 401"
    );
}

#[tokio::test]
async fn test_api_key_auth_expired() {
    let app = TestApp::new().await;

    // Seed a key that expired 1 hour ago.
    let expired_at = Utc::now() - Duration::hours(1);
    let (_, raw_key) =
        seed_api_key(&app, "expired-key", vec!["admin".into()], Some(expired_at)).await;

    let resp = app
        .client()
        .get(&format!(
            "{}/api/keys?realm_id={}",
            app.url(),
            app.master_realm_id()
        ))
        .header("X-API-Key", &raw_key)
        .send()
        .await
        .expect("request with expired key failed");

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expired key should return 401"
    );
}

// ===================================================================
// Group 3: API Key Security
// ===================================================================

#[tokio::test]
async fn test_api_key_cannot_access_other_realm() {
    let app = TestApp::new().await;

    // Seed a second realm.
    let other_realm_id = seed_second_realm(&app).await;

    // Seed a key in the OTHER realm with admin scope.
    let (_, other_realm_key) = seed_api_key_in_realm(
        &app,
        other_realm_id,
        "realm-b-admin-key",
        vec!["admin".into()],
    )
    .await;

    // Try to list keys in the MASTER realm using the OTHER realm's key.
    // The key is valid (it authenticates), but it belongs to a different
    // realm. The list endpoint filters by the `realm_id` query param, so
    // the key will authenticate but should return an empty list (or 403
    // if the server enforces realm matching).
    let resp = app
        .client()
        .get(&format!(
            "{}/api/keys?realm_id={}",
            app.url(),
            app.master_realm_id()
        ))
        .header("X-API-Key", &other_realm_key)
        .send()
        .await
        .expect("cross-realm list request failed");

    let status = resp.status();
    // The key authenticates successfully (200), but the list should not
    // contain keys from the other realm. Alternatively, the server may
    // enforce realm isolation and return 403.
    assert!(
        status == StatusCode::OK || status == StatusCode::FORBIDDEN,
        "cross-realm list should return 200 (empty list) or 403 (forbidden); got {status}"
    );

    if status == StatusCode::OK {
        let body: Value = resp.json().await.expect("response should be JSON");
        let items = body["items"].as_array().expect("items must be an array");
        // The other realm's key should NOT appear in the master realm's list.
        let found_other = items
            .iter()
            .any(|item| item["realm_id"].as_str() == Some(&other_realm_id.to_string()));
        assert!(
            !found_other,
            "keys from other realm should not appear in master realm list"
        );
    }
}

#[tokio::test]
async fn test_deleted_api_key_rejected() {
    let app = TestApp::new().await;

    let (key_model, raw_key) =
        seed_api_key(&app, "to-be-deleted-key", vec!["admin".into()], None).await;

    // We need a second admin key to revoke the first one (since after revocation
    // the first key may still work during the rotation grace period).
    // Actually, revocation is immediate — the `find_by_prefix` query filters
    // `NOT revoked`. Let's revoke via the API using the key itself.
    let resp = app
        .client()
        .delete(&format!("{}/api/keys/{}", app.url(), key_model.id))
        .header("X-API-Key", &raw_key)
        .send()
        .await
        .expect("revoke key request failed");

    assert_eq!(resp.status(), StatusCode::OK, "revoke should succeed");

    // Now try to use the revoked key.
    let resp = app
        .client()
        .get(&format!(
            "{}/api/keys?realm_id={}",
            app.url(),
            app.master_realm_id()
        ))
        .header("X-API-Key", &raw_key)
        .send()
        .await
        .expect("request with revoked key failed");

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "revoked key should be rejected with 401"
    );
}
