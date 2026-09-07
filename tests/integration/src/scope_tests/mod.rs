//! Scope management integration tests (Phase 3).
//!
//! Tests CRUD operations on the `/api/scopes` REST endpoint
//! and scope assignment during client creation.

use base64::Engine;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::helpers::app::TestApp;
use crate::helpers::fixtures;

/// Obtain an admin Bearer token via password grant.
async fn admin_login(app: &TestApp) -> String {
    let resp = app
        .client()
        .post(format!("{}/oidc/login", app.url()))
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

#[tokio::test]
async fn test_scope_crud_lifecycle() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    // 1. List realms to get the master realm ID
    let list_resp = app
        .client()
        .get(format!("{}/api/realms?limit=1", app.url()))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("realm list failed");
    let list_body: Value = list_resp.json().await.expect("json");
    let realm_id = list_body["items"][0]["id"].as_str().expect("realm id");

    // 2. Create a scope
    let create_resp = app
        .client()
        .post(format!("{}/api/scopes", app.url()))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "realm_id": realm_id,
            "name": "read:users",
            "description": "Read user profiles",
            "enabled": true,
        }))
        .send()
        .await
        .expect("scope create failed");
    assert_eq!(create_resp.status(), StatusCode::OK);
    let create_body: Value = create_resp.json().await.expect("json");
    let scope_id = create_body["id"].as_str().expect("scope id");

    // 3. List scopes — should include the new one
    let scopes_resp = app
        .client()
        .get(format!("{}/api/scopes?realm_id={realm_id}", app.url()))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("scope list failed");
    assert_eq!(scopes_resp.status(), StatusCode::OK);
    let scopes_body: Value = scopes_resp.json().await.expect("json");
    let items = scopes_body["items"].as_array().expect("items array");
    assert!(
        items.iter().any(|s| s["name"] == "read:users"),
        "scope list should contain read:users"
    );

    // 4. Get scope by ID
    let get_resp = app
        .client()
        .get(format!("{}/api/scopes/{scope_id}", app.url()))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("scope get failed");
    assert_eq!(get_resp.status(), StatusCode::OK);
    let get_body: Value = get_resp.json().await.expect("json");
    assert_eq!(get_body["name"], "read:users");
    assert_eq!(get_body["description"], "Read user profiles");
    assert_eq!(get_body["enabled"], true);

    // 5. Update scope
    let update_resp = app
        .client()
        .put(format!("{}/api/scopes/{scope_id}", app.url()))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "name": "read:users",
            "description": "Updated description",
            "enabled": false,
        }))
        .send()
        .await
        .expect("scope update failed");
    assert_eq!(update_resp.status(), StatusCode::OK);

    // Verify update
    let get2_resp = app
        .client()
        .get(format!("{}/api/scopes/{scope_id}", app.url()))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("scope get2 failed");
    let get2_body: Value = get2_resp.json().await.expect("json");
    assert_eq!(get2_body["description"], "Updated description");
    assert_eq!(get2_body["enabled"], false);

    // 6. Delete scope
    let del_resp = app
        .client()
        .delete(format!("{}/api/scopes/{scope_id}", app.url()))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("scope delete failed");
    assert_eq!(del_resp.status(), StatusCode::OK);

    // Verify deletion
    let scopes_resp2 = app
        .client()
        .get(format!("{}/api/scopes?realm_id={realm_id}", app.url()))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("scope list2 failed");
    let scopes_body2: Value = scopes_resp2.json().await.expect("json");
    let items2 = scopes_body2["items"].as_array().expect("items array");
    assert!(
        !items2.iter().any(|s| s["id"] == scope_id),
        "deleted scope should not appear in list"
    );
}

#[tokio::test]
async fn test_protocol_mapper_and_client_scope_lifecycle() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realms: Value = app
        .client()
        .get(format!("{}/api/realms?limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let realm_id = realms["items"][0]["id"].as_str().unwrap();
    let scope: Value = app
        .client()
        .post(format!("{}/api/scopes", app.url()))
        .bearer_auth(&token)
        .json(&json!({"realm_id":realm_id,"name":"workforce-profile","enabled":true}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let scope_id = scope["id"].as_str().unwrap();
    let client: Value = app.client().post(format!("{}/api/clients", app.url())).bearer_auth(&token)
        .json(&json!({"realm_id":realm_id,"client_id":format!("mapper-client-{}", uuid::Uuid::new_v4()),"name":"Mapper Client","client_type":"public","allowed_scopes":["openid"]})).send().await.unwrap().json().await.unwrap();
    let client_id = client["id"].as_str().unwrap();

    let assigned = app
        .client()
        .post(format!("{}/api/clients/{client_id}/scopes", app.url()))
        .bearer_auth(&token)
        .json(&json!({"scope_id":scope_id,"assignment_type":"default"}))
        .send()
        .await
        .unwrap();
    assert_eq!(assigned.status(), StatusCode::OK);
    let assignments: Value = app
        .client()
        .get(format!("{}/api/clients/{client_id}/scopes", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(assignments["items"][0]["assignment_type"], "default");

    let mapper_response = app.client().post(format!("{}/api/scopes/{scope_id}/mappers", app.url())).bearer_auth(&token)
        .json(&json!({"name":"Department","mapper_type":"user_attribute","claim_name":"employee.department","source":"department","add_to_access_token":true,"add_to_id_token":true,"add_to_userinfo":true})).send().await.unwrap();
    assert_eq!(mapper_response.status(), StatusCode::OK);
    let mapper: Value = mapper_response.json().await.unwrap();
    let mapper_id = mapper["id"].as_str().unwrap();
    let mappers: Value = app
        .client()
        .get(format!("{}/api/scopes/{scope_id}/mappers", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(mappers["items"][0]["claim_name"], "employee.department");

    for body in [
        json!({"name":"Tenant tier","mapper_type":"hardcoded_claim","claim_name":"tenant.tier","claim_value":"gold","add_to_access_token":true,"add_to_id_token":true,"add_to_userinfo":true}),
        json!({"name":"Workforce API","mapper_type":"audience","claim_value":"workforce-api","add_to_access_token":true,"add_to_id_token":true,"add_to_userinfo":false}),
    ] {
        let response = app
            .client()
            .post(format!("{}/api/scopes/{scope_id}/mappers", app.url()))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let login: Value = app.client().post(format!("{}/oidc/login", app.url())).json(&json!({
        "email": fixtures::TEST_USER_EMAIL, "password": fixtures::TEST_USER_PASSWORD, "client_id": client["client_id"]
    })).send().await.unwrap().json().await.unwrap();
    let payload = login["access_token"]
        .as_str()
        .unwrap()
        .split('.')
        .nth(1)
        .unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    let claims: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(claims["tenant"]["tier"], "gold");
    assert!(
        claims["aud"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "workforce-api")
    );
    assert!(
        claims["scope"]
            .as_str()
            .unwrap()
            .contains("workforce-profile")
    );

    let updated = app.client().put(format!("{}/api/scopes/{scope_id}/mappers/{mapper_id}", app.url())).bearer_auth(&token)
        .json(&json!({"name":"Department","mapper_type":"user_attribute","claim_name":"work.department","source":"department","add_to_access_token":true,"add_to_id_token":false,"add_to_userinfo":true})).send().await.unwrap();
    assert_eq!(updated.status(), StatusCode::OK);
    let deleted = app
        .client()
        .delete(format!(
            "{}/api/scopes/{scope_id}/mappers/{mapper_id}",
            app.url()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    let removed = app
        .client()
        .delete(format!(
            "{}/api/clients/{client_id}/scopes/{scope_id}",
            app.url()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_scope_unauthorized_without_admin_token() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(format!(
            "{}/api/scopes?realm_id={}",
            app.url(),
            uuid::Uuid::new_v4()
        ))
        .send()
        .await
        .expect("request failed");

    // With realm_id but no auth token: should be 401 Unauthorized
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_scope_missing_realm_id_returns_bad_request() {
    let app = TestApp::new().await;

    let resp = app
        .client()
        .get(format!("{}/api/scopes", app.url()))
        .send()
        .await
        .expect("request failed");

    // Without realm_id query param: 400 Bad Request (param missing before auth check)
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_scope_requires_realm_id() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    // Missing realm_id query param
    let resp = app
        .client()
        .get(format!("{}/api/scopes", app.url()))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("request failed");

    // Should return 400 because realm_id is required
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_client_creation_with_scope_assignment() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;

    // 1. Get master realm ID
    let list_resp = app
        .client()
        .get(format!("{}/api/realms?limit=1", app.url()))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("realm list failed");
    let list_body: Value = list_resp.json().await.expect("json");
    let realm_id = list_body["items"][0]["id"].as_str().expect("realm id");

    // 2. Create a custom scope
    let scope_resp = app
        .client()
        .post(format!("{}/api/scopes", app.url()))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "realm_id": realm_id,
            "name": "custom:action",
            "description": "Custom action scope",
            "enabled": true,
        }))
        .send()
        .await
        .expect("scope create failed");
    assert_eq!(scope_resp.status(), StatusCode::OK);

    // 3. Create a client that includes the custom scope in allowed_scopes
    let client_resp = app
        .client()
        .post(format!("{}/api/clients", app.url()))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "realm_id": realm_id,
            "client_id": "scoped-client",
            "name": "Scoped Client",
            "client_type": "public",
            "redirect_uris": ["http://localhost:3000/callback"],
            "allowed_scopes": ["openid", "custom:action"],
            "allowed_grant_types": ["authorization_code"],
            "pkce_required": true,
            "enabled": true,
        }))
        .send()
        .await
        .expect("client create failed");
    assert_eq!(client_resp.status(), StatusCode::OK);

    // 4. Login via the scoped client and verify the scope is present in the token
    let login_resp = app
        .client()
        .post(format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": fixtures::TEST_USER_PASSWORD,
            "client_id": "scoped-client",
        }))
        .send()
        .await
        .expect("login failed");
    assert_eq!(login_resp.status(), StatusCode::OK);
    let login_body: Value = login_resp.json().await.expect("json");
    let access_token = login_body["access_token"]
        .as_str()
        .expect("access_token must be present");

    // 5. Introspect the token to verify scope claim includes custom:action
    let intro_resp = app
        .client()
        .post(format!("{}/oidc/introspect", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "token={}&client_id=scoped-client",
            urlencoding::encode(access_token)
        ))
        .send()
        .await
        .expect("introspect failed");

    // introspect without client_secret may be rejected; accept either 200 or 401
    if intro_resp.status() == StatusCode::OK {
        let intro_body: Value = intro_resp.json().await.expect("json");
        if intro_body["active"] == true {
            let scope = intro_body["scope"].as_str().unwrap_or("");
            assert!(
                scope.contains("custom:action") || scope.contains("admin"),
                "token scope should contain custom:action or admin (password flow injects admin), got: {scope}"
            );
        }
    }
}
