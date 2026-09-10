use crate::helpers::{app::TestApp, fixtures};
use reqwest::StatusCode;
use serde_json::{Value, json};

async fn login(app: &TestApp, password: &str) -> reqwest::Response {
    app.client()
        .post(format!("{}/oidc/login", app.url()))
        .json(&json!({"email":fixtures::TEST_USER_EMAIL,"password":password}))
        .send()
        .await
        .unwrap()
}

async fn admin_context(app: &TestApp) -> (String, String) {
    let response = login(app, fixtures::TEST_USER_PASSWORD).await;
    assert_eq!(response.status(), StatusCode::OK);
    let token = response.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let users = app
        .client()
        .get(format!(
            "{}/api/users?realm_id={}",
            app.url(),
            app.master_realm_id()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    (token, users["items"][0]["id"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn assigned_actions_block_tokens_until_completed_in_order() {
    let app = TestApp::new().await;
    let (admin, user_id) = admin_context(&app).await;
    let assigned = app
        .client()
        .put(format!(
            "{}/api/users/{user_id}/required-actions",
            app.url()
        ))
        .bearer_auth(&admin)
        .json(&json!({"required_actions":["update_password","update_profile"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(assigned.status(), StatusCode::OK);

    let blocked = login(&app, fixtures::TEST_USER_PASSWORD).await;
    assert_eq!(blocked.status(), StatusCode::ACCEPTED);
    let body = blocked.json::<Value>().await.unwrap();
    assert!(body.get("access_token").is_none());
    assert_eq!(body["required_actions"][0], "update_password");
    let action_token = body["action_token"].as_str().unwrap();
    let password = app
        .client()
        .post(format!("{}/oidc/required-actions/password", app.url()))
        .json(&json!({"action_token":action_token,"new_password":"RequiredActionPass123!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(password.status(), StatusCode::OK);
    assert_eq!(
        password.json::<Value>().await.unwrap()["required_actions"][0],
        "update_profile"
    );
    let profile=app.client().post(format!("{}/oidc/required-actions/profile",app.url())).json(&json!({"action_token":action_token,"given_name":"Required","family_name":"User","username":"required-user"})).send().await.unwrap();
    assert_eq!(profile.status(), StatusCode::OK);
    assert_eq!(profile.json::<Value>().await.unwrap()["complete"], true);
    assert_ne!(
        login(&app, fixtures::TEST_USER_PASSWORD).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        login(&app, "RequiredActionPass123!").await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn terms_versions_and_step_up_are_enforced_by_realm_flow() {
    let app = TestApp::new().await;
    let (admin, _) = admin_context(&app).await;
    let realm_id = app.master_realm_id();
    let realm = app
        .client()
        .get(format!("{}/api/realms/{realm_id}", app.url()))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let mut config = realm["config"].clone();
    config["authentication_flow"] = json!({"enabled":true,"action_order":["accept_terms","configure_mfa","verify_email","update_profile","update_password"],"terms":{"enabled":true,"version":"2026-09","text":"Example service terms"},"step_up":{"enabled":false,"client_ids":[],"scopes":[]}});
    assert_eq!(
        app.client()
            .put(format!("{}/api/realms/{realm_id}", app.url()))
            .bearer_auth(&admin)
            .json(&json!({"config":config}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let blocked = login(&app, fixtures::TEST_USER_PASSWORD).await;
    assert_eq!(blocked.status(), StatusCode::ACCEPTED);
    let body = blocked.json::<Value>().await.unwrap();
    assert_eq!(body["required_actions"][0], "accept_terms");
    let action_token = body["action_token"].as_str().unwrap();
    let accepted = app
        .client()
        .post(format!("{}/oidc/required-actions/terms", app.url()))
        .json(&json!({"action_token":action_token,"version":"2026-09","accepted":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(accepted.json::<Value>().await.unwrap()["complete"], true);
    assert_eq!(
        login(&app, fixtures::TEST_USER_PASSWORD).await.status(),
        StatusCode::OK
    );

    config["authentication_flow"]["terms"]["version"] = json!("2026-10");
    config["authentication_flow"]["step_up"] =
        json!({"enabled":true,"client_ids":["admin-ui"],"scopes":[]});
    assert_eq!(
        app.client()
            .put(format!("{}/api/realms/{realm_id}", app.url()))
            .bearer_auth(&admin)
            .json(&json!({"config":config}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let blocked = login(&app, fixtures::TEST_USER_PASSWORD)
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        blocked["required_actions"],
        json!(["accept_terms", "configure_mfa"])
    );
}
