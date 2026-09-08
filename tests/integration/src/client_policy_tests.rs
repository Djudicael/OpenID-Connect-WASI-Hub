use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::helpers::{app::TestApp, fixtures};

async fn admin_login(app: &TestApp) -> String {
    let response = app
        .client()
        .post(format!("{}/oidc/login", app.url()))
        .json(&json!({"email":fixtures::TEST_USER_EMAIL,"password":fixtures::TEST_USER_PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .into()
}

#[tokio::test]
async fn client_policies_are_managed_evaluated_and_enforced_on_every_registration_path() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm = app.master_realm_id();
    let profile_response=app.client().post(format!("{}/api/realms/{realm}/client-policy-profiles",app.url())).bearer_auth(&token).json(&json!({"name":"Browser baseline","description":"Safe browser clients","executors":[{"type":"require_pkce"},{"type":"secure_redirect_uris","allow_loopback_http":true},{"type":"allowed_scopes","values":["openid","profile"]}]})).send().await.unwrap();
    assert_eq!(profile_response.status(), StatusCode::CREATED);
    let profile: Value = profile_response.json().await.unwrap();
    let profile_update = app.client().put(format!("{}/api/realms/{realm}/client-policy-profiles/{}",app.url(),profile["id"].as_str().unwrap())).bearer_auth(&token).json(&json!({"name":"Browser baseline","description":"Updated browser requirements","executors":[{"type":"require_pkce"},{"type":"secure_redirect_uris","allow_loopback_http":true},{"type":"allowed_scopes","values":["openid","profile"]}]})).send().await.unwrap();
    assert_eq!(profile_update.status(), StatusCode::OK);
    let policy_response=app.client().post(format!("{}/api/realms/{realm}/client-policies",app.url())).bearer_auth(&token).json(&json!({"name":"Public clients","enabled":true,"priority":10,"conditions":[{"type":"client_type","client_type":"public"}],"profile_ids":[profile["id"]]})).send().await.unwrap();
    assert_eq!(policy_response.status(), StatusCode::CREATED);
    let policy: Value = policy_response.json().await.unwrap();
    let policy_update = app.client().put(format!("{}/api/realms/{realm}/client-policies/{}",app.url(),policy["id"].as_str().unwrap())).bearer_auth(&token).json(&json!({"name":"Public clients","enabled":true,"priority":20,"conditions":[{"type":"client_type","client_type":"public"}],"profile_ids":[profile["id"]]})).send().await.unwrap();
    assert_eq!(policy_update.status(), StatusCode::OK);

    let blocked=app.client().post(format!("{}/api/clients",app.url())).bearer_auth(&token).json(&json!({"realm_id":realm,"client_id":"unsafe-browser","name":"Unsafe browser","client_type":"public","redirect_uris":["https://app.example/callback"],"allowed_scopes":["openid"],"pkce_required":false})).send().await.unwrap();
    assert_eq!(blocked.status(), StatusCode::BAD_REQUEST);
    let body: Value = blocked.json().await.unwrap();
    assert_eq!(body["error"], "client_policy_violation");
    assert!(body["error_description"].as_str().unwrap().contains("PKCE"));
    let created=app.client().post(format!("{}/api/clients",app.url())).bearer_auth(&token).json(&json!({"realm_id":realm,"client_id":"safe-browser","name":"Safe browser","client_type":"public","redirect_uris":["http://127.0.0.1:4200/callback"],"allowed_scopes":["openid","profile"],"pkce_required":true})).send().await.unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let client: Value = created.json().await.unwrap();
    let evaluation: Value = app
        .client()
        .post(format!(
            "{}/api/realms/{realm}/client-policies/evaluate",
            app.url()
        ))
        .bearer_auth(&token)
        .json(&json!({"client_id":client["id"],"context":"admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(evaluation["allowed"], true);
    assert_eq!(evaluation["matched_policies"][0], "Public clients");

    let dynamic=app.client().post(format!("{}/oidc/register",app.url())).bearer_auth(&token).json(&json!({"realm_id":realm,"client_name":"Dynamic browser","redirect_uris":["https://dynamic.example/callback"],"grant_types":["authorization_code"],"scope":"openid email","token_endpoint_auth_method":"none"})).send().await.unwrap();
    assert_eq!(dynamic.status(), StatusCode::BAD_REQUEST);
    let body: Value = dynamic.json().await.unwrap();
    assert!(body.to_string().contains("scope 'email' is not allowed"));

    let used_delete = app
        .client()
        .delete(format!(
            "{}/api/realms/{realm}/client-policy-profiles/{}",
            app.url(),
            profile["id"].as_str().unwrap()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(used_delete.status(), StatusCode::CONFLICT);
    assert_eq!(
        app.client()
            .delete(format!(
                "{}/api/realms/{realm}/client-policies/{}",
                app.url(),
                policy["id"].as_str().unwrap()
            ))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.client()
            .delete(format!(
                "{}/api/realms/{realm}/client-policy-profiles/{}",
                app.url(),
                profile["id"].as_str().unwrap()
            ))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}
