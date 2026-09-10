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
async fn user_event_runs_ordered_actions_and_records_history() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm = app.master_realm_id();
    let response=app.client().post(format!("{}/api/realms/{realm}/workflows",app.url())).bearer_auth(&token).json(&json!({
        "name":"New user onboarding","description":"Prepare every new account","enabled":true,"trigger_events":["user.created"],"conditions":[{"type":"user_enabled","value":true}],
        "steps":[{"action":{"type":"set_user_attribute","name":"lifecycle","value":"onboarded"},"after_seconds":0},{"action":{"type":"add_required_action","action":"update_profile"},"after_seconds":0}],"schedule":null
    })).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let workflow = response.json::<Value>().await.unwrap();

    let response=app.client().post(format!("{}/api/users",app.url())).bearer_auth(&token).json(&json!({"realm_id":realm,"email":"workflow-user@example.com","password":"WorkflowPass123!","username":"workflow-user"})).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let user = response.json::<Value>().await.unwrap();
    let loaded = app
        .client()
        .get(format!(
            "{}/api/users/{}",
            app.url(),
            user["id"].as_str().unwrap()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(loaded["attributes"]["lifecycle"], "onboarded");
    let actions = app
        .client()
        .get(format!(
            "{}/api/users/{}/required-actions",
            app.url(),
            user["id"].as_str().unwrap()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(
        actions["required_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "update_profile")
    );
    let history = app
        .client()
        .get(format!(
            "{}/api/realms/{realm}/workflows/executions",
            app.url()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(history["items"][0]["workflow_id"], workflow["id"]);
    assert_eq!(history["items"][0]["status"], "completed");
    assert_eq!(history["items"][0]["trigger_event"], "user.created");
}

#[tokio::test]
async fn delayed_manual_execution_can_be_cancelled_and_schedules_are_processed() {
    let app = TestApp::new().await;
    let token = admin_login(&app).await;
    let realm = app.master_realm_id();
    let users = app
        .client()
        .get(format!("{}/api/users?realm_id={realm}&limit=1", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let user_id = users["items"][0]["id"].as_str().unwrap();
    let delayed=app.client().post(format!("{}/api/realms/{realm}/workflows",app.url())).bearer_auth(&token).json(&json!({"name":"Delayed security review","enabled":true,"trigger_events":[],"conditions":[],"steps":[{"action":{"type":"revoke_sessions"},"after_seconds":3600}],"schedule":null})).send().await.unwrap().json::<Value>().await.unwrap();
    let activation = app
        .client()
        .post(format!(
            "{}/api/realms/{realm}/workflows/{}/activate",
            app.url(),
            delayed["id"].as_str().unwrap()
        ))
        .bearer_auth(&token)
        .json(&json!({"user_id":user_id}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(activation["activated"], true);
    let execution_id = activation["execution_id"].as_str().unwrap();
    let cancelled = app
        .client()
        .post(format!(
            "{}/api/realms/{realm}/workflows/executions/{execution_id}/cancel",
            app.url()
        ))
        .bearer_auth(&token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(cancelled.status(), StatusCode::OK);
    let scheduled=app.client().post(format!("{}/api/realms/{realm}/workflows",app.url())).bearer_auth(&token).json(&json!({"name":"Scheduled account marker","enabled":true,"trigger_events":[],"conditions":[],"steps":[{"action":{"type":"set_user_attribute","name":"reviewed","value":"yes"},"after_seconds":0}],"schedule":{"every_seconds":60,"batch_size":100}})).send().await.unwrap();
    assert_eq!(scheduled.status(), StatusCode::CREATED);
    let run = app
        .client()
        .post(format!(
            "{}/api/realms/{realm}/workflows/run-due",
            app.url()
        ))
        .bearer_auth(&token)
        .json(&json!({"limit":500}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(run["scheduled_workflows"], 1);
    assert!(run["completed"].as_u64().unwrap() >= 1);
    let loaded = app
        .client()
        .get(format!("{}/api/users/{user_id}", app.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(loaded["attributes"]["reviewed"], "yes");
}
