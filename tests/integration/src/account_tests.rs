use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::helpers::{app::TestApp, fixtures};

async fn login(app: &TestApp, password: &str) -> String {
    let response = app
        .client()
        .post(format!("{}/oidc/login", app.url()))
        .json(&json!({"email": fixtures::TEST_USER_EMAIL, "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn account_console_manages_profile_sessions_password_and_applications() {
    let app = TestApp::new().await;
    let first_token = login(&app, fixtures::TEST_USER_PASSWORD).await;
    let current_token = login(&app, fixtures::TEST_USER_PASSWORD).await;

    let profile = app
        .client()
        .get(format!("{}/oidc/account", app.url()))
        .bearer_auth(&current_token)
        .send()
        .await
        .unwrap();
    assert_eq!(profile.status(), StatusCode::OK);
    let profile = profile.json::<Value>().await.unwrap();
    assert_eq!(profile["email"], fixtures::TEST_USER_EMAIL);
    assert_eq!(profile["administration_access"], true);

    let updated = app
        .client()
        .put(format!("{}/oidc/account", app.url()))
        .bearer_auth(&current_token)
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "username": "account-owner",
            "given_name": "Account",
            "family_name": "Owner",
            "locale": "fr"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::OK);
    let updated = updated.json::<Value>().await.unwrap();
    assert_eq!(updated["given_name"], "Account");
    assert_eq!(updated["locale"], "fr");

    let sessions = app
        .client()
        .get(format!("{}/oidc/account/sessions", app.url()))
        .bearer_auth(&current_token)
        .send()
        .await
        .unwrap();
    assert_eq!(sessions.status(), StatusCode::OK);
    let sessions = sessions.json::<Value>().await.unwrap();
    assert!(sessions["items"].as_array().unwrap().len() >= 2);
    assert!(
        sessions["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["current"] == true)
    );
    let other_session_id = sessions["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["current"] == false)
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let revoked = app
        .client()
        .delete(format!(
            "{}/oidc/account/sessions/{other_session_id}",
            app.url()
        ))
        .bearer_auth(&current_token)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::OK);
    let revoked_session = app
        .client()
        .get(format!("{}/oidc/account", app.url()))
        .bearer_auth(&first_token)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked_session.status(), StatusCode::UNAUTHORIZED);

    let applications = app
        .client()
        .get(format!("{}/oidc/account/applications", app.url()))
        .bearer_auth(&current_token)
        .send()
        .await
        .unwrap();
    assert_eq!(applications.status(), StatusCode::OK);
    let applications = applications.json::<Value>().await.unwrap();
    assert!(
        applications["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["client_id"] == "admin-ui")
    );

    let identities = app
        .client()
        .get(format!("{}/oidc/account/linked-identities", app.url()))
        .bearer_auth(&current_token)
        .send()
        .await
        .unwrap();
    assert_eq!(identities.status(), StatusCode::OK);
    assert!(
        identities.json::<Value>().await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let changed = app.client().put(format!("{}/oidc/account/password", app.url()))
        .bearer_auth(&current_token)
        .json(&json!({"current_password": fixtures::TEST_USER_PASSWORD, "new_password": "NewAccountPass123!"}))
        .send().await.unwrap();
    assert_eq!(changed.status(), StatusCode::OK);

    let revoked_old_session = app
        .client()
        .get(format!("{}/oidc/account", app.url()))
        .bearer_auth(&first_token)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked_old_session.status(), StatusCode::UNAUTHORIZED);
    let new_token = login(&app, "NewAccountPass123!").await;

    let applications = app
        .client()
        .get(format!("{}/oidc/account/applications", app.url()))
        .bearer_auth(&new_token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let application_id = applications["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["client_id"] == "admin-ui")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let revoked_application = app
        .client()
        .delete(format!(
            "{}/oidc/account/applications/{application_id}",
            app.url()
        ))
        .bearer_auth(&new_token)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked_application.status(), StatusCode::OK);
    let revoked_application_session = app
        .client()
        .get(format!("{}/oidc/account", app.url()))
        .bearer_auth(&new_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        revoked_application_session.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn account_endpoints_require_an_active_user_session() {
    let app = TestApp::new().await;
    for path in [
        "/oidc/account",
        "/oidc/account/sessions",
        "/oidc/account/applications",
        "/oidc/account/linked-identities",
    ] {
        let response = app
            .client()
            .get(format!("{}{}", app.url(), path))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn explicit_consent_is_saved_and_visible_in_the_account() {
    let app = TestApp::new().await;
    let login_response = app
        .client()
        .post(format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL,
            "password": fixtures::TEST_USER_PASSWORD
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let cookie = login_response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let access_token = login_response.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let authorize_url = format!(
        "{}/oidc/authorize?client_id=admin-ui&redirect_uri={}&response_type=code&scope=openid+profile+email+admin&state=account-consent&prompt=consent&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
        app.url(),
        urlencoding::encode("http://localhost:3000/callback")
    );
    let consent_page = app
        .client()
        .get(&authorize_url)
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(consent_page.status(), StatusCode::OK);
    let body = consent_page.text().await.unwrap();
    assert!(body.contains("Approve access"));
    assert!(body.contains("View your email address"));
    let marker = "name=\"consent_token\" value=\"";
    let token_start = body.find(marker).unwrap() + marker.len();
    let consent_token = &body[token_start..token_start + body[token_start..].find('"').unwrap()];

    let approved = app
        .client()
        .get(format!(
            "{authorize_url}&consent_action=allow&consent_token={}",
            urlencoding::encode(consent_token)
        ))
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(approved.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(
        approved
            .headers()
            .get(reqwest::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("code=")
    );

    let applications = app
        .client()
        .get(format!("{}/oidc/account/applications", app.url()))
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(applications.status(), StatusCode::OK);
    let applications = applications.json::<Value>().await.unwrap();
    let admin_ui = applications["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["client_id"] == "admin-ui")
        .unwrap();
    assert!(
        admin_ui["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|scope| scope == "email")
    );
}
