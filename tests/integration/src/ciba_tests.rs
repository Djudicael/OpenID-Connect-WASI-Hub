use crate::helpers::{app::TestApp, fixtures};
use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use oidc_core::models::{CIBA_GRANT_TYPE, CibaClientConfig};
use oidc_repository::repositories::{ciba_repo::CibaRepo, client_repo::ClientRepo};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::sync::mpsc;

async fn capture_ping(
    State(sender): State<mpsc::UnboundedSender<(HeaderMap, Value)>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> StatusCode {
    let _ = sender.send((headers, body));
    StatusCode::NO_CONTENT
}

#[tokio::test]
async fn ciba_poll_flow_requires_user_approval_and_is_one_time() {
    let app = TestApp::new().await;
    let client_id = "ciba-test";
    let secret = "ciba-test-secret";
    let id = app
        .seed_client_with_secret(client_id, secret, &["https://client.example/callback"])
        .await;
    let mut conn = app.db_conn().await;
    let mut client = ClientRepo.find_by_id(&mut conn, id).await.unwrap().unwrap();
    client.allowed_grant_types.push(CIBA_GRANT_TYPE.into());
    ClientRepo.update(&mut conn, &client).await.unwrap();
    CibaRepo
        .save_config(
            &mut conn,
            &CibaClientConfig {
                client_id: id,
                delivery_mode: "poll".into(),
                client_notification_endpoint: None,
                request_lifetime_seconds: 300,
                polling_interval_seconds: 2,
            },
        )
        .await
        .unwrap();
    conn.close().await.unwrap();

    let login = app
        .client()
        .post(format!("{}/oidc/login", app.url()))
        .json(&json!({"email":fixtures::TEST_USER_EMAIL,"password":fixtures::TEST_USER_PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let user_token = login.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let start = app
        .client()
        .post(format!(
            "{}/realms/master/protocol/openid-connect/ext/ciba/auth",
            app.url()
        ))
        .form(&[
            ("client_id", client_id),
            ("client_secret", secret),
            ("login_hint", fixtures::TEST_USER_EMAIL),
            ("scope", "openid profile"),
            ("binding_message", "4821"),
            ("request_context", "Approve the desktop sign-in"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::OK);
    let start = start.json::<Value>().await.unwrap();
    let auth_req_id = start["auth_req_id"].as_str().unwrap();

    let poll = app
        .client()
        .post(format!(
            "{}/realms/master/protocol/openid-connect/token",
            app.url()
        ))
        .form(&[
            ("grant_type", CIBA_GRANT_TYPE),
            ("auth_req_id", auth_req_id),
            ("client_id", client_id),
            ("client_secret", secret),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(poll.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        poll.json::<Value>().await.unwrap()["error"],
        "authorization_pending"
    );
    let fast_poll = app
        .client()
        .post(format!(
            "{}/realms/master/protocol/openid-connect/token",
            app.url()
        ))
        .form(&[
            ("grant_type", CIBA_GRANT_TYPE),
            ("auth_req_id", auth_req_id),
            ("client_id", client_id),
            ("client_secret", secret),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        fast_poll.json::<Value>().await.unwrap()["error"],
        "slow_down"
    );

    let pending = app
        .client()
        .get(format!("{}/oidc/account/ciba", app.url()))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    assert_eq!(pending.status(), StatusCode::OK);
    let pending = pending.json::<Value>().await.unwrap();
    assert_eq!(pending["items"][0]["binding_message"], "4821");
    let request_id = pending["items"][0]["id"].as_str().unwrap();

    let approved = app
        .client()
        .post(format!("{}/oidc/account/ciba/{request_id}", app.url()))
        .bearer_auth(&user_token)
        .json(&json!({"decision":"approve"}))
        .send()
        .await
        .unwrap();
    assert_eq!(approved.status(), StatusCode::OK);

    let tokens = app
        .client()
        .post(format!(
            "{}/realms/master/protocol/openid-connect/token",
            app.url()
        ))
        .form(&[
            ("grant_type", CIBA_GRANT_TYPE),
            ("auth_req_id", auth_req_id),
            ("client_id", client_id),
            ("client_secret", secret),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(tokens.status(), StatusCode::OK);
    let tokens = tokens.json::<Value>().await.unwrap();
    assert!(tokens["access_token"].as_str().is_some());
    assert!(tokens["id_token"].as_str().is_some());

    let replay = app
        .client()
        .post(format!(
            "{}/realms/master/protocol/openid-connect/token",
            app.url()
        ))
        .form(&[
            ("grant_type", CIBA_GRANT_TYPE),
            ("auth_req_id", auth_req_id),
            ("client_id", client_id),
            ("client_secret", secret),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        replay.json::<Value>().await.unwrap()["error"],
        "expired_token"
    );

    let (ping_sender, mut ping_receiver) = mpsc::unbounded_channel();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ping_endpoint = format!("http://{}/notify", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/notify", post(capture_ping))
                .with_state(ping_sender),
        )
        .await
        .unwrap();
    });

    let mut conn = app.db_conn().await;
    CibaRepo
        .save_config(
            &mut conn,
            &CibaClientConfig {
                client_id: id,
                delivery_mode: "ping".into(),
                client_notification_endpoint: Some(ping_endpoint),
                request_lifetime_seconds: 300,
                polling_interval_seconds: 2,
            },
        )
        .await
        .unwrap();
    conn.close().await.unwrap();

    let notification_token = "a-high-entropy-notification-token";
    let ping_start = app
        .client()
        .post(format!(
            "{}/realms/master/protocol/openid-connect/ext/ciba/auth",
            app.url()
        ))
        .form(&[
            ("client_id", client_id),
            ("client_secret", secret),
            ("login_hint", fixtures::TEST_USER_EMAIL),
            ("scope", "openid profile"),
            ("binding_message", "9374"),
            ("client_notification_token", notification_token),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(ping_start.status(), StatusCode::OK);
    let ping_auth_req_id = ping_start.json::<Value>().await.unwrap()["auth_req_id"]
        .as_str()
        .unwrap()
        .to_string();

    let pending = app
        .client()
        .get(format!("{}/oidc/account/ciba", app.url()))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let ping_request_id = pending["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["binding_message"] == "9374")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let approved = app
        .client()
        .post(format!("{}/oidc/account/ciba/{ping_request_id}", app.url()))
        .bearer_auth(&user_token)
        .json(&json!({"decision":"approve"}))
        .send()
        .await
        .unwrap();
    assert_eq!(approved.status(), StatusCode::OK);
    assert_eq!(
        approved.json::<Value>().await.unwrap()["notification_delivered"],
        true
    );

    let (ping_headers, ping_body) =
        tokio::time::timeout(std::time::Duration::from_secs(2), ping_receiver.recv())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        ping_headers.get("authorization").unwrap(),
        format!("Bearer {notification_token}").as_str()
    );
    assert_eq!(ping_body["auth_req_id"], ping_auth_req_id);

    let ping_tokens = app
        .client()
        .post(format!(
            "{}/realms/master/protocol/openid-connect/token",
            app.url()
        ))
        .form(&[
            ("grant_type", CIBA_GRANT_TYPE),
            ("auth_req_id", ping_auth_req_id.as_str()),
            ("client_id", client_id),
            ("client_secret", secret),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(ping_tokens.status(), StatusCode::OK);
}
