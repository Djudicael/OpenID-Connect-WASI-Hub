use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};

use crate::helpers::app::TestApp;
use crate::helpers::fixtures;

#[derive(Clone)]
struct GatewayState {
    secret: String,
}

struct MockFederationGateway {
    base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl MockFederationGateway {
    async fn start(secret: &str) -> Self {
        async fn authorized(headers: &HeaderMap, state: &GatewayState) -> bool {
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                == Some(&format!("Bearer {}", state.secret))
        }
        async fn test(
            State(state): State<GatewayState>,
            headers: HeaderMap,
        ) -> (StatusCode, Json<Value>) {
            if !authorized(&headers, &state).await {
                return (StatusCode::UNAUTHORIZED, Json(json!({"ok":false})));
            }
            (
                StatusCode::OK,
                Json(json!({"ok":true,"message":"Directory connection successful"})),
            )
        }
        async fn authenticate(
            State(state): State<GatewayState>,
            headers: HeaderMap,
            Json(body): Json<Value>,
        ) -> (StatusCode, Json<Value>) {
            if !authorized(&headers, &state).await {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"authenticated":false})),
                );
            }
            let provider_type = body["provider_type"].as_str().unwrap_or_default();
            let identifier = body["identifier"].as_str().unwrap_or_default();
            let password = body["password"].as_str().unwrap_or_default();
            let user = match (provider_type, identifier, password) {
                ("ldap", "ldap.alice", "DirectoryPass123!") => Some(directory_user(
                    "ldap-100",
                    "ldap.alice",
                    "ldap.alice@example.com",
                    &["engineering"],
                )),
                ("active_directory", "ad.bob", "DirectoryPass123!") => Some(directory_user(
                    "ad-guid-200",
                    "ad.bob",
                    "ad.bob@example.com",
                    &["employees", "finance"],
                )),
                _ => None,
            };
            (
                StatusCode::OK,
                Json(json!({"authenticated":user.is_some(),"user":user})),
            )
        }
        async fn kerberos(
            State(state): State<GatewayState>,
            headers: HeaderMap,
            Json(body): Json<Value>,
        ) -> (StatusCode, Json<Value>) {
            if !authorized(&headers, &state).await {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"authenticated":false})),
                );
            }
            let valid = body["provider_type"] == "kerberos"
                && body["negotiate_token"] == "valid-spnego-token";
            let user = valid.then(|| {
                directory_user(
                    "krb-alice@EXAMPLE.COM",
                    "krb.alice",
                    "krb.alice@example.com",
                    &["domain-users"],
                )
            });
            (
                StatusCode::OK,
                Json(json!({"authenticated":valid,"user":user})),
            )
        }
        async fn users(
            State(state): State<GatewayState>,
            headers: HeaderMap,
            Json(body): Json<Value>,
        ) -> (StatusCode, Json<Value>) {
            if !authorized(&headers, &state).await {
                return (StatusCode::UNAUTHORIZED, Json(json!({"users":[]})));
            }
            let users = match body["provider_type"].as_str().unwrap_or_default() {
                "ldap" => vec![directory_user(
                    "ldap-sync-300",
                    "sync.carol",
                    "sync.carol@example.com",
                    &["engineering"],
                )],
                "active_directory" => vec![directory_user(
                    "ad-sync-400",
                    "sync.dan",
                    "sync.dan@example.com",
                    &["employees"],
                )],
                _ => vec![],
            };
            (
                StatusCode::OK,
                Json(json!({"users":users,"next_cursor":null})),
            )
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = Router::new()
            .route("/v1/test", post(test))
            .route("/v1/authenticate", post(authenticate))
            .route("/v1/kerberos/verify", post(kerberos))
            .route("/v1/users", post(users))
            .with_state(GatewayState {
                secret: secret.into(),
            });
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            shutdown: Some(tx),
            task: Some(task),
        }
    }
}

impl Drop for MockFederationGateway {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn directory_user(id: &str, username: &str, email: &str, groups: &[&str]) -> Value {
    json!({
        "external_id": id, "username": username, "email": email,
        "dn": format!("uid={username},ou=people,dc=example,dc=com"),
        "given_name": username.split('.').next().map(capitalize),
        "family_name": username.split('.').nth(1).map(capitalize),
        "enabled": true, "groups": groups, "attributes": {"department":"engineering"}
    })
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
        .unwrap_or_default()
}

async fn admin_token(app: &TestApp) -> String {
    let response = app
        .client()
        .post(format!("{}/oidc/login", app.url()))
        .json(&json!({
            "email": fixtures::TEST_USER_EMAIL, "password": fixtures::TEST_USER_PASSWORD,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .into()
}

async fn create_provider(
    app: &TestApp,
    token: &str,
    gateway: &MockFederationGateway,
    name: &str,
    provider_type: &str,
    priority: i32,
) -> Value {
    let response = app
        .client()
        .post(format!("{}/api/user-federation", app.url()))
        .bearer_auth(token)
        .json(&json!({
            "realm_id": app.master_realm_id(), "name": name, "provider_type": provider_type,
            "enabled": true, "priority": priority, "gateway_url": gateway.base_url,
            "gateway_secret": "shared-test-secret", "config": {"link_existing_users":false},
            "import_users": true, "sync_groups": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    response.json().await.unwrap()
}

#[tokio::test]
async fn ldap_active_directory_and_kerberos_federation_work_end_to_end() {
    let app = TestApp::new().await;
    let gateway = MockFederationGateway::start("shared-test-secret").await;
    let admin = admin_token(&app).await;
    let ldap = create_provider(&app, &admin, &gateway, "Corporate LDAP", "ldap", 10).await;
    create_provider(&app, &admin, &gateway, "Company AD", "active_directory", 20).await;
    create_provider(&app, &admin, &gateway, "Desktop SSO", "kerberos", 30).await;

    let test = app
        .client()
        .post(format!(
            "{}/api/user-federation/{}/test",
            app.url(),
            ldap["id"].as_str().unwrap()
        ))
        .bearer_auth(&admin)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(test.status(), StatusCode::OK);

    let sync = app
        .client()
        .post(format!(
            "{}/api/user-federation/{}/sync",
            app.url(),
            ldap["id"].as_str().unwrap()
        ))
        .bearer_auth(&admin)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(sync.status(), StatusCode::OK);
    assert_eq!(sync.json::<Value>().await.unwrap()["synced"], 1);

    for (identifier, expected_email, expected_amr) in [
        ("ldap.alice", "ldap.alice@example.com", "ldap"),
        ("ad.bob", "ad.bob@example.com", "active_directory"),
    ] {
        let response = app
            .client()
            .post(format!("{}/realms/master/login", app.url()))
            .json(&json!({
                "email": identifier, "password": "DirectoryPass123!", "client_id": "admin-ui"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "directory login failed for {identifier}"
        );
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["user"]["email"], expected_email);
        let claims = decode_claims(body["id_token"].as_str().unwrap());
        assert!(
            claims["amr"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == expected_amr)
        );
    }

    let rejected = app
        .client()
        .post(format!(
            "{}/realms/master/protocol/openid-connect/kerberos",
            app.url()
        ))
        .header("Authorization", "Negotiate invalid-token")
        .json(&json!({"client_id":"admin-ui"}))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        rejected
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Negotiate")
    );

    let kerberos = app
        .client()
        .post(format!(
            "{}/realms/master/protocol/openid-connect/kerberos",
            app.url()
        ))
        .header("Authorization", "Negotiate valid-spnego-token")
        .json(&json!({"client_id":"admin-ui"}))
        .send()
        .await
        .unwrap();
    assert_eq!(kerberos.status(), StatusCode::OK);
    let body: Value = kerberos.json().await.unwrap();
    assert_eq!(body["user"]["email"], "krb.alice@example.com");
    let claims = decode_claims(body["id_token"].as_str().unwrap());
    assert!(
        claims["amr"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "kerberos")
    );

    let mut conn = app.db_conn().await;
    let imported = oidc_repository::repositories::user_repo::UserRepo
        .find_by_email(&mut conn, app.master_realm_id(), "sync.carol@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(
        oidc_repository::repositories::user_group_repo::UserGroupRepo
            .find_groups_by_user(&mut conn, imported.id)
            .await
            .unwrap()
            .iter()
            .any(|group| group.name == "engineering")
    );
}

fn decode_claims(token: &str) -> Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
