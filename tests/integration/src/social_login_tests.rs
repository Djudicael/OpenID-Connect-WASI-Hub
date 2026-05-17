//! Social login / federation integration tests.

use axum::Json;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::helpers::app::TestApp;

fn encrypt_test_secret(plaintext: &str) -> String {
    use pkcs8::EncodePrivateKey;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use rsa::pkcs1::EncodeRsaPrivateKey;

    let rsa_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("failed to generate RSA key");
    let rsa_pem = rsa_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .expect("failed to serialize RSA key")
        .to_string();

    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let ed_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    let ed_pem = ed_key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .expect("failed to serialize Ed25519 key")
        .to_string();

    let state =
        openid_connect_wasi::state::AppState::from_config(openid_connect_wasi::state::AppConfig {
            database_url: "postgresql://localhost/oidc_hub?sslmode=prefer".to_string(),
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            issuer: "http://localhost:8080".to_string(),
            encryption_key: crate::helpers::fixtures::TEST_ENCRYPTION_KEY.to_string(),
            pairwise_salt: "test-pairwise-salt".to_string(),
            signing_key: Some(rsa_pem),
            ed25519_key: Some(ed_pem),
        });

    state
        .encrypt_sensitive_value(plaintext.as_bytes())
        .expect("test secret encryption should succeed")
}

fn pkce_s256_challenge(verifier: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn parse_query_param(url: &str, key: &str) -> Option<String> {
    let parsed = url::Url::parse(url).expect("URL should be valid");
    parsed
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

fn extract_set_cookie_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookie| {
            cookie
                .strip_prefix(&format!("{name}="))
                .and_then(|rest| rest.split(';').next())
                .map(|value| value.to_string())
        })
}

struct MockUpstreamIdp {
    base_url: String,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl MockUpstreamIdp {
    async fn start() -> Self {
        async fn authorize() -> &'static str {
            "mock authorize"
        }

        async fn token() -> Json<Value> {
            Json(json!({
                "access_token": "upstream-access-token",
                "token_type": "Bearer",
                "expires_in": 300
            }))
        }

        async fn userinfo() -> Json<Value> {
            Json(json!({
                "sub": "upstream-user-123",
                "email": "social.user@example.com",
                "name": "Social User"
            }))
        }

        let app = axum::Router::new()
            .route("/authorize", axum::routing::get(authorize))
            .route("/token", axum::routing::post(token))
            .route("/userinfo", axum::routing::get(userinfo));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock upstream listener should bind");
        let port = listener
            .local_addr()
            .expect("mock upstream addr should exist")
            .port();
        let base_url = format!("http://127.0.0.1:{port}");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("mock upstream server should run");
        });

        Self {
            base_url,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
        }
    }
}

impl Drop for MockUpstreamIdp {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
    }
}

async fn seed_identity_provider(app: &TestApp, upstream: &MockUpstreamIdp, alias: &str) -> Uuid {
    let mut conn = app.db_conn().await;
    let provider = oidc_core::models::IdentityProvider {
        id: Uuid::new_v4(),
        realm_id: app.master_realm_id(),
        alias: alias.to_string(),
        display_name: "Mock Social".to_string(),
        provider_type: oidc_core::models::IdentityProviderType::Oidc,
        enabled: true,
        issuer: upstream.base_url.clone(),
        authorization_url: format!("{}/authorize", upstream.base_url),
        token_url: format!("{}/token", upstream.base_url),
        userinfo_url: format!("{}/userinfo", upstream.base_url),
        jwks_url: format!("{}/jwks", upstream.base_url),
        client_id: "upstream-client".to_string(),
        client_secret: encrypt_test_secret("upstream-secret"),
        scopes: vec!["openid".into(), "profile".into(), "email".into()],
        auto_create_users: true,
        link_users_by_email: true,
        deleted_at: None,
    };
    oidc_repository::repositories::identity_provider_repo::IdentityProviderRepo
        .create(&mut conn, &provider)
        .await
        .expect("identity provider seed should succeed");
    let _ = conn.close().await;
    provider.id
}

#[tokio::test]
async fn test_social_login_callback_uses_persisted_state_and_binds_session_to_client() {
    let app = TestApp::new().await;
    let upstream = MockUpstreamIdp::start().await;
    let provider_alias = "mock-social";
    let provider_id = seed_identity_provider(&app, &upstream, provider_alias).await;

    let redirect_uri = "https://app.example.com/callback";
    let code_verifier = "social-login-verifier-1234567890";
    let code_challenge = pkce_s256_challenge(code_verifier);
    let local_client_id = app
        .seed_public_client("social-client", &[redirect_uri])
        .await;

    let initiate_resp = app
        .client()
        .get(&format!(
            "{}/realms/master/protocol/openid-connect/social/{}?client_id={}&redirect_uri={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256&scope={}",
            app.url(),
            provider_alias,
            urlencoding::encode("social-client"),
            urlencoding::encode(redirect_uri),
            urlencoding::encode("rp-state-123"),
            urlencoding::encode("nonce-123"),
            urlencoding::encode(&code_challenge),
            urlencoding::encode("openid profile email"),
        ))
        .send()
        .await
        .expect("social login initiate should succeed");

    assert_eq!(initiate_resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = initiate_resp
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("initiate redirect should include location")
        .to_str()
        .expect("location should be valid UTF-8");
    let state = parse_query_param(location, "state").expect("upstream state should exist");
    let cookie_state = extract_set_cookie_value(initiate_resp.headers(), "oidc_social_state")
        .expect("social state cookie should be set");
    assert_eq!(
        state, cookie_state,
        "cookie and upstream state should match"
    );

    let callback_resp = app
        .client()
        .get(&format!(
            "{}/realms/master/protocol/openid-connect/social/{}/callback?code={}&state={}",
            app.url(),
            provider_alias,
            urlencoding::encode("upstream-code"),
            urlencoding::encode(&state),
        ))
        .header(
            reqwest::header::COOKIE,
            format!("oidc_social_state={cookie_state}"),
        )
        .send()
        .await
        .expect("social login callback should succeed");

    assert_eq!(callback_resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let callback_headers = callback_resp.headers().clone();
    let redirect_location = callback_headers
        .get(reqwest::header::LOCATION)
        .expect("callback redirect should include location")
        .to_str()
        .expect("callback redirect location should be valid UTF-8")
        .to_string();

    assert!(redirect_location.starts_with(redirect_uri));
    assert!(parse_query_param(&redirect_location, "code").is_some());
    assert_eq!(
        parse_query_param(&redirect_location, "state").as_deref(),
        Some("rp-state-123")
    );
    assert!(
        parse_query_param(&redirect_location, "access_token").is_none(),
        "access_token must not be placed into redirect query parameters"
    );
    assert!(
        !redirect_location.contains("#access_token="),
        "tokens must not be placed into redirect fragments"
    );

    let auth_code = parse_query_param(&redirect_location, "code")
        .expect("authorization code should be present");

    let token_resp = app
        .client()
        .post(&format!("{}/oidc/token", app.url()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
            urlencoding::encode(&auth_code),
            urlencoding::encode(redirect_uri),
            urlencoding::encode("social-client"),
            urlencoding::encode(code_verifier),
        ))
        .send()
        .await
        .expect("token exchange should succeed");

    assert_eq!(token_resp.status(), StatusCode::OK);
    let token_body: Value = token_resp
        .json()
        .await
        .expect("token response should be valid JSON");
    assert!(token_body["access_token"].as_str().is_some());
    assert!(token_body["refresh_token"].as_str().is_some());
    assert!(token_body["id_token"].as_str().is_some());

    let clear_cookie = callback_headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|cookie| cookie.starts_with("oidc_social_state=;") && cookie.contains("Max-Age=0"));
    assert!(
        clear_cookie,
        "callback should clear the temporary social state cookie"
    );

    let mut conn = app.db_conn().await;
    let session_row = conn
        .query_one_params(
            "SELECT client_id FROM sessions WHERE grant_type = $1 ORDER BY created_at DESC LIMIT 1",
            &[&"social_login"],
        )
        .await
        .expect("session lookup should succeed")
        .expect("social login session should exist");
    let bound_client_id = session_row
        .get::<uuid::Uuid>(0)
        .expect("session client_id should be readable");
    assert_eq!(bound_client_id, local_client_id);

    let state_row = conn
        .query_one_params(
            "SELECT used FROM social_login_states WHERE identity_provider_id = $1 ORDER BY created_at DESC LIMIT 1",
            &[&provider_id],
        )
        .await
        .expect("social state lookup should succeed")
        .expect("social state row should exist");
    let used = state_row
        .get::<bool>(0)
        .expect("used flag should be readable");
    assert!(used, "persisted social login state should be marked used");
    let _ = conn.close().await;
}

#[tokio::test]
async fn test_social_login_callback_rejects_mismatched_cookie_and_replay() {
    let app = TestApp::new().await;
    let upstream = MockUpstreamIdp::start().await;
    let provider_alias = "mock-social-replay";
    seed_identity_provider(&app, &upstream, provider_alias).await;

    let redirect_uri = "https://app.example.com/callback";
    let code_verifier = "social-login-replay-verifier-1234567890";
    let code_challenge = pkce_s256_challenge(code_verifier);
    app.seed_public_client("social-client-replay", &[redirect_uri])
        .await;

    let initiate_resp = app
        .client()
        .get(&format!(
            "{}/realms/master/protocol/openid-connect/social/{}?client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256&scope={}",
            app.url(),
            provider_alias,
            urlencoding::encode("social-client-replay"),
            urlencoding::encode(redirect_uri),
            urlencoding::encode("rp-state-replay"),
            urlencoding::encode(&code_challenge),
            urlencoding::encode("openid profile email"),
        ))
        .send()
        .await
        .expect("social login initiate should succeed");

    assert_eq!(initiate_resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = initiate_resp
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("initiate redirect should include location")
        .to_str()
        .expect("location should be valid UTF-8");
    let state = parse_query_param(location, "state").expect("upstream state should exist");
    let cookie_state = extract_set_cookie_value(initiate_resp.headers(), "oidc_social_state")
        .expect("social state cookie should be set");

    let mismatched_cookie_resp = app
        .client()
        .get(&format!(
            "{}/realms/master/protocol/openid-connect/social/{}/callback?code={}&state={}",
            app.url(),
            provider_alias,
            urlencoding::encode("upstream-code"),
            urlencoding::encode(&state),
        ))
        .header(
            reqwest::header::COOKIE,
            "oidc_social_state=wrong-cookie-value",
        )
        .send()
        .await
        .expect("mismatched cookie callback should return a response");

    assert_eq!(mismatched_cookie_resp.status(), StatusCode::BAD_REQUEST);
    let mismatched_body = mismatched_cookie_resp
        .text()
        .await
        .expect("mismatched cookie body should be readable");
    assert!(mismatched_body.contains("Invalid state"));

    let _ = code_verifier;

    let success_resp = app
        .client()
        .get(&format!(
            "{}/realms/master/protocol/openid-connect/social/{}/callback?code={}&state={}",
            app.url(),
            provider_alias,
            urlencoding::encode("upstream-code"),
            urlencoding::encode(&state),
        ))
        .header(
            reqwest::header::COOKIE,
            format!("oidc_social_state={cookie_state}"),
        )
        .send()
        .await
        .expect("first callback should succeed");
    assert_eq!(success_resp.status(), StatusCode::TEMPORARY_REDIRECT);

    let replay_resp = app
        .client()
        .get(&format!(
            "{}/realms/master/protocol/openid-connect/social/{}/callback?code={}&state={}",
            app.url(),
            provider_alias,
            urlencoding::encode("upstream-code"),
            urlencoding::encode(&state),
        ))
        .header(
            reqwest::header::COOKIE,
            format!("oidc_social_state={cookie_state}"),
        )
        .send()
        .await
        .expect("replayed callback should return a response");

    assert_eq!(replay_resp.status(), StatusCode::BAD_REQUEST);
    let replay_body = replay_resp
        .text()
        .await
        .expect("replay body should be readable");
    assert!(replay_body.contains("Invalid state"));
}
