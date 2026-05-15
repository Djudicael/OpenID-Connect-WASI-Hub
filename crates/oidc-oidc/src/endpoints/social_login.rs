//! Social login / federation endpoints.
//!
//! Allows the OIDC Hub to act as a Relying Party (RP) to upstream
//! identity providers (Google, GitHub, generic OIDC).

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::header::SET_COOKIE;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use oidc_core::models::{FederatedIdentity, IdentityProvider, User};
use oidc_core::traits::token_service::TokenService;
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex};
use oidc_repository::repositories::federated_identity_repo::FederatedIdentityRepo;
use oidc_repository::repositories::identity_provider_repo::IdentityProviderRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;

use crate::session_cookie;
use crate::state::OidcState;

/// Request parameters for initiating social login.
#[derive(Debug, Deserialize)]
pub struct SocialLoginParams {
    /// The client_id of the local RP.
    pub client_id: Option<String>,
    /// The redirect_uri to return to after login.
    pub redirect_uri: Option<String>,
    /// The state parameter to pass through.
    pub state: Option<String>,
    /// The nonce for the local OIDC flow.
    pub nonce: Option<String>,
}

/// Callback parameters from the upstream IdP.
#[derive(Debug, Deserialize)]
pub struct SocialLoginCallbackParams {
    /// Authorization code from the upstream IdP.
    pub code: String,
    /// State parameter (contains our internal state).
    pub state: String,
}

/// Initiate social login with an upstream identity provider.
///
/// Redirects the user's browser to the upstream IdP's authorization URL.
pub async fn social_login_initiate_handler(
    State(state): State<OidcState>,
    Path((realm_name, provider_alias)): Path<(String, String)>,
    Query(params): Query<SocialLoginParams>,
) -> Response {
    let mut conn = match state.connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB connection failed in social login: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            )
                .into_response();
        }
    };

    let realm = match RealmRepo.find_by_name(&mut conn, &realm_name).await {
        Ok(Some(r)) if r.enabled => r,
        _ => return (axum::http::StatusCode::NOT_FOUND, "Realm not found").into_response(),
    };

    let provider = match IdentityProviderRepo
        .find_by_alias(&mut conn, realm.id, &provider_alias)
        .await
    {
        Ok(Some(p)) if p.enabled => p,
        _ => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                "Identity provider not found",
            )
                .into_response();
        }
    };

    // Generate a state token that encodes our internal state.
    // We encode the internal state as:
    // base64url_no_pad(json({state_hash, client_id, redirect_uri, realm_id, provider_id, nonce}))
    let internal_state = generate_opaque_token().unwrap_or_default();
    let state_hash = sha2_256_hex(&internal_state);

    let state_data = json!({
        "sh": state_hash,
        "cid": params.client_id,
        "ri": params.redirect_uri,
        "rid": realm.id.to_string(),
        "pid": provider.id.to_string(),
        "n": params.nonce,
        "s": params.state,
    });

    let encoded_state = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&state_data).unwrap_or_default());

    // Build the upstream authorization URL
    let redirect_uri_for_upstream = format!(
        "{}/realms/{}/protocol/openid-connect/social/{}/callback",
        state.issuer, realm_name, provider_alias
    );

    let scopes = provider.scopes.join(" ");
    let upstream_auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
        provider.authorization_url,
        urlencoding::encode(&provider.client_id),
        urlencoding::encode(&redirect_uri_for_upstream),
        urlencoding::encode(&scopes),
        urlencoding::encode(&encoded_state),
    );

    axum::response::Redirect::temporary(&upstream_auth_url).into_response()
}

/// Callback handler for social login.
///
/// Exchanges the upstream authorization code for tokens, creates or links
/// the local user, and issues local OIDC tokens.
pub async fn social_login_callback_handler(
    State(state): State<OidcState>,
    Path((realm_name, provider_alias)): Path<(String, String)>,
    Query(params): Query<SocialLoginCallbackParams>,
) -> Response {
    // Decode the state parameter
    let state_data: serde_json::Value =
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&params.state) {
            Ok(bytes) => match serde_json::from_slice(&bytes[..]) {
                Ok(v) => v,
                Err(_) => {
                    return (axum::http::StatusCode::BAD_REQUEST, "Invalid state").into_response();
                }
            },
            Err(_) => {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    "Invalid state encoding",
                )
                    .into_response();
            }
        };

    let realm_id: uuid::Uuid = match state_data
        .get("rid")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                "Missing realm in state",
            )
                .into_response();
        }
    };

    let provider_id: uuid::Uuid = match state_data
        .get("pid")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                "Missing provider in state",
            )
                .into_response();
        }
    };

    let redirect_uri = state_data
        .get("ri")
        .and_then(|v| v.as_str())
        .unwrap_or("/")
        .to_string();
    let client_id = state_data
        .get("cid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let original_state = state_data
        .get("s")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let nonce = state_data
        .get("n")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut conn = match state.connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB connection failed in social login callback: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            )
                .into_response();
        }
    };

    let provider = match IdentityProviderRepo
        .find_by_id(&mut conn, provider_id)
        .await
    {
        Ok(Some(p)) if p.enabled => p,
        _ => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                "Identity provider not found",
            )
                .into_response();
        }
    };

    // Exchange the upstream authorization code for tokens
    let token_response = match exchange_code_for_tokens(
        &state,
        &provider,
        &params.code,
        &realm_name,
        &provider_alias,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to exchange code for tokens: {e}");
            return (axum::http::StatusCode::BAD_REQUEST, "Token exchange failed").into_response();
        }
    };

    // Extract the upstream access token
    let upstream_access_token = token_response
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Get user info from the upstream provider
    let upstream_userinfo =
        match get_upstream_userinfo(&state, &provider, upstream_access_token).await {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("Failed to get upstream userinfo: {e}");
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    "Failed to get user info",
                )
                    .into_response();
            }
        };

    let upstream_subject = upstream_userinfo
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let upstream_email = upstream_userinfo
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let upstream_name = upstream_userinfo
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if upstream_subject.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "No subject from upstream provider",
        )
            .into_response();
    }

    // Find or create the local user
    let user = match find_or_create_local_user(
        &mut conn,
        &provider,
        &upstream_subject,
        upstream_email.as_deref(),
        upstream_name.as_deref(),
        realm_id,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Failed to find/create local user: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "User creation failed",
            )
                .into_response();
        }
    };

    // Issue local OIDC tokens
    let subject = user.id.to_string();
    let audience = client_id.unwrap_or_else(|| "admin-ui".to_string());
    let scopes = vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ];

    let sid = oidc_core::utils::generate_sid().unwrap_or_default();

    let token_svc = match state.token_service_for_realm(realm_id).await {
        Ok(svc) => svc,
        Err(e) => {
            tracing::error!("Token service error: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Token service error",
            )
                .into_response();
        }
    };

    let access_token = match token_svc
        .issue_access_token(&subject, &audience, &scopes, None, None, None)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to issue access token: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Token issuance failed",
            )
                .into_response();
        }
    };

    let at_hash = oidc_core::utils::compute_at_hash(&access_token);

    let id_token_extra = oidc_core::traits::token_service::IdTokenExtraClaims {
        nonce,
        at_hash: Some(at_hash),
        auth_time: Some(chrono::Utc::now().timestamp()),
        sid: Some(sid.clone()),
        acr: Some("urn:mace:incommon:iap:silver".to_string()),
        amr: Some(vec!["pwd".to_string()]),
        email: Some(user.email.clone()),
        email_verified: Some(user.email_verified),
        name: user.username.clone(),
        given_name: user.given_name.clone(),
        family_name: user.family_name.clone(),
        ..Default::default()
    };

    let id_token = match token_svc
        .issue_id_token(&subject, &audience, Some(id_token_extra))
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to issue ID token: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Token issuance failed",
            )
                .into_response();
        }
    };

    // Store session
    let refresh_token = generate_opaque_token().unwrap_or_default();
    let now = chrono::Utc::now();
    let session = oidc_core::models::Session {
        id: generate_uuid_v7(),
        sid,
        user_id: Some(user.id),
        realm_id,
        client_id: provider.id,
        grant_type: "social_login".to_string(),
        access_token_hash: sha2_256_hex(&access_token),
        refresh_token_hash: Some(sha2_256_hex(&refresh_token)),
        id_token_jti: None,
        scope: scopes.clone(),
        revoked: false,
        expires_at: now + chrono::Duration::minutes(15),
        refresh_expires_at: Some(now + chrono::Duration::days(7)),
        created_at: now,
        last_used_at: None,
        token_family_id: Some(generate_uuid_v7()),
        previous_session_id: None,
        rotated_at: None,
        reused_at: None,
        family_revoked: false,
        authorization_details: None,
        resource: vec![],
    };

    if let Err(e) = SessionRepo.create(&mut conn, &session).await {
        tracing::error!("Failed to create session: {e}");
    }

    // Set session cookie
    let encryption_key = match state.decode_encryption_key() {
        Ok(k) => k,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Encryption key error",
            )
                .into_response();
        }
    };
    let cookie_header =
        session_cookie::session_cookie_header(&session.id.to_string(), &encryption_key);

    // Build redirect URL with tokens
    let mut redirect_url = redirect_uri.clone();
    redirect_url.push_str(&format!(
        "?access_token={}&token_type=Bearer&expires_in=900&id_token={}&refresh_token={}",
        urlencoding::encode(&access_token),
        urlencoding::encode(&id_token),
        urlencoding::encode(&refresh_token),
    ));
    if let Some(s) = original_state {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(&s)));
    }

    let mut response = axum::response::Redirect::temporary(&redirect_url).into_response();
    if let Ok(value) = cookie_header.parse() {
        response.headers_mut().insert(SET_COOKIE, value);
    }

    response
}

/// List available identity providers for a realm.
pub async fn list_identity_providers_handler(
    State(state): State<OidcState>,
    Path(realm_name): Path<String>,
) -> Response {
    let mut conn = match state.connect().await {
        Ok(c) => c,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            )
                .into_response();
        }
    };

    let realm = match RealmRepo.find_by_name(&mut conn, &realm_name).await {
        Ok(Some(r)) if r.enabled => r,
        _ => return (axum::http::StatusCode::NOT_FOUND, "Realm not found").into_response(),
    };

    let providers = match IdentityProviderRepo
        .find_by_realm(&mut conn, realm.id)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to list identity providers: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            )
                .into_response();
        }
    };

    let items: Vec<serde_json::Value> = providers
        .iter()
        .map(|p| {
            json!({
                "id": p.id.to_string(),
                "alias": p.alias,
                "display_name": p.display_name,
                "provider_type": p.provider_type.to_string(),
            })
        })
        .collect();

    Json(json!({"items": items})).into_response()
}

/// Exchange an authorization code for tokens with the upstream IdP.
async fn exchange_code_for_tokens(
    state: &OidcState,
    provider: &IdentityProvider,
    code: &str,
    realm_name: &str,
    provider_alias: &str,
) -> Result<serde_json::Value, oidc_core::OidcError> {
    let redirect_uri = format!(
        "{}/realms/{}/protocol/openid-connect/social/{}/callback",
        state.issuer, realm_name, provider_alias
    );

    let body = serde_urlencoded::to_string(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &redirect_uri),
        ("client_id", &provider.client_id),
        ("client_secret", &provider.client_secret),
    ])
    .map_err(|e| oidc_core::OidcError::Internal(format!("URL encoding failed: {e}")))?;

    #[cfg(not(target_arch = "wasm32"))]
    {
        let client = reqwest::Client::new();
        let response = client
            .post(&provider.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                oidc_core::OidcError::Internal(format!("Upstream token request failed: {e}"))
            })?;

        let json: serde_json::Value = response.json().await.map_err(|e| {
            oidc_core::OidcError::Internal(format!("Upstream token response parse failed: {e}"))
        })?;

        Ok(json)
    }

    #[cfg(target_arch = "wasm32")]
    {
        let request = wstd::http::Request::post(&provider.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(wstd::http::Body::from(body.into_bytes()))
            .map_err(|e| oidc_core::OidcError::Internal(format!("Request build failed: {e}")))?;

        let mut response = wstd::http::Client::new().send(request).await.map_err(|e| {
            oidc_core::OidcError::Internal(format!("Upstream token request failed: {e}"))
        })?;

        let body_bytes = response.body_mut().contents().await.map_err(|e| {
            oidc_core::OidcError::Internal(format!("Upstream token body read failed: {e}"))
        })?;

        let json: serde_json::Value = serde_json::from_slice(body_bytes).map_err(|e| {
            oidc_core::OidcError::Internal(format!("Upstream token response parse failed: {e}"))
        })?;

        Ok(json)
    }
}

/// Get user info from the upstream provider.
async fn get_upstream_userinfo(
    state: &OidcState,
    provider: &IdentityProvider,
    access_token: &str,
) -> Result<serde_json::Value, oidc_core::OidcError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _state = state; // suppress unused warning
        let client = reqwest::Client::new();
        let response = client
            .get(&provider.userinfo_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| {
                oidc_core::OidcError::Internal(format!("Upstream userinfo request failed: {e}"))
            })?;

        let json: serde_json::Value = response.json().await.map_err(|e| {
            oidc_core::OidcError::Internal(format!("Upstream userinfo parse failed: {e}"))
        })?;

        Ok(json)
    }

    #[cfg(target_arch = "wasm32")]
    {
        let _state = state; // suppress unused warning
        let request = wstd::http::Request::get(&provider.userinfo_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .body(wstd::http::Body::from(Vec::new()))
            .map_err(|e| oidc_core::OidcError::Internal(format!("Request build failed: {e}")))?;

        let mut response = wstd::http::Client::new().send(request).await.map_err(|e| {
            oidc_core::OidcError::Internal(format!("Upstream userinfo request failed: {e}"))
        })?;

        let body_bytes = response.body_mut().contents().await.map_err(|e| {
            oidc_core::OidcError::Internal(format!("Upstream userinfo body read failed: {e}"))
        })?;

        let json: serde_json::Value = serde_json::from_slice(body_bytes).map_err(|e| {
            oidc_core::OidcError::Internal(format!("Upstream userinfo parse failed: {e}"))
        })?;

        Ok(json)
    }
}

/// Find or create a local user based on the federated identity.
async fn find_or_create_local_user(
    conn: &mut oidc_repository::Connection,
    provider: &IdentityProvider,
    upstream_subject: &str,
    upstream_email: Option<&str>,
    upstream_name: Option<&str>,
    realm_id: uuid::Uuid,
) -> Result<User, oidc_core::OidcError> {
    // 1. Check if a federated identity already exists for this upstream subject
    if let Some(fi) = FederatedIdentityRepo
        .find_by_upstream_subject(conn, provider.id, upstream_subject)
        .await?
    {
        // Update last_used
        let _ = FederatedIdentityRepo.update_last_used(conn, fi.id).await;

        // Return the linked user
        return UserRepo
            .find_by_id(conn, fi.user_id)
            .await?
            .ok_or_else(|| oidc_core::OidcError::NotFound("linked user not found".into()));
    }

    // 2. If link_users_by_email is enabled, try to find a user by email
    if provider.link_users_by_email {
        if let Some(email) = upstream_email {
            if let Some(user) = UserRepo.find_by_email(conn, realm_id, email).await? {
                // Link the federated identity to this user
                let fi = FederatedIdentity {
                    id: generate_uuid_v7(),
                    user_id: user.id,
                    realm_id,
                    identity_provider_id: provider.id,
                    upstream_subject: upstream_subject.to_string(),
                    upstream_username: upstream_name.map(|s| s.to_string()),
                    upstream_email: Some(email.to_string()),
                    created_at: chrono::Utc::now(),
                    last_used_at: Some(chrono::Utc::now()),
                };
                FederatedIdentityRepo.create(conn, &fi).await?;
                return Ok(user);
            }
        }
    }

    // 3. If auto_create_users is enabled, create a new user
    if provider.auto_create_users {
        let email = match upstream_email {
            Some(e) => e.to_string(),
            None => format!("{}@federated.{}", upstream_subject, provider.alias),
        };
        let username = upstream_name.map(|s| s.to_string());

        let user = User {
            id: generate_uuid_v7(),
            realm_id,
            email: email.clone(),
            email_verified: upstream_email.is_some(),
            username,
            password_hash: None, // Federated users don't have local passwords
            given_name: upstream_name.map(|s| s.to_string()),
            family_name: None,
            middle_name: None,
            nickname: None,
            preferred_username: None,
            profile: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            phone_number: None,
            phone_number_verified: None,
            locale: "en".to_string(),
            attributes: serde_json::Value::Object(serde_json::Map::new()),
            enabled: true,
            deleted_at: None,
            updated_at: chrono::Utc::now(),
        };

        UserRepo.create(conn, &user).await?;

        // Create the federated identity link
        let fi = FederatedIdentity {
            id: generate_uuid_v7(),
            user_id: user.id,
            realm_id,
            identity_provider_id: provider.id,
            upstream_subject: upstream_subject.to_string(),
            upstream_username: upstream_name.map(|s| s.to_string()),
            upstream_email: upstream_email.map(|s| s.to_string()),
            created_at: chrono::Utc::now(),
            last_used_at: Some(chrono::Utc::now()),
        };
        FederatedIdentityRepo.create(conn, &fi).await?;

        return Ok(user);
    }

    Err(oidc_core::OidcError::NotFound(
        "No local user found and auto-creation is disabled".into(),
    ))
}
