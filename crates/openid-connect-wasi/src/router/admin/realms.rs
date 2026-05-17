use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use oidc_core::models::IdentityProviderType;
use oidc_core::models::audit_event::ActorType;
use oidc_core::utils::generate_uuid_v7;
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;
use oidc_repository::repositories::identity_provider_repo::IdentityProviderRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::realm_signing_keys_repo::RealmSigningKeysRepo;

use crate::middleware::admin_auth::AdminAuth;
use crate::router::admin::{
    admin_or_forbidden, bad_request, conflict, connect, internal_error, not_found,
};
use crate::state::AppState;

// ─── Realms CRUD ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RealmListQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
}

fn default_limit() -> i64 {
    20
}
fn default_offset() -> i64 {
    0
}

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<RealmListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let realms = match RealmRepo.list(&mut conn, query.limit, query.offset).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("list realms error: {e}");
            return internal_error();
        }
    };
    let total = RealmRepo.count(&mut conn).await.unwrap_or_else(|e| {
        tracing::warn!("failed to count realms: {e}");
        0
    });
    let rows: Vec<Value> = realms
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id.to_string(),
                "name": r.name,
                "display_name": r.display_name,
                "enabled": r.enabled,
                "config": r.config,
            })
        })
        .collect();
    Json(json!({"items": rows, "total": total})).into_response()
}

pub async fn get(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match RealmRepo.find_by_id(&mut conn, id).await {
        Ok(Some(r)) => Json(json!({
            "id": r.id.to_string(),
            "name": r.name,
            "display_name": r.display_name,
            "enabled": r.enabled,
            "config": r.config,
        }))
        .into_response(),
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!("get realm error: {e}");
            internal_error()
        }
    }
}

#[derive(Deserialize)]
pub struct CreateRequest {
    name: String,
    display_name: String,
    enabled: Option<bool>,
    config: Option<Value>,
}

pub async fn create(State(state): State<AppState>, auth: AdminAuth, body: String) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: CreateRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match RealmRepo.find_by_name(&mut conn, &req.name).await {
        Ok(Some(_)) => return conflict(),
        Ok(None) => {}
        Err(e) => {
            tracing::error!("create realm duplicate check error: {e}");
            return internal_error();
        }
    }
    let realm_id = generate_uuid_v7();
    let config = req
        .config
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
    let realm = oidc_core::models::Realm {
        id: realm_id,
        name: req.name,
        display_name: req.display_name,
        enabled: req.enabled.unwrap_or(true),
        config,
        deleted_at: None,
    };
    match RealmRepo.create(&mut conn, &realm).await {
        Ok(()) => {}
        Err(e) => {
            tracing::error!("create realm error: {e}");
            return internal_error();
        }
    }
    let keys = match oidc_oidc::tokens::generate_realm_keys(realm.id) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("generate realm keys error: {e}");
            return internal_error();
        }
    };
    if let Err(e) = RealmSigningKeysRepo.create(&mut conn, &keys).await {
        tracing::error!("store realm keys error: {e}");
        return internal_error();
    }
    let actor_type = if auth.is_api_key {
        ActorType::ApiKey
    } else {
        ActorType::User
    };
    let actor_id = Uuid::parse_str(&auth.subject).ok();
    let audit = oidc_core::models::audit_event::AuditEvent {
        id: generate_uuid_v7(),
        realm_id: Some(realm.id),
        event_type: "realm.created".to_string(),
        actor_id,
        actor_type,
        target_type: Some("realm".to_string()),
        target_id: Some(realm.id),
        details: json!({"name": realm.name}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
        tracing::warn!("create realm audit event error: {e}");
    }
    Json(json!({
        "id": realm.id.to_string(),
        "name": realm.name,
        "display_name": realm.display_name,
        "enabled": realm.enabled,
        "config": realm.config,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct UpdateRequest {
    name: Option<String>,
    display_name: Option<String>,
    enabled: Option<bool>,
    config: Option<Value>,
}

pub async fn update(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: UpdateRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut realm = match RealmRepo.find_by_id(&mut conn, id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("update realm fetch error: {e}");
            return internal_error();
        }
    };
    if let Some(v) = req.name {
        realm.name = v;
    }
    if let Some(v) = req.display_name {
        realm.display_name = v;
    }
    if let Some(v) = req.enabled {
        realm.enabled = v;
    }
    if let Some(v) = req.config {
        realm.config = v;
    }
    match RealmRepo.update(&mut conn, &realm).await {
        Ok(()) => Json(json!({"updated": true})).into_response(),
        Err(e) => {
            tracing::error!("update realm error: {e}");
            internal_error()
        }
    }
}

pub async fn delete(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(e) = RealmSigningKeysRepo.delete_by_realm_id(&mut conn, id).await {
        tracing::warn!("delete realm signing keys error: {e}");
    }
    match RealmRepo.delete(&mut conn, id).await {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => {
            tracing::error!("delete realm error: {e}");
            internal_error()
        }
    }
}

// ─── Password Policy ───────────────────────────────────────────────────────────

pub async fn get_password_policy(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let realm = match RealmRepo.find_by_id(&mut conn, id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("get password policy realm fetch error: {e}");
            return internal_error();
        }
    };
    let policy = oidc_core::models::PasswordPolicy::from_realm_config(&realm.config);
    Json(json!({
        "min_length": policy.min_length,
        "max_length": policy.max_length,
        "require_uppercase": policy.require_uppercase,
        "require_lowercase": policy.require_lowercase,
        "require_digit": policy.require_digit,
        "require_special": policy.require_special,
        "min_unique_chars": policy.min_unique_chars,
        "password_history_count": policy.password_history_count,
        "max_identical_consecutive": policy.max_identical_consecutive,
        "disallowed_passwords": policy.disallowed_passwords,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct UpdatePasswordPolicyRequest {
    min_length: Option<usize>,
    max_length: Option<usize>,
    require_uppercase: Option<bool>,
    require_lowercase: Option<bool>,
    require_digit: Option<bool>,
    require_special: Option<bool>,
    min_unique_chars: Option<usize>,
    password_history_count: Option<usize>,
    max_identical_consecutive: Option<usize>,
    disallowed_passwords: Option<Vec<String>>,
}

pub async fn update_password_policy(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: UpdatePasswordPolicyRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut realm = match RealmRepo.find_by_id(&mut conn, id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("update password policy realm fetch error: {e}");
            return internal_error();
        }
    };
    let current = oidc_core::models::PasswordPolicy::from_realm_config(&realm.config);
    let updated_policy = oidc_core::models::PasswordPolicy {
        min_length: req.min_length.unwrap_or(current.min_length),
        max_length: req.max_length.unwrap_or(current.max_length),
        require_uppercase: req.require_uppercase.unwrap_or(current.require_uppercase),
        require_lowercase: req.require_lowercase.unwrap_or(current.require_lowercase),
        require_digit: req.require_digit.unwrap_or(current.require_digit),
        require_special: req.require_special.unwrap_or(current.require_special),
        min_unique_chars: req.min_unique_chars.unwrap_or(current.min_unique_chars),
        password_history_count: req
            .password_history_count
            .unwrap_or(current.password_history_count),
        max_identical_consecutive: req
            .max_identical_consecutive
            .unwrap_or(current.max_identical_consecutive),
        disallowed_passwords: req
            .disallowed_passwords
            .unwrap_or(current.disallowed_passwords),
    };
    let config = realm.config.as_object_mut();
    if let Some(config_map) = config {
        config_map.insert(
            "password_policy".to_string(),
            serde_json::to_value(&updated_policy).unwrap_or_default(),
        );
    }
    match RealmRepo.update(&mut conn, &realm).await {
        Ok(()) => {
            let audit = oidc_core::models::audit_event::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: Some(realm.id),
                event_type: "realm.password_policy_updated".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("realm".to_string()),
                target_id: Some(realm.id),
                details: json!({}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
                tracing::warn!("failed to write audit event: {e}");
            }
            Json(json!({
                "min_length": updated_policy.min_length,
                "max_length": updated_policy.max_length,
                "require_uppercase": updated_policy.require_uppercase,
                "require_lowercase": updated_policy.require_lowercase,
                "require_digit": updated_policy.require_digit,
                "require_special": updated_policy.require_special,
                "min_unique_chars": updated_policy.min_unique_chars,
                "password_history_count": updated_policy.password_history_count,
                "max_identical_consecutive": updated_policy.max_identical_consecutive,
                "disallowed_passwords": updated_policy.disallowed_passwords,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("update password policy error: {e}");
            internal_error()
        }
    }
}

// ─── Identity Providers CRUD ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct IdpListQuery {
    realm_id: Option<Uuid>,
}

pub async fn list_identity_providers(
    State(state): State<AppState>,
    Query(query): Query<IdpListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let items = match query.realm_id {
        Some(realm_id) => match IdentityProviderRepo
            .find_by_realm(&mut conn, realm_id)
            .await
        {
            Ok(i) => i,
            Err(e) => {
                tracing::error!("list identity providers error: {e}");
                return internal_error();
            }
        },
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "realm_id required"})),
            )
                .into_response();
        }
    };
    let rows: Vec<Value> = items.into_iter().map(|i| json!({
        "id": i.id.to_string(),
        "realm_id": i.realm_id.to_string(),
        "alias": i.alias,
        "display_name": i.display_name,
        "provider_type": match i.provider_type { IdentityProviderType::Oidc => "oidc", IdentityProviderType::Google => "google", IdentityProviderType::GitHub => "github" },
        "enabled": i.enabled,
        "issuer": i.issuer,
        "authorization_url": i.authorization_url,
        "token_url": i.token_url,
        "userinfo_url": i.userinfo_url,
        "jwks_url": i.jwks_url,
        "client_id": i.client_id,
        "scopes": i.scopes,
        "auto_create_users": i.auto_create_users,
        "link_users_by_email": i.link_users_by_email,
    })).collect();
    Json(json!({"items": rows, "total": rows.len()})).into_response()
}

#[derive(Deserialize)]
pub struct CreateIdentityProviderRequest {
    realm_id: Uuid,
    alias: String,
    display_name: String,
    provider_type: Option<String>,
    enabled: Option<bool>,
    issuer: String,
    authorization_url: Option<String>,
    token_url: Option<String>,
    userinfo_url: Option<String>,
    jwks_url: Option<String>,
    client_id: String,
    client_secret: Option<String>,
    scopes: Option<Vec<String>>,
    auto_create_users: Option<bool>,
    link_users_by_email: Option<bool>,
}

pub async fn create_identity_provider(
    State(state): State<AppState>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: CreateIdentityProviderRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match IdentityProviderRepo
        .find_by_alias(&mut conn, req.realm_id, &req.alias)
        .await
    {
        Ok(Some(_)) => return conflict(),
        Ok(None) => {}
        Err(e) => {
            tracing::error!("create idp duplicate check error: {e}");
            return internal_error();
        }
    }
    let provider_type = match req.provider_type.as_deref() {
        Some("google") => IdentityProviderType::Google,
        Some("github") => IdentityProviderType::GitHub,
        _ => IdentityProviderType::Oidc,
    };
    let (issuer, authorization_url, token_url, userinfo_url, jwks_url) = match provider_type {
        IdentityProviderType::Google => (
            req.issuer,
            req.authorization_url
                .unwrap_or_else(|| "https://accounts.google.com/o/oauth2/v2/auth".into()),
            req.token_url
                .unwrap_or_else(|| "https://oauth2.googleapis.com/token".into()),
            req.userinfo_url
                .unwrap_or_else(|| "https://openidconnect.googleapis.com/v1/userinfo".into()),
            req.jwks_url
                .unwrap_or_else(|| "https://www.googleapis.com/oauth2/v3/certs".into()),
        ),
        IdentityProviderType::GitHub => (
            req.issuer,
            req.authorization_url
                .unwrap_or_else(|| "https://github.com/login/oauth/authorize".into()),
            req.token_url
                .unwrap_or_else(|| "https://github.com/login/oauth/access_token".into()),
            req.userinfo_url
                .unwrap_or_else(|| "https://api.github.com/user".into()),
            req.jwks_url.unwrap_or_default(),
        ),
        IdentityProviderType::Oidc => (
            req.issuer.clone(),
            req.authorization_url.unwrap_or_default(),
            req.token_url.unwrap_or_default(),
            req.userinfo_url.unwrap_or_default(),
            req.jwks_url.unwrap_or_default(),
        ),
    };
    let id = generate_uuid_v7();
    let idp = oidc_core::models::IdentityProvider {
        id,
        realm_id: req.realm_id,
        alias: req.alias,
        display_name: req.display_name,
        provider_type,
        enabled: req.enabled.unwrap_or(true),
        issuer,
        authorization_url,
        token_url,
        userinfo_url,
        jwks_url,
        client_id: req.client_id,
        client_secret: req.client_secret.unwrap_or_default(),
        scopes: req
            .scopes
            .unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]),
        auto_create_users: req.auto_create_users.unwrap_or(true),
        link_users_by_email: req.link_users_by_email.unwrap_or(false),
        deleted_at: None,
    };
    if let Err(e) = idp.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{e}")})),
        )
            .into_response();
    }
    match IdentityProviderRepo.create(&mut conn, &idp).await {
        Ok(()) => {
            let audit = oidc_core::models::audit_event::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: Some(idp.realm_id),
                event_type: "identity_provider.created".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("identity_provider".to_string()),
                target_id: Some(idp.id),
                details: json!({"alias": idp.alias}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
                tracing::warn!("failed to write audit event: {e}");
            }
            Json(json!({
                "id": idp.id.to_string(),
                "realm_id": idp.realm_id.to_string(),
                "alias": idp.alias,
                "display_name": idp.display_name,
                "provider_type": match idp.provider_type { IdentityProviderType::Oidc => "oidc", IdentityProviderType::Google => "google", IdentityProviderType::GitHub => "github" },
                "enabled": idp.enabled,
                "issuer": idp.issuer,
                "authorization_url": idp.authorization_url,
                "token_url": idp.token_url,
                "userinfo_url": idp.userinfo_url,
                "jwks_url": idp.jwks_url,
                "client_id": idp.client_id,
                "scopes": idp.scopes,
                "auto_create_users": idp.auto_create_users,
                "link_users_by_email": idp.link_users_by_email,
            })).into_response()
        }
        Err(e) => {
            tracing::error!("create identity provider error: {e}");
            internal_error()
        }
    }
}

pub async fn get_identity_provider(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match IdentityProviderRepo.find_by_id(&mut conn, id).await {
        Ok(Some(i)) => Json(json!({
            "id": i.id.to_string(),
            "realm_id": i.realm_id.to_string(),
            "alias": i.alias,
            "display_name": i.display_name,
            "provider_type": match i.provider_type { IdentityProviderType::Oidc => "oidc", IdentityProviderType::Google => "google", IdentityProviderType::GitHub => "github" },
            "enabled": i.enabled,
            "issuer": i.issuer,
            "authorization_url": i.authorization_url,
            "token_url": i.token_url,
            "userinfo_url": i.userinfo_url,
            "jwks_url": i.jwks_url,
            "client_id": i.client_id,
            "scopes": i.scopes,
            "auto_create_users": i.auto_create_users,
            "link_users_by_email": i.link_users_by_email,
        })).into_response(),
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!("get identity provider error: {e}");
            internal_error()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateIdentityProviderRequest {
    alias: Option<String>,
    display_name: Option<String>,
    provider_type: Option<String>,
    enabled: Option<bool>,
    issuer: Option<String>,
    authorization_url: Option<String>,
    token_url: Option<String>,
    userinfo_url: Option<String>,
    jwks_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scopes: Option<Vec<String>>,
    auto_create_users: Option<bool>,
    link_users_by_email: Option<bool>,
}

pub async fn update_identity_provider(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: UpdateIdentityProviderRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut idp = match IdentityProviderRepo.find_by_id(&mut conn, id).await {
        Ok(Some(i)) => i,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("update idp fetch error: {e}");
            return internal_error();
        }
    };
    if let Some(v) = req.alias {
        idp.alias = v;
    }
    if let Some(v) = req.display_name {
        idp.display_name = v;
    }
    if let Some(v) = req.provider_type {
        idp.provider_type = match v.as_str() {
            "google" => IdentityProviderType::Google,
            "github" => IdentityProviderType::GitHub,
            _ => IdentityProviderType::Oidc,
        };
    }
    if let Some(v) = req.enabled {
        idp.enabled = v;
    }
    if let Some(v) = req.issuer {
        idp.issuer = v;
    }
    if let Some(v) = req.authorization_url {
        idp.authorization_url = v;
    }
    if let Some(v) = req.token_url {
        idp.token_url = v;
    }
    if let Some(v) = req.userinfo_url {
        idp.userinfo_url = v;
    }
    if let Some(v) = req.jwks_url {
        idp.jwks_url = v;
    }
    if let Some(v) = req.client_id {
        idp.client_id = v;
    }
    if let Some(v) = req.client_secret {
        idp.client_secret = v;
    }
    if let Some(v) = req.scopes {
        idp.scopes = v;
    }
    if let Some(v) = req.auto_create_users {
        idp.auto_create_users = v;
    }
    if let Some(v) = req.link_users_by_email {
        idp.link_users_by_email = v;
    }
    if let Err(e) = idp.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{e}")})),
        )
            .into_response();
    }
    match IdentityProviderRepo.update(&mut conn, &idp).await {
        Ok(()) => {
            let audit = oidc_core::models::audit_event::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: Some(idp.realm_id),
                event_type: "identity_provider.updated".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("identity_provider".to_string()),
                target_id: Some(idp.id),
                details: json!({"alias": idp.alias}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
                tracing::warn!("failed to write audit event: {e}");
            }
            Json(json!({"updated": true})).into_response()
        }
        Err(e) => {
            tracing::error!("update identity provider error: {e}");
            internal_error()
        }
    }
}

pub async fn delete_identity_provider(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let idp = match IdentityProviderRepo.find_by_id(&mut conn, id).await {
        Ok(Some(i)) => i,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("delete idp fetch error: {e}");
            return internal_error();
        }
    };
    match IdentityProviderRepo.delete(&mut conn, id).await {
        Ok(()) => {
            let audit = oidc_core::models::audit_event::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: Some(idp.realm_id),
                event_type: "identity_provider.deleted".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("identity_provider".to_string()),
                target_id: Some(idp.id),
                details: json!({"alias": idp.alias}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
                tracing::warn!("failed to write audit event: {e}");
            }
            Json(json!({"deleted": true})).into_response()
        }
        Err(e) => {
            tracing::error!("delete identity provider error: {e}");
            internal_error()
        }
    }
}
