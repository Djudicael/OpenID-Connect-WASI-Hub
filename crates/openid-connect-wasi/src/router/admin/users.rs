use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use oidc_core::models::audit_event::ActorType;
use oidc_core::models::account_recovery_token::AccountRecoveryToken;
use oidc_core::utils::{generate_uuid_v7, is_strong_password, is_valid_email, is_valid_username};
use oidc_repository::repositories::account_recovery_token_repo::AccountRecoveryTokenRepo;
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;
use oidc_repository::repositories::role_repo::RoleRepo;
use oidc_repository::repositories::user_group_repo::UserGroupRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::repositories::user_role_repo::UserRoleRepo;

use crate::middleware::admin_auth::AdminAuth;
use crate::router::admin::{admin_or_forbidden, connect, bad_request, conflict, internal_error, not_found};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ListQuery {
    realm_id: Option<Uuid>,
    search: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
}

fn default_limit() -> i64 { 20 }
fn default_offset() -> i64 { 0 }

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    let users = match UserRepo.list(&mut conn, query.realm_id, query.search.as_deref(), query.limit, query.offset).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("list users error: {e}");
            return internal_error();
        }
    };
    let total = UserRepo.count(&mut conn, query.realm_id).await.unwrap_or_else(|e| {
        tracing::warn!("failed to count users: {e}");
        0
    });
    let rows: Vec<Value> = users.into_iter().map(|u| json!({
        "id": u.id.to_string(),
        "realm_id": u.realm_id.to_string(),
        "email": u.email,
        "email_verified": u.email_verified,
        "username": u.username,
        "given_name": u.given_name,
        "family_name": u.family_name,
        "middle_name": u.middle_name,
        "nickname": u.nickname,
        "preferred_username": u.preferred_username,
        "profile": u.profile,
        "picture": u.picture,
        "website": u.website,
        "gender": u.gender,
        "birthdate": u.birthdate,
        "zoneinfo": u.zoneinfo,
        "phone_number": u.phone_number,
        "phone_number_verified": u.phone_number_verified,
        "street_address": u.street_address,
        "locality": u.locality,
        "region": u.region,
        "postal_code": u.postal_code,
        "country": u.country,
        "locale": u.locale,
        "attributes": u.attributes,
        "enabled": u.enabled,
        "updated_at": u.updated_at.to_rfc3339(),
    })).collect();
    Json(json!({"items": rows, "total": total})).into_response()
}

pub async fn get(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    match UserRepo.find_by_id(&mut conn, id).await {
        Ok(Some(u)) => Json(json!({
            "id": u.id.to_string(),
            "realm_id": u.realm_id.to_string(),
            "email": u.email,
            "email_verified": u.email_verified,
            "username": u.username,
            "given_name": u.given_name,
            "family_name": u.family_name,
            "middle_name": u.middle_name,
            "nickname": u.nickname,
            "preferred_username": u.preferred_username,
            "profile": u.profile,
            "picture": u.picture,
            "website": u.website,
            "gender": u.gender,
            "birthdate": u.birthdate,
            "zoneinfo": u.zoneinfo,
            "phone_number": u.phone_number,
            "phone_number_verified": u.phone_number_verified,
            "street_address": u.street_address,
            "locality": u.locality,
            "region": u.region,
            "postal_code": u.postal_code,
            "country": u.country,
            "locale": u.locale,
            "attributes": u.attributes,
            "enabled": u.enabled,
            "updated_at": u.updated_at.to_rfc3339(),
        })).into_response(),
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!("get user error: {e}");
            internal_error()
        }
    }
}

#[derive(Deserialize)]
pub struct CreateRequest {
    realm_id: Uuid,
    email: String,
    password: String,
    username: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    middle_name: Option<String>,
    nickname: Option<String>,
    preferred_username: Option<String>,
    profile: Option<String>,
    picture: Option<String>,
    website: Option<String>,
    gender: Option<String>,
    birthdate: Option<String>,
    zoneinfo: Option<String>,
    phone_number: Option<String>,
    phone_number_verified: Option<bool>,
    street_address: Option<String>,
    locality: Option<String>,
    region: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    locale: Option<String>,
    enabled: Option<bool>,
}

pub async fn create(State(state): State<AppState>, auth: AdminAuth, body: String) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let req: CreateRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    if !is_valid_email(&req.email) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_request", "error_description": "Invalid input"}))).into_response();
    }
    if !is_strong_password(&req.password) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_request", "error_description": "Invalid input"}))).into_response();
    }
    if let Some(ref username) = req.username {
        if !is_valid_username(username) {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_request", "error_description": "Invalid input"}))).into_response();
        }
    }
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    match UserRepo.find_by_email(&mut conn, req.realm_id, &req.email).await {
        Ok(Some(_)) => return conflict(),
        Ok(None) => {}
        Err(e) => {
            tracing::error!("create user duplicate check error: {e}");
            return internal_error();
        }
    }
    let password_hash = match state.hasher.hash(&req.password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("create user hash error: {e}");
            return internal_error();
        }
    };
    let user_id = generate_uuid_v7();
    let user = oidc_core::models::User {
        id: user_id,
        realm_id: req.realm_id,
        email: req.email,
        email_verified: false,
        username: req.username,
        password_hash: Some(password_hash),
        given_name: req.given_name,
        family_name: req.family_name,
        middle_name: req.middle_name,
        nickname: req.nickname,
        preferred_username: req.preferred_username,
        profile: req.profile,
        picture: req.picture,
        website: req.website,
        gender: req.gender,
        birthdate: req.birthdate,
        zoneinfo: req.zoneinfo,
        phone_number: req.phone_number,
        phone_number_verified: req.phone_number_verified,
        street_address: req.street_address,
        locality: req.locality,
        region: req.region,
        postal_code: req.postal_code,
        country: req.country,
        locale: req.locale.unwrap_or_else(|| "en".into()),
        attributes: serde_json::Value::Object(serde_json::Map::new()),
        enabled: req.enabled.unwrap_or(true),
        deleted_at: None,
        updated_at: chrono::Utc::now(),
    };
    match UserRepo.create(&mut conn, &user).await {
        Ok(()) => {}
        Err(e) => {
            tracing::error!("create user error: {e}");
            return internal_error();
        }
    }
    let actor_type = if auth.is_api_key { ActorType::ApiKey } else { ActorType::User };
    let actor_id = Uuid::parse_str(&auth.subject).ok();
    let audit = oidc_core::models::audit_event::AuditEvent {
        id: generate_uuid_v7(),
        realm_id: Some(user.realm_id),
        event_type: "user.created".to_string(),
        actor_id,
        actor_type,
        target_type: Some("user".to_string()),
        target_id: Some(user.id),
        details: json!({"email": user.email}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
        tracing::warn!("create user audit event error: {e}");
    }
    Json(json!({
        "id": user.id.to_string(),
        "realm_id": user.realm_id.to_string(),
        "email": user.email,
        "email_verified": user.email_verified,
        "username": user.username,
        "given_name": user.given_name,
        "family_name": user.family_name,
        "middle_name": user.middle_name,
        "nickname": user.nickname,
        "preferred_username": user.preferred_username,
        "profile": user.profile,
        "picture": user.picture,
        "website": user.website,
        "gender": user.gender,
        "birthdate": user.birthdate,
        "zoneinfo": user.zoneinfo,
        "phone_number": user.phone_number,
        "phone_number_verified": user.phone_number_verified,
        "street_address": user.street_address,
        "locality": user.locality,
        "region": user.region,
        "postal_code": user.postal_code,
        "country": user.country,
        "locale": user.locale,
        "attributes": user.attributes,
        "enabled": user.enabled,
    })).into_response()
}

#[derive(Deserialize)]
pub struct UpdateRequest {
    email: Option<String>,
    email_verified: Option<bool>,
    username: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    middle_name: Option<String>,
    nickname: Option<String>,
    preferred_username: Option<String>,
    profile: Option<String>,
    picture: Option<String>,
    website: Option<String>,
    gender: Option<String>,
    birthdate: Option<String>,
    zoneinfo: Option<String>,
    phone_number: Option<String>,
    phone_number_verified: Option<bool>,
    street_address: Option<String>,
    locality: Option<String>,
    region: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    locale: Option<String>,
    enabled: Option<bool>,
}

pub async fn update(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let req: UpdateRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    let mut user = match UserRepo.find_by_id(&mut conn, id).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("update user fetch error: {e}");
            return internal_error();
        }
    };
    if let Some(v) = req.email { user.email = v; }
    if let Some(v) = req.email_verified { user.email_verified = v; }
    if let Some(v) = req.username { user.username = Some(v); }
    if let Some(v) = req.given_name { user.given_name = Some(v); }
    if let Some(v) = req.family_name { user.family_name = Some(v); }
    if let Some(v) = req.middle_name { user.middle_name = Some(v); }
    if let Some(v) = req.nickname { user.nickname = Some(v); }
    if let Some(v) = req.preferred_username { user.preferred_username = Some(v); }
    if let Some(v) = req.profile { user.profile = Some(v); }
    if let Some(v) = req.picture { user.picture = Some(v); }
    if let Some(v) = req.website { user.website = Some(v); }
    if let Some(v) = req.gender { user.gender = Some(v); }
    if let Some(v) = req.birthdate { user.birthdate = Some(v); }
    if let Some(v) = req.zoneinfo { user.zoneinfo = Some(v); }
    if let Some(v) = req.phone_number { user.phone_number = Some(v); }
    if let Some(v) = req.phone_number_verified { user.phone_number_verified = Some(v); }
    if let Some(v) = req.street_address { user.street_address = Some(v); }
    if let Some(v) = req.locality { user.locality = Some(v); }
    if let Some(v) = req.region { user.region = Some(v); }
    if let Some(v) = req.postal_code { user.postal_code = Some(v); }
    if let Some(v) = req.country { user.country = Some(v); }
    if let Some(v) = req.locale { user.locale = v; }
    if let Some(v) = req.enabled { user.enabled = v; }
    match UserRepo.update(&mut conn, &user).await {
        Ok(()) => Json(json!({"updated": true})).into_response(),
        Err(e) => {
            tracing::error!("update user error: {e}");
            internal_error()
        }
    }
}

pub async fn delete(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    match UserRepo.delete(&mut conn, id).await {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => {
            tracing::error!("delete user error: {e}");
            internal_error()
        }
    }
}

// ─── User-Role assignments ─────────────────────────────────────────────────────

pub async fn list_roles(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    let roles = match RoleRepo.find_by_user_id(&mut conn, id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("list user roles error: {e}");
            return internal_error();
        }
    };
    let rows: Vec<Value> = roles.into_iter().map(|r| json!({
        "id": r.id.to_string(),
        "realm_id": r.realm_id.to_string(),
        "name": r.name,
        "description": r.description,
        "permissions": r.permissions,
    })).collect();
    Json(json!({"items": rows})).into_response()
}

#[derive(Deserialize)]
pub struct AssignRoleRequest {
    role_id: Uuid,
}

pub async fn assign_role(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let req: AssignRoleRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    match UserRoleRepo.assign(&mut conn, id, req.role_id).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: None,
                event_type: "user.role_assigned".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key { ActorType::ApiKey } else { ActorType::User },
                target_type: Some("user".to_string()),
                target_id: Some(id),
                details: json!({"role_id": req.role_id.to_string()}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
                tracing::warn!("failed to write audit event: {e}");
            }
            Json(json!({"assigned": true})).into_response()
        }
        Err(e) => {
            tracing::error!("assign role to user error: {e}");
            internal_error()
        }
    }
}

pub async fn unassign_role(
    State(state): State<AppState>,
    axum::extract::Path((id, role_id)): axum::extract::Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    match UserRoleRepo.unassign(&mut conn, id, role_id).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: None,
                event_type: "user.role_unassigned".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key { ActorType::ApiKey } else { ActorType::User },
                target_type: Some("user".to_string()),
                target_id: Some(id),
                details: json!({"role_id": role_id.to_string()}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
                tracing::warn!("failed to write audit event: {e}");
            }
            Json(json!({"unassigned": true})).into_response()
        }
        Err(e) => {
            tracing::error!("unassign role from user error: {e}");
            internal_error()
        }
    }
}

// ─── User-Group assignments ─────────────────────────────────────────────────────

pub async fn list_groups(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    let groups = match UserGroupRepo.find_groups_by_user(&mut conn, id).await {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("list user groups error: {e}");
            return internal_error();
        }
    };
    let rows: Vec<Value> = groups.into_iter().map(|g| json!({
        "id": g.id.to_string(),
        "realm_id": g.realm_id.to_string(),
        "name": g.name,
        "description": g.description,
        "parent_id": g.parent_id.map(|p| p.to_string()),
    })).collect();
    Json(json!({"items": rows})).into_response()
}

#[derive(Deserialize)]
pub struct AssignGroupRequest {
    group_id: Uuid,
}

pub async fn assign_group(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let req: AssignGroupRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    match UserGroupRepo.assign(&mut conn, id, req.group_id).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: None,
                event_type: "user.group_assigned".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key { ActorType::ApiKey } else { ActorType::User },
                target_type: Some("user".to_string()),
                target_id: Some(id),
                details: json!({"group_id": req.group_id.to_string()}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
                tracing::warn!("failed to write audit event: {e}");
            }
            Json(json!({"assigned": true})).into_response()
        }
        Err(e) => {
            tracing::error!("assign group to user error: {e}");
            internal_error()
        }
    }
}

pub async fn unassign_group(
    State(state): State<AppState>,
    axum::extract::Path((id, group_id)): axum::extract::Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    match UserGroupRepo.unassign(&mut conn, id, group_id).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: None,
                event_type: "user.group_unassigned".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key { ActorType::ApiKey } else { ActorType::User },
                target_type: Some("user".to_string()),
                target_id: Some(id),
                details: json!({"group_id": group_id.to_string()}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
                tracing::warn!("failed to write audit event: {e}");
            }
            Json(json!({"unassigned": true})).into_response()
        }
        Err(e) => {
            tracing::error!("unassign group from user error: {e}");
            internal_error()
        }
    }
}

// ─── Account Recovery ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AccountRecoveryRequest {
    creator_ip: Option<String>,
}

pub async fn initiate_account_recovery(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let req: AccountRecoveryRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => AccountRecoveryRequest { creator_ip: None },
    };
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    let user = match UserRepo.find_by_id(&mut conn, id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({"error": "user not found"}))).into_response(),
        Err(e) => {
            tracing::error!("account recovery user fetch error: {e}");
            return internal_error();
        }
    };
    let admin_uuid = match Uuid::parse_str(&auth.subject) {
        Ok(u) => u,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "invalid admin identity"}))).into_response(),
    };
    let (token_entity, raw_token) = match AccountRecoveryToken::new(user.id, user.realm_id, admin_uuid, req.creator_ip) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("account recovery token creation error: {e}");
            return internal_error();
        }
    };
    match AccountRecoveryTokenRepo.create(&mut conn, &token_entity).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: Some(user.realm_id),
                event_type: "user.account_recovery_initiated".to_string(),
                actor_id: Some(admin_uuid),
                actor_type: if auth.is_api_key { ActorType::ApiKey } else { ActorType::User },
                target_type: Some("user".to_string()),
                target_id: Some(user.id),
                details: json!({}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
                tracing::warn!("failed to write audit event: {e}");
            }
            Json(json!({
                "recovery_token": raw_token,
                "user_id": user.id.to_string(),
                "expires_at": token_entity.expires_at.to_rfc3339(),
            })).into_response()
        }
        Err(e) => {
            tracing::error!("account recovery token store error: {e}");
            internal_error()
        }
    }
}

// ─── User Impersonation ────────────────────────────────────────────────────────

pub async fn impersonate(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) { return r; }
    let mut conn = match connect(&state).await { Ok(c) => c, Err(r) => return r };
    let user = match UserRepo.find_by_id(&mut conn, id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({"error": "user not found"}))).into_response(),
        Err(e) => {
            tracing::error!("impersonate user fetch error: {e}");
            return internal_error();
        }
    };
    if !user.enabled {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "user is disabled"}))).into_response();
    }
    let sub = user.id.to_string();
    let act_sub = auth.subject.clone();
    let scope = "openid profile email";
    let audience = vec!["account".to_string()];
    let token = match state.token_service.encode_access_token_with_act(&sub, &act_sub, scope, &audience, 300) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("impersonate token encode error: {e}");
            return internal_error();
        }
    };
    let audit = oidc_core::models::AuditEvent {
        id: generate_uuid_v7(),
        realm_id: Some(user.realm_id),
        event_type: "user.impersonated".to_string(),
        actor_id: Uuid::parse_str(&auth.subject).ok(),
        actor_type: if auth.is_api_key { ActorType::ApiKey } else { ActorType::User },
        target_type: Some("user".to_string()),
        target_id: Some(user.id),
        details: json!({"impersonated_user_id": user.id.to_string(), "impersonated_by": auth.subject}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
        tracing::warn!("failed to write audit event: {e}");
    }
    Json(json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 300,
        "impersonated_user_id": user.id.to_string(),
        "impersonated_by": auth.subject,
    })).into_response()
}
