use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use oidc_core::models::audit_event::ActorType;
use oidc_core::models::{ProtocolMapper, ProtocolMapperType, Scope};
use oidc_core::utils::generate_uuid_v7;
use oidc_repository::repositories::account_recovery_token_repo::AccountRecoveryTokenRepo;
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;
use oidc_repository::repositories::auth_code_repo::AuthCodeRepo;
use oidc_repository::repositories::authorization_service_repo::AuthorizationServiceRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::device_code_repo::DeviceCodeRepo;
use oidc_repository::repositories::email_verification_token_repo::EmailVerificationTokenRepo;
use oidc_repository::repositories::group_repo::GroupRepo;
use oidc_repository::repositories::group_role_repo::GroupRoleRepo;
use oidc_repository::repositories::par_repo::ParRepo;
use oidc_repository::repositories::password_reset_token_repo::PasswordResetTokenRepo;
use oidc_repository::repositories::protocol_mapper_repo::ProtocolMapperRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::realm_signing_keys_repo::RealmSigningKeysRepo;
use oidc_repository::repositories::role_composite_repo::RoleCompositeRepo;
use oidc_repository::repositories::role_repo::RoleRepo;
use oidc_repository::repositories::saml_repo::SamlRepo;
use oidc_repository::repositories::scope_repo::ScopeRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;

use crate::middleware::admin_auth::AdminAuth;
use crate::router::admin::{
    admin_or_forbidden, bad_request, conflict, connect, internal_error, not_found,
    realm_or_forbidden, scoped_realm,
};
use crate::state::AppState;

// ─── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct StatsQuery {
    realm_id: Option<Uuid>,
}

pub async fn stats_handler(
    State(state): State<AppState>,
    Query(query): Query<StatsQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let realm_id = match scoped_realm(&auth, query.realm_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let user_count = UserRepo
        .count(&mut conn, realm_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to count users: {e}");
            0
        });
    let client_count = ClientRepo
        .count(&mut conn, realm_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to count clients: {e}");
            0
        });
    let realm_count = if realm_id.is_some() {
        1
    } else {
        RealmRepo.count(&mut conn).await.unwrap_or_else(|e| {
            tracing::warn!("failed to count realms: {e}");
            0
        })
    };
    let session_count = SessionRepo
        .count(&mut conn, None, realm_id, Some(false))
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to count sessions: {e}");
            0
        });
    Json(json!({
        "users": user_count,
        "clients": client_count,
        "realms": realm_count,
        "active_sessions": session_count,
    }))
    .into_response()
}

// ─── Sessions ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SessionListQuery {
    user_id: Option<Uuid>,
    realm_id: Option<Uuid>,
    revoked: Option<bool>,
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

pub async fn list_sessions(
    State(state): State<AppState>,
    Query(query): Query<SessionListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let realm_id = match scoped_realm(&auth, query.realm_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let sessions = match SessionRepo
        .list(
            &mut conn,
            query.user_id,
            realm_id,
            query.revoked,
            query.limit,
            query.offset,
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("list sessions error: {e}");
            return internal_error();
        }
    };
    let total = SessionRepo
        .count(&mut conn, query.user_id, realm_id, query.revoked)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to count sessions: {e}");
            0
        });
    let rows: Vec<Value> = sessions
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id.to_string(),
                "user_id": s.user_id.map(|id| id.to_string()),
                "realm_id": s.realm_id.to_string(),
                "client_id": s.client_id.to_string(),
                "grant_type": s.grant_type,
                "scope": s.scope,
                "revoked": s.revoked,
                "family_revoked": s.family_revoked,
                "offline": s.offline_session,
                "expires_at": s.refresh_expires_at.unwrap_or(s.expires_at),
                "maximum_expires_at": s.offline_max_expires_at,
            })
        })
        .collect();
    Json(json!({"items": rows, "total": total})).into_response()
}

pub async fn revoke_session(
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
    let session = match SessionRepo.find_by_id(&mut conn, id).await {
        Ok(Some(session)) => session,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("find session for revocation error: {e}");
            return internal_error();
        }
    };
    let result = if let Some(family_id) = session.token_family_id {
        SessionRepo.revoke_family(&mut conn, family_id).await
    } else {
        SessionRepo.revoke(&mut conn, id).await
    };
    match result {
        Ok(()) => Json(json!({"revoked": true})).into_response(),
        Err(e) => {
            tracing::error!("revoke session error: {e}");
            internal_error()
        }
    }
}

// ─── Audit Events ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuditListQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
    event_type: Option<String>,
    actor_id: Option<String>,
    realm_id: Option<Uuid>,
}

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<AuditListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let realm_id = match scoped_realm(&auth, query.realm_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let event_type_filter = query.event_type.as_deref();
    let actor_id_filter: Option<Uuid> = query.actor_id.as_deref().and_then(|s| s.parse().ok());
    let actor_id_ref = actor_id_filter.as_ref();
    let total = match AuditEventRepo
        .count(
            &mut conn,
            realm_id,
            event_type_filter,
            actor_id_ref,
            None,
            None,
        )
        .await
    {
        Ok(t) => t,
        Err(err) => {
            tracing::error!("count audit events error: {err}");
            return internal_error();
        }
    };
    let events = match AuditEventRepo
        .list_recent(
            &mut conn,
            query.limit,
            query.offset,
            event_type_filter,
            actor_id_ref,
            realm_id,
            None,
            None,
        )
        .await
    {
        Ok(e) => e,
        Err(err) => {
            tracing::error!("list audit events error: {err}");
            return internal_error();
        }
    };
    let rows: Vec<Value> = events.into_iter().map(|e| json!({
        "id": e.id.to_string(),
        "realm_id": e.realm_id.map(|id| id.to_string()),
        "event_type": e.event_type,
        "actor_id": e.actor_id.map(|id| id.to_string()),
        "actor_type": match e.actor_type { ActorType::User => "user", ActorType::ApiKey => "api_key", ActorType::System => "system" },
        "target_type": e.target_type,
        "target_id": e.target_id.map(|id| id.to_string()),
        "details": e.details,
        "created_at": e.created_at.to_rfc3339(),
    })).collect();
    Json(json!({"items": rows, "total": total})).into_response()
}

// ─── Scopes ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ScopeListQuery {
    realm_id: Uuid,
}

pub async fn list_scopes(
    State(state): State<AppState>,
    Query(query): Query<ScopeListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Some(response) = realm_or_forbidden(&auth, query.realm_id) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let items = match ScopeRepo.list_by_realm(&mut conn, query.realm_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("list scopes error: {e}");
            return internal_error();
        }
    };
    Json(json!({
        "items": items.iter().map(|s| json!({
            "id": s.id.to_string(),
            "realm_id": s.realm_id.to_string(),
            "name": s.name,
            "description": s.description,
            "enabled": s.enabled,
        })).collect::<Vec<_>>()
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct CreateScopeRequest {
    realm_id: Uuid,
    name: String,
    description: Option<String>,
    enabled: Option<bool>,
}

pub async fn create_scope(
    State(state): State<AppState>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: CreateScopeRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    if let Some(response) = realm_or_forbidden(&auth, req.realm_id) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Ok(Some(_)) = ScopeRepo
        .find_by_name(&mut conn, req.realm_id, &req.name)
        .await
    {
        return conflict();
    }
    let scope = Scope {
        id: generate_uuid_v7(),
        realm_id: req.realm_id,
        name: req.name,
        description: req.description,
        enabled: req.enabled.unwrap_or(true),
    };
    match ScopeRepo.create(&mut conn, &scope).await {
        Ok(()) => Json(json!({
            "id": scope.id.to_string(),
            "realm_id": scope.realm_id.to_string(),
            "name": scope.name,
            "description": scope.description,
            "enabled": scope.enabled,
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("create scope error: {e}");
            internal_error()
        }
    }
}

pub async fn get_scope(
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
    match ScopeRepo.find_by_id(&mut conn, id).await {
        Ok(Some(s)) => Json(json!({
            "id": s.id.to_string(),
            "realm_id": s.realm_id.to_string(),
            "name": s.name,
            "description": s.description,
            "enabled": s.enabled,
        }))
        .into_response(),
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!("get scope error: {e}");
            internal_error()
        }
    }
}

#[derive(Deserialize)]
struct UpdateScopeRequest {
    name: Option<String>,
    description: Option<String>,
    enabled: Option<bool>,
}

pub async fn update_scope(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: UpdateScopeRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut scope = match ScopeRepo.find_by_id(&mut conn, id).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("update scope fetch error: {e}");
            return internal_error();
        }
    };
    if let Some(v) = req.name {
        scope.name = v;
    }
    if req.description.is_some() {
        scope.description = req.description;
    }
    if let Some(v) = req.enabled {
        scope.enabled = v;
    }
    match ScopeRepo.update(&mut conn, &scope).await {
        Ok(()) => Json(json!({"updated": true})).into_response(),
        Err(e) => {
            tracing::error!("update scope error: {e}");
            internal_error()
        }
    }
}

pub async fn delete_scope(
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
    match ScopeRepo.delete(&mut conn, id).await {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => {
            tracing::error!("delete scope error: {e}");
            internal_error()
        }
    }
}

fn protocol_mapper_json(mapper: &ProtocolMapper) -> Value {
    json!({
        "id": mapper.id.to_string(), "scope_id": mapper.scope_id.to_string(), "name": mapper.name,
        "mapper_type": mapper.mapper_type.as_str(), "claim_name": mapper.claim_name,
        "source": mapper.source, "claim_value": mapper.claim_value, "multivalued": mapper.multivalued,
        "add_to_access_token": mapper.add_to_access_token, "add_to_id_token": mapper.add_to_id_token,
        "add_to_userinfo": mapper.add_to_userinfo,
    })
}

#[derive(Deserialize)]
pub struct ProtocolMapperRequest {
    name: String,
    mapper_type: String,
    claim_name: Option<String>,
    source: Option<String>,
    claim_value: Option<Value>,
    #[serde(default)]
    multivalued: bool,
    #[serde(default = "default_true")]
    add_to_access_token: bool,
    #[serde(default = "default_true")]
    add_to_id_token: bool,
    #[serde(default = "default_true")]
    add_to_userinfo: bool,
}

fn default_true() -> bool {
    true
}

fn mapper_from_request(
    id: Uuid,
    scope_id: Uuid,
    req: ProtocolMapperRequest,
) -> Result<ProtocolMapper, oidc_core::OidcError> {
    let mapper = ProtocolMapper {
        id,
        scope_id,
        name: req.name,
        mapper_type: ProtocolMapperType::try_from(req.mapper_type.as_str())?,
        claim_name: req.claim_name,
        source: req.source,
        claim_value: req.claim_value,
        multivalued: req.multivalued,
        add_to_access_token: req.add_to_access_token,
        add_to_id_token: req.add_to_id_token,
        add_to_userinfo: req.add_to_userinfo,
    };
    mapper.validate()?;
    Ok(mapper)
}

pub async fn list_protocol_mappers(
    State(state): State<AppState>,
    axum::extract::Path(scope_id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    match ScopeRepo.find_by_id(&mut conn, scope_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(),
        Err(error) => {
            tracing::error!("protocol mapper scope lookup error: {error}");
            return internal_error();
        }
    }
    match ProtocolMapperRepo.list_by_scope(&mut conn, scope_id).await {
        Ok(items) => {
            Json(json!({"items": items.iter().map(protocol_mapper_json).collect::<Vec<_>>() }))
                .into_response()
        }
        Err(error) => {
            tracing::error!("list protocol mappers error: {error}");
            internal_error()
        }
    }
}

pub async fn create_protocol_mapper(
    State(state): State<AppState>,
    axum::extract::Path(scope_id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let req = match serde_json::from_str::<ProtocolMapperRequest>(&body) {
        Ok(req) => req,
        Err(_) => return bad_request(),
    };
    let mapper = match mapper_from_request(generate_uuid_v7(), scope_id, req) {
        Ok(mapper) => mapper,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    let scope = match ScopeRepo.find_by_id(&mut conn, scope_id).await {
        Ok(Some(scope)) => scope,
        Ok(None) => return not_found(),
        Err(error) => {
            tracing::error!("protocol mapper scope lookup error: {error}");
            return internal_error();
        }
    };
    if mapper.mapper_type == ProtocolMapperType::ClientRoles {
        match ClientRepo
            .find_by_client_id(&mut conn, mapper.source.as_deref().unwrap_or_default())
            .await
        {
            Ok(Some(client)) if client.realm_id == scope.realm_id => {}
            Ok(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        json!({"error":"client role source must identify a client in this realm"}),
                    ),
                )
                    .into_response();
            }
            Err(error) => {
                tracing::error!("protocol mapper client lookup error: {error}");
                return internal_error();
            }
        }
    }
    match ProtocolMapperRepo.create(&mut conn, &mapper).await {
        Ok(()) => Json(protocol_mapper_json(&mapper)).into_response(),
        Err(oidc_core::OidcError::Conflict(_)) => conflict(),
        Err(error) => {
            tracing::error!("create protocol mapper error: {error}");
            internal_error()
        }
    }
}

pub async fn update_protocol_mapper(
    State(state): State<AppState>,
    axum::extract::Path((scope_id, mapper_id)): axum::extract::Path<(Uuid, Uuid)>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let req = match serde_json::from_str::<ProtocolMapperRequest>(&body) {
        Ok(req) => req,
        Err(_) => return bad_request(),
    };
    let mapper = match mapper_from_request(mapper_id, scope_id, req) {
        Ok(mapper) => mapper,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    match ProtocolMapperRepo.find_by_id(&mut conn, mapper_id).await {
        Ok(Some(existing)) if existing.scope_id == scope_id => {}
        Ok(_) => return not_found(),
        Err(error) => {
            tracing::error!("protocol mapper lookup error: {error}");
            return internal_error();
        }
    }
    let scope = match ScopeRepo.find_by_id(&mut conn, scope_id).await {
        Ok(Some(scope)) => scope,
        Ok(None) => return not_found(),
        Err(error) => {
            tracing::error!("protocol mapper scope lookup error: {error}");
            return internal_error();
        }
    };
    if mapper.mapper_type == ProtocolMapperType::ClientRoles {
        match ClientRepo
            .find_by_client_id(&mut conn, mapper.source.as_deref().unwrap_or_default())
            .await
        {
            Ok(Some(client)) if client.realm_id == scope.realm_id => {}
            Ok(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        json!({"error":"client role source must identify a client in this realm"}),
                    ),
                )
                    .into_response();
            }
            Err(error) => {
                tracing::error!("protocol mapper client lookup error: {error}");
                return internal_error();
            }
        }
    }
    match ProtocolMapperRepo.update(&mut conn, &mapper).await {
        Ok(()) => Json(protocol_mapper_json(&mapper)).into_response(),
        Err(oidc_core::OidcError::Conflict(_)) => conflict(),
        Err(error) => {
            tracing::error!("update protocol mapper error: {error}");
            internal_error()
        }
    }
}

pub async fn delete_protocol_mapper(
    State(state): State<AppState>,
    axum::extract::Path((scope_id, mapper_id)): axum::extract::Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    match ProtocolMapperRepo.find_by_id(&mut conn, mapper_id).await {
        Ok(Some(existing)) if existing.scope_id == scope_id => {}
        Ok(_) => return not_found(),
        Err(error) => {
            tracing::error!("protocol mapper lookup error: {error}");
            return internal_error();
        }
    }
    match ProtocolMapperRepo.delete(&mut conn, mapper_id).await {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(error) => {
            tracing::error!("delete protocol mapper error: {error}");
            internal_error()
        }
    }
}

#[derive(Deserialize)]
pub struct ClientScopeRequest {
    scope_id: Uuid,
    assignment_type: String,
}

pub async fn list_client_scopes(
    State(state): State<AppState>,
    axum::extract::Path(client_id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if !matches!(
        ClientRepo.find_by_id(&mut conn, client_id).await,
        Ok(Some(_))
    ) {
        return not_found();
    }
    match ScopeRepo.list_by_client(&mut conn, client_id).await {
        Ok(items) => Json(json!({"items": items})).into_response(),
        Err(error) => {
            tracing::error!("list client scopes error: {error}");
            internal_error()
        }
    }
}

pub async fn assign_client_scope(
    State(state): State<AppState>,
    axum::extract::Path(client_id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let req = match serde_json::from_str::<ClientScopeRequest>(&body) {
        Ok(req) => req,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    let client = match ClientRepo.find_by_id(&mut conn, client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    let scope = match ScopeRepo.find_by_id(&mut conn, req.scope_id).await {
        Ok(Some(scope)) => scope,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if client.realm_id != scope.realm_id {
        return bad_request();
    }
    match ScopeRepo
        .assign_to_client(&mut conn, client_id, req.scope_id, &req.assignment_type)
        .await
    {
        Ok(()) => Json(json!({"assigned": true})).into_response(),
        Err(oidc_core::OidcError::InvalidInput(message)) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": message}))).into_response()
        }
        Err(error) => {
            tracing::error!("assign client scope error: {error}");
            internal_error()
        }
    }
}

pub async fn unassign_client_scope(
    State(state): State<AppState>,
    axum::extract::Path((client_id, scope_id)): axum::extract::Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    match ScopeRepo
        .unassign_from_client(&mut conn, client_id, scope_id)
        .await
    {
        Ok(()) => Json(json!({"removed": true})).into_response(),
        Err(error) => {
            tracing::error!("unassign client scope error: {error}");
            internal_error()
        }
    }
}

// ─── Roles CRUD ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RoleListQuery {
    realm_id: Option<Uuid>,
    search: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
}

pub async fn list_roles(
    State(state): State<AppState>,
    Query(query): Query<RoleListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let realm_id = match scoped_realm(&auth, query.realm_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let items = match RoleRepo
        .list(
            &mut conn,
            realm_id,
            query.search.as_deref(),
            query.limit,
            query.offset,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("list roles error: {e}");
            return internal_error();
        }
    };
    let total = RoleRepo
        .count(&mut conn, realm_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to count roles: {e}");
            0
        });
    let rows: Vec<Value> = items
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id.to_string(),
                "realm_id": r.realm_id.to_string(),
                "name": r.name,
                "description": r.description,
                "permissions": r.permissions,
                "client_id": r.client_id.map(|id| id.to_string()),
                "created_at": r.created_at.to_rfc3339(),
                "updated_at": r.updated_at.to_rfc3339(),
            })
        })
        .collect();
    Json(json!({"items": rows, "total": total})).into_response()
}

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    realm_id: Uuid,
    name: String,
    description: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    client_id: Option<Uuid>,
}

pub async fn create_role(State(state): State<AppState>, auth: AdminAuth, body: String) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: CreateRoleRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    if let Some(response) = realm_or_forbidden(&auth, req.realm_id) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Some(client_id) = req.client_id {
        match ClientRepo.find_by_id(&mut conn, client_id).await {
            Ok(Some(client)) if client.realm_id == req.realm_id => {}
            Ok(_) => return bad_request(),
            Err(error) => {
                tracing::error!("client role validation error: {error}");
                return internal_error();
            }
        }
    }
    let now = chrono::Utc::now();
    let role = oidc_core::models::Role {
        id: generate_uuid_v7(),
        realm_id: req.realm_id,
        name: req.name.clone(),
        description: req.description.clone(),
        permissions: req.permissions.clone(),
        created_at: now,
        updated_at: now,
        client_id: req.client_id,
    };
    if let Err(e) = role.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{e}")})),
        )
            .into_response();
    }
    let duplicate = match req.client_id {
        Some(client_id) => {
            RoleRepo
                .find_by_client_and_name(&mut conn, client_id, &req.name)
                .await
        }
        None => {
            RoleRepo
                .find_by_name(&mut conn, req.realm_id, &req.name)
                .await
        }
    };
    match duplicate {
        Ok(Some(_)) => return conflict(),
        Ok(None) => {}
        Err(error) => {
            tracing::error!("role duplicate check error: {error}");
            return internal_error();
        }
    }
    match RoleRepo.create(&mut conn, &role).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: Some(role.realm_id),
                event_type: "role.created".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("role".to_string()),
                target_id: Some(role.id),
                details: json!({"name": role.name}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
                tracing::warn!("failed to write audit event: {e}");
            }
            Json(json!({
                "id": role.id.to_string(),
                "realm_id": role.realm_id.to_string(),
                "name": role.name,
                "description": role.description,
                "permissions": role.permissions,
                "client_id": role.client_id.map(|id| id.to_string()),
            }))
            .into_response()
        }
        Err(oidc_core::OidcError::Conflict(_)) => conflict(),
        Err(e) => {
            tracing::error!("create role error: {e}");
            internal_error()
        }
    }
}

pub async fn get_role(
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
    match RoleRepo.find_by_id(&mut conn, id).await {
        Ok(Some(r)) => Json(json!({
            "id": r.id.to_string(),
            "realm_id": r.realm_id.to_string(),
            "name": r.name,
            "description": r.description,
            "permissions": r.permissions,
            "client_id": r.client_id.map(|id| id.to_string()),
            "created_at": r.created_at.to_rfc3339(),
            "updated_at": r.updated_at.to_rfc3339(),
        }))
        .into_response(),
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!("get role error: {e}");
            internal_error()
        }
    }
}

#[derive(Deserialize)]
pub struct CompositeRoleRequest {
    role_id: Uuid,
}

pub async fn list_role_composites(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    if !matches!(RoleRepo.find_by_id(&mut conn, id).await, Ok(Some(_))) {
        return not_found();
    }
    match RoleCompositeRepo.list_children(&mut conn, id).await {
        Ok(roles) => Json(json!({"items": roles.into_iter().map(|role| json!({
            "id": role.id.to_string(),
            "realm_id": role.realm_id.to_string(),
            "client_id": role.client_id.map(|value| value.to_string()),
            "name": role.name,
            "description": role.description,
        })).collect::<Vec<_>>() }))
        .into_response(),
        Err(error) => {
            tracing::error!("list composite roles error: {error}");
            internal_error()
        }
    }
}

pub async fn add_role_composite(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let req: CompositeRoleRequest = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    let parent = match RoleRepo.find_by_id(&mut conn, id).await {
        Ok(Some(role)) => role,
        Ok(None) => return not_found(),
        Err(error) => {
            tracing::error!("composite parent lookup error: {error}");
            return internal_error();
        }
    };
    let child = match RoleRepo.find_by_id(&mut conn, req.role_id).await {
        Ok(Some(role)) if role.realm_id == parent.realm_id => role,
        Ok(Some(_)) => return bad_request(),
        Ok(None) => return not_found(),
        Err(error) => {
            tracing::error!("composite child lookup error: {error}");
            return internal_error();
        }
    };
    match RoleCompositeRepo.add(&mut conn, id, child.id).await {
        Ok(()) => Json(json!({"added": true})).into_response(),
        Err(oidc_core::OidcError::InvalidInput(message)) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": message}))).into_response()
        }
        Err(error) => {
            tracing::error!("add composite role error: {error}");
            internal_error()
        }
    }
}

pub async fn remove_role_composite(
    State(state): State<AppState>,
    axum::extract::Path((id, child_id)): axum::extract::Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(conn) => conn,
        Err(response) => return response,
    };
    match RoleCompositeRepo.remove(&mut conn, id, child_id).await {
        Ok(()) => Json(json!({"removed": true})).into_response(),
        Err(error) => {
            tracing::error!("remove composite role error: {error}");
            internal_error()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    name: Option<String>,
    description: Option<String>,
    permissions: Option<Vec<String>>,
}

pub async fn update_role(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: UpdateRoleRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut role = match RoleRepo.find_by_id(&mut conn, id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("update role fetch error: {e}");
            return internal_error();
        }
    };
    if let Some(v) = req.name {
        role.name = v;
    }
    if req.description.is_some() {
        role.description = req.description;
    }
    if let Some(v) = req.permissions {
        role.permissions = v;
    }
    if let Err(e) = role.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{e}")})),
        )
            .into_response();
    }
    let duplicate = match role.client_id {
        Some(client_id) => {
            RoleRepo
                .find_by_client_and_name(&mut conn, client_id, &role.name)
                .await
        }
        None => {
            RoleRepo
                .find_by_name(&mut conn, role.realm_id, &role.name)
                .await
        }
    };
    match duplicate {
        Ok(Some(existing)) if existing.id != role.id => return conflict(),
        Ok(_) => {}
        Err(error) => {
            tracing::error!("role duplicate check error: {error}");
            return internal_error();
        }
    }
    match RoleRepo.update(&mut conn, &role).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: Some(role.realm_id),
                event_type: "role.updated".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("role".to_string()),
                target_id: Some(role.id),
                details: json!({"name": role.name}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
                tracing::warn!("failed to write audit event: {e}");
            }
            Json(json!({"updated": true})).into_response()
        }
        Err(oidc_core::OidcError::Conflict(_)) => conflict(),
        Err(e) => {
            tracing::error!("update role error: {e}");
            internal_error()
        }
    }
}

pub async fn delete_role(
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
    let role = match RoleRepo.find_by_id(&mut conn, id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("delete role fetch error: {e}");
            return internal_error();
        }
    };
    match RoleRepo.delete(&mut conn, id).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: Some(role.realm_id),
                event_type: "role.deleted".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("role".to_string()),
                target_id: Some(role.id),
                details: json!({"name": role.name}),
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
            tracing::error!("delete role error: {e}");
            internal_error()
        }
    }
}

// ─── Groups CRUD ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GroupListQuery {
    realm_id: Option<Uuid>,
    search: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
}

pub async fn list_groups(
    State(state): State<AppState>,
    Query(query): Query<GroupListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let realm_id = match scoped_realm(&auth, query.realm_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let items = match GroupRepo
        .list(
            &mut conn,
            realm_id,
            query.search.as_deref(),
            query.limit,
            query.offset,
        )
        .await
    {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("list groups error: {e}");
            return internal_error();
        }
    };
    let total = GroupRepo
        .count(&mut conn, realm_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to count groups: {e}");
            0
        });
    let rows: Vec<Value> = items
        .into_iter()
        .map(|g| {
            json!({
                "id": g.id.to_string(),
                "realm_id": g.realm_id.to_string(),
                "name": g.name,
                "description": g.description,
                "parent_id": g.parent_id.map(|p| p.to_string()),
                "created_at": g.created_at.to_rfc3339(),
                "updated_at": g.updated_at.to_rfc3339(),
            })
        })
        .collect();
    Json(json!({"items": rows, "total": total})).into_response()
}

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    realm_id: Uuid,
    name: String,
    description: Option<String>,
    parent_id: Option<Uuid>,
}

pub async fn create_group(
    State(state): State<AppState>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: CreateGroupRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    if let Some(response) = realm_or_forbidden(&auth, req.realm_id) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let now = chrono::Utc::now();
    let group = oidc_core::models::Group {
        id: generate_uuid_v7(),
        realm_id: req.realm_id,
        name: req.name.clone(),
        description: req.description.clone(),
        parent_id: req.parent_id,
        created_at: now,
        updated_at: now,
    };
    if let Err(e) = group.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{e}")})),
        )
            .into_response();
    }
    if let Ok(Some(_)) = GroupRepo
        .find_by_name(&mut conn, req.realm_id, &req.name)
        .await
    {
        return conflict();
    }
    match GroupRepo.create(&mut conn, &group).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: Some(group.realm_id),
                event_type: "group.created".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("group".to_string()),
                target_id: Some(group.id),
                details: json!({"name": group.name}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
                tracing::warn!("failed to write audit event: {e}");
            }
            Json(json!({
                "id": group.id.to_string(),
                "realm_id": group.realm_id.to_string(),
                "name": group.name,
                "description": group.description,
                "parent_id": group.parent_id.map(|p| p.to_string()),
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("create group error: {e}");
            internal_error()
        }
    }
}

pub async fn get_group(
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
    match GroupRepo.find_by_id(&mut conn, id).await {
        Ok(Some(g)) => Json(json!({
            "id": g.id.to_string(),
            "realm_id": g.realm_id.to_string(),
            "name": g.name,
            "description": g.description,
            "parent_id": g.parent_id.map(|p| p.to_string()),
            "created_at": g.created_at.to_rfc3339(),
            "updated_at": g.updated_at.to_rfc3339(),
        }))
        .into_response(),
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!("get group error: {e}");
            internal_error()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateGroupRequest {
    name: Option<String>,
    description: Option<String>,
    parent_id: Option<Option<Uuid>>,
}

pub async fn update_group(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: UpdateGroupRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut group = match GroupRepo.find_by_id(&mut conn, id).await {
        Ok(Some(g)) => g,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("update group fetch error: {e}");
            return internal_error();
        }
    };
    if let Some(v) = req.name {
        group.name = v;
    }
    if req.description.is_some() {
        group.description = req.description;
    }
    if let Some(v) = req.parent_id {
        group.parent_id = v;
    }
    if let Err(e) = group.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{e}")})),
        )
            .into_response();
    }
    match GroupRepo.update(&mut conn, &group).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: Some(group.realm_id),
                event_type: "group.updated".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("group".to_string()),
                target_id: Some(group.id),
                details: json!({"name": group.name}),
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
            tracing::error!("update group error: {e}");
            internal_error()
        }
    }
}

pub async fn delete_group(
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
    let group = match GroupRepo.find_by_id(&mut conn, id).await {
        Ok(Some(g)) => g,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("delete group fetch error: {e}");
            return internal_error();
        }
    };
    match GroupRepo.delete(&mut conn, id).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: Some(group.realm_id),
                event_type: "group.deleted".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("group".to_string()),
                target_id: Some(group.id),
                details: json!({"name": group.name}),
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
            tracing::error!("delete group error: {e}");
            internal_error()
        }
    }
}

// ─── Group-Role assignments ─────────────────────────────────────────────────────

pub async fn list_group_roles(
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
    let roles = match GroupRoleRepo.find_roles_by_group(&mut conn, id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("list group roles error: {e}");
            return internal_error();
        }
    };
    let rows: Vec<Value> = roles
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id.to_string(),
                "realm_id": r.realm_id.to_string(),
                "name": r.name,
                "description": r.description,
                "permissions": r.permissions,
                "client_id": r.client_id.map(|value| value.to_string()),
            })
        })
        .collect();
    Json(json!({"items": rows})).into_response()
}

#[derive(Deserialize)]
pub struct AssignRoleToGroupRequest {
    role_id: Uuid,
}

pub async fn assign_role_to_group(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: AssignRoleToGroupRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let group = match GroupRepo.find_by_id(&mut conn, id).await {
        Ok(Some(group)) => group,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    let role = match RoleRepo.find_by_id(&mut conn, req.role_id).await {
        Ok(Some(role)) => role,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if group.realm_id != role.realm_id {
        return bad_request();
    }
    match GroupRoleRepo.assign(&mut conn, id, req.role_id).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: None,
                event_type: "group.role_assigned".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("group".to_string()),
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
            tracing::error!("assign role to group error: {e}");
            internal_error()
        }
    }
}

pub async fn unassign_role_from_group(
    State(state): State<AppState>,
    axum::extract::Path((id, role_id)): axum::extract::Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match GroupRoleRepo.unassign(&mut conn, id, role_id).await {
        Ok(()) => {
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: None,
                event_type: "group.role_unassigned".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("group".to_string()),
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
            tracing::error!("unassign role from group error: {e}");
            internal_error()
        }
    }
}

// ─── Token Cleanup ─────────────────────────────────────────────────────────────

pub async fn cleanup_expired(State(state): State<AppState>, auth: AdminAuth) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let sessions_deleted = SessionRepo
        .cleanup_expired(&mut conn)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to cleanup expired sessions: {e}");
            0
        });
    let password_reset_deleted = PasswordResetTokenRepo
        .cleanup_expired(&mut conn)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to cleanup expired password reset tokens: {e}");
            0
        });
    let email_verification_deleted = EmailVerificationTokenRepo
        .cleanup_expired(&mut conn)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to cleanup expired email verification tokens: {e}");
            0
        });
    let account_recovery_deleted = AccountRecoveryTokenRepo
        .cleanup_expired(&mut conn)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to cleanup expired account recovery tokens: {e}");
            0
        });
    let device_codes_deleted = DeviceCodeRepo
        .cleanup_expired(&mut conn)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to cleanup expired device codes: {e}");
            0
        });
    let auth_codes_deleted = AuthCodeRepo
        .cleanup_expired(&mut conn)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to cleanup expired auth codes: {e}");
            0
        });
    let par_deleted = ParRepo
        .cleanup_expired(&mut conn)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to cleanup expired PARs: {e}");
            0
        });
    let authorization_grants_deleted = AuthorizationServiceRepo
        .cleanup_expired(&mut conn)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to cleanup expired authorization grants: {e}");
            0
        });
    let saml_entries_deleted = SamlRepo.cleanup(&mut conn).await.unwrap_or_else(|e| {
        tracing::warn!("failed to cleanup expired SAML state: {e}");
        0
    });
    let audit = oidc_core::models::AuditEvent {
        id: generate_uuid_v7(),
        realm_id: None,
        event_type: "maintenance.cleanup".to_string(),
        actor_id: Uuid::parse_str(&auth.subject).ok(),
        actor_type: if auth.is_api_key {
            ActorType::ApiKey
        } else {
            ActorType::User
        },
        target_type: None,
        target_id: None,
        details: json!({
            "sessions_deleted": sessions_deleted,
            "password_reset_deleted": password_reset_deleted,
            "email_verification_deleted": email_verification_deleted,
            "account_recovery_deleted": account_recovery_deleted,
            "device_codes_deleted": device_codes_deleted,
            "auth_codes_deleted": auth_codes_deleted,
            "par_deleted": par_deleted,
            "authorization_grants_deleted": authorization_grants_deleted,
            "saml_entries_deleted": saml_entries_deleted,
        }),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
        tracing::warn!("failed to write audit event: {e}");
    }
    Json(json!({
        "sessions_deleted": sessions_deleted,
        "password_reset_deleted": password_reset_deleted,
        "email_verification_deleted": email_verification_deleted,
        "account_recovery_deleted": account_recovery_deleted,
        "device_codes_deleted": device_codes_deleted,
        "auth_codes_deleted": auth_codes_deleted,
        "par_deleted": par_deleted,
        "authorization_grants_deleted": authorization_grants_deleted,
    }))
    .into_response()
}

pub async fn reencrypt_legacy_secrets(State(state): State<AppState>, auth: AdminAuth) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    let mut identity_provider_count = 0_u64;
    let mut realm_signing_key_count = 0_u64;

    let idp_rows = match conn
        .query("SELECT id, client_secret FROM identity_providers WHERE deleted_at IS NULL")
        .await
    {
        Ok(result) => result.into_rows(),
        Err(e) => {
            tracing::error!("query identity providers for re-encryption failed: {e}");
            return internal_error();
        }
    };

    for row in &idp_rows {
        let id = match row.get::<Uuid>(0) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!("skip identity provider row with unreadable id: {e}");
                continue;
            }
        };
        let client_secret = match row.get::<String>(1) {
            Ok(secret) => secret,
            Err(e) => {
                tracing::warn!("skip identity provider {id} with unreadable secret: {e}");
                continue;
            }
        };

        if state.decrypt_sensitive_value(&client_secret).is_ok() {
            continue;
        }

        let encrypted = match state.encrypt_sensitive_value(client_secret.as_bytes()) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!("failed to encrypt legacy identity provider secret for {id}: {e}");
                continue;
            }
        };

        if let Err(e) = conn
            .execute_params(
                "UPDATE identity_providers SET client_secret = $1 WHERE id = $2",
                &[&encrypted, &id],
            )
            .await
        {
            tracing::warn!("failed to update encrypted identity provider secret for {id}: {e}");
            continue;
        }
        identity_provider_count += 1;
    }

    let key_rows = match conn
        .query(
            "SELECT realm_id, rsa_private_pem, rsa_kid, rsa_public_n, rsa_public_e, ed25519_private_pem, ed25519_kid, ed25519_public_x, created_at, updated_at FROM realm_signing_keys",
        )
        .await
    {
        Ok(result) => result.into_rows(),
        Err(e) => {
            tracing::error!("query realm signing keys for re-encryption failed: {e}");
            return internal_error();
        }
    };

    for row in &key_rows {
        let realm_id = match row.get::<Uuid>(0) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!("skip unreadable realm signing key row id: {e}");
                continue;
            }
        };
        let rsa_private_pem = match row.get::<String>(1) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!("skip unreadable realm RSA key for {realm_id}: {e}");
                continue;
            }
        };
        let rsa_kid = match row.get::<String>(2) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!("skip unreadable realm RSA kid for {realm_id}: {e}");
                continue;
            }
        };
        let rsa_public_n = match row.get::<String>(3) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!("skip unreadable realm RSA n for {realm_id}: {e}");
                continue;
            }
        };
        let rsa_public_e = match row.get::<String>(4) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!("skip unreadable realm RSA e for {realm_id}: {e}");
                continue;
            }
        };
        let ed25519_private_pem = match row.get::<String>(5) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!("skip unreadable realm Ed25519 key for {realm_id}: {e}");
                continue;
            }
        };
        let ed25519_kid = match row.get::<String>(6) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!("skip unreadable realm Ed25519 kid for {realm_id}: {e}");
                continue;
            }
        };
        let ed25519_public_x = match row.get::<String>(7) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!("skip unreadable realm Ed25519 x for {realm_id}: {e}");
                continue;
            }
        };
        let created_at = match row.get::<chrono::DateTime<chrono::Utc>>(8) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!("skip unreadable realm key created_at for {realm_id}: {e}");
                continue;
            }
        };

        let rsa_already_encrypted = state.decrypt_sensitive_value(&rsa_private_pem).is_ok();
        let ed_already_encrypted = state.decrypt_sensitive_value(&ed25519_private_pem).is_ok();
        if rsa_already_encrypted && ed_already_encrypted {
            continue;
        }

        let updated = oidc_core::models::RealmSigningKeys {
            realm_id,
            rsa_private_pem: if rsa_already_encrypted {
                rsa_private_pem
            } else {
                match state.encrypt_sensitive_value(rsa_private_pem.as_bytes()) {
                    Ok(value) => value,
                    Err(e) => {
                        tracing::warn!(
                            "failed to encrypt legacy realm RSA key for {realm_id}: {e}"
                        );
                        continue;
                    }
                }
            },
            rsa_kid,
            rsa_public_n,
            rsa_public_e,
            ed25519_private_pem: if ed_already_encrypted {
                ed25519_private_pem
            } else {
                match state.encrypt_sensitive_value(ed25519_private_pem.as_bytes()) {
                    Ok(value) => value,
                    Err(e) => {
                        tracing::warn!(
                            "failed to encrypt legacy realm Ed25519 key for {realm_id}: {e}"
                        );
                        continue;
                    }
                }
            },
            ed25519_kid,
            ed25519_public_x,
            created_at,
            updated_at: chrono::Utc::now(),
        };

        if let Err(e) = RealmSigningKeysRepo.update(&mut conn, &updated).await {
            tracing::warn!(
                "failed to update encrypted realm keys for {}: {e}",
                updated.realm_id
            );
            continue;
        }
        realm_signing_key_count += 1;
    }

    let audit = oidc_core::models::AuditEvent {
        id: generate_uuid_v7(),
        realm_id: None,
        event_type: "maintenance.reencrypt_legacy_secrets".to_string(),
        actor_id: Uuid::parse_str(&auth.subject).ok(),
        actor_type: if auth.is_api_key {
            ActorType::ApiKey
        } else {
            ActorType::User
        },
        target_type: None,
        target_id: None,
        details: json!({
            "identity_providers_reencrypted": identity_provider_count,
            "realm_signing_keys_reencrypted": realm_signing_key_count,
        }),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    if let Err(e) = AuditEventRepo.create(&mut conn, &audit).await {
        tracing::warn!("failed to write re-encryption audit event: {e}");
    }

    Json(json!({
        "identity_providers_reencrypted": identity_provider_count,
        "realm_signing_keys_reencrypted": realm_signing_key_count,
    }))
    .into_response()
}
