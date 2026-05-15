//! Admin API routes for the management UI.

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use oidc_core::models::ClientType;
use oidc_core::models::Scope;
use oidc_core::models::audit_event::ActorType;

use oidc_core::utils::{
    generate_opaque_token, generate_uuid_v7, is_strong_password, is_valid_email, is_valid_username,
};
use oidc_repository::Connection;
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::realm_signing_keys_repo::RealmSigningKeysRepo;
use oidc_repository::repositories::scope_repo::ScopeRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;

use crate::middleware::admin_auth::AdminAuth;
use crate::state::AppState;

/// Build the admin sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        // Admin UI SPA fallback — serves index.html for all non-API routes
        .route("/admin", get(admin_index_handler))
        .route("/admin/", get(admin_index_handler))
        .route("/admin/{*path}", get(admin_index_handler))
        // Stats
        .route("/api/stats", get(stats_handler))
        // Users
        .route("/api/users", get(list_users))
        .route("/api/users", post(create_user))
        .route("/api/users/{id}", get(get_user))
        .route("/api/users/{id}", put(update_user))
        .route("/api/users/{id}", delete(delete_user))
        // Clients
        .route("/api/clients", get(list_clients))
        .route("/api/clients", post(create_client))
        .route("/api/clients/{id}", get(get_client))
        .route("/api/clients/{id}", put(update_client))
        .route("/api/clients/{id}", delete(delete_client))
        // Realms
        .route("/api/realms", get(list_realms))
        .route("/api/realms", post(create_realm))
        .route("/api/realms/{id}", get(get_realm))
        .route("/api/realms/{id}", put(update_realm))
        .route("/api/realms/{id}", delete(delete_realm))
        // Sessions
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{id}/revoke", post(revoke_session))
        // Audit
        .route("/api/audit/events", get(list_audit_events))
        // Scopes
        .route("/api/scopes", get(list_scopes))
        .route("/api/scopes", post(create_scope))
        .route("/api/scopes/{id}", get(get_scope))
        .route("/api/scopes/{id}", put(update_scope))
        .route("/api/scopes/{id}", delete(delete_scope))
}

async fn admin_index_handler(
    _path: axum::extract::Path<String>,
) -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../../../../front/admin/index.html"))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn admin_or_forbidden(_auth: &AdminAuth) -> Option<Response> {
    // Scope check is now performed during AdminAuth extraction.
    // If extraction succeeded, the caller is already verified as admin.
    None
}

async fn connect(state: &AppState) -> Result<Connection, Response> {
    match wasi_pg_client::Connection::connect(&state.db_config).await {
        Ok(c) => Ok(Connection::from_pg_client(c)),
        Err(e) => {
            tracing::error!("db connect error: {e}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response())
        }
    }
}

// ─── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct StatsQuery {
    realm_id: Option<Uuid>,
}

async fn stats_handler(
    State(state): State<AppState>,
    Query(query): Query<StatsQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }

    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    let user_count = UserRepo.count(&mut conn, query.realm_id).await.unwrap_or(0);
    let client_count = ClientRepo
        .count(&mut conn, query.realm_id)
        .await
        .unwrap_or(0);
    let realm_count = RealmRepo.count(&mut conn).await.unwrap_or(0);
    let session_count = SessionRepo
        .count(&mut conn, None, query.realm_id, Some(false))
        .await
        .unwrap_or(0);

    Json(json!({
        "users": user_count,
        "clients": client_count,
        "realms": realm_count,
        "active_sessions": session_count,
    }))
    .into_response()
}

// ─── Users ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ListQuery {
    realm_id: Option<Uuid>,
    search: Option<String>,
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

async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }

    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    let users = match UserRepo
        .list(
            &mut conn,
            query.realm_id,
            query.search.as_deref(),
            query.limit,
            query.offset,
        )
        .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("list users error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    let total = UserRepo.count(&mut conn, query.realm_id).await.unwrap_or(0);

    let rows: Vec<Value> = users
        .into_iter()
        .map(|u| {
            json!({
                "id": u.id.to_string(),
                "realm_id": u.realm_id.to_string(),
                "email": u.email,
                "email_verified": u.email_verified,
                "username": u.username,
                "given_name": u.given_name,
                "family_name": u.family_name,
                "enabled": u.enabled,
            })
        })
        .collect();

    Json(json!({"items": rows, "total": total})).into_response()
}

async fn get_user(
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

    match UserRepo.find_by_id(&mut conn, id).await {
        Ok(Some(u)) => Json(json!({
            "id": u.id.to_string(),
            "realm_id": u.realm_id.to_string(),
            "email": u.email,
            "email_verified": u.email_verified,
            "username": u.username,
            "given_name": u.given_name,
            "family_name": u.family_name,
            "enabled": u.enabled,
        }))
        .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
        Err(e) => {
            tracing::error!("get user error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    email: Option<String>,
    email_verified: Option<bool>,
    username: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    enabled: Option<bool>,
}

async fn update_user(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }

    let req: UpdateUserRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "bad_request"})),
            )
                .into_response();
        }
    };

    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    let mut user = match UserRepo.find_by_id(&mut conn, id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
        }
        Err(e) => {
            tracing::error!("update user fetch error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    if let Some(v) = req.email {
        user.email = v;
    }
    if let Some(v) = req.email_verified {
        user.email_verified = v;
    }
    if let Some(v) = req.username {
        user.username = Some(v);
    }
    if let Some(v) = req.given_name {
        user.given_name = Some(v);
    }
    if let Some(v) = req.family_name {
        user.family_name = Some(v);
    }
    if let Some(v) = req.enabled {
        user.enabled = v;
    }

    match UserRepo.update(&mut conn, &user).await {
        Ok(()) => Json(json!({"updated": true})).into_response(),
        Err(e) => {
            tracing::error!("update user error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn delete_user(
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

    match UserRepo.delete(&mut conn, id).await {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => {
            tracing::error!("delete user error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

// ─── Clients ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ClientListQuery {
    realm_id: Option<Uuid>,
    search: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
}

async fn list_clients(
    State(state): State<AppState>,
    Query(query): Query<ClientListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }

    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    let clients = match ClientRepo
        .list(
            &mut conn,
            query.realm_id,
            query.search.as_deref(),
            query.limit,
            query.offset,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("list clients error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    let total = ClientRepo
        .count(&mut conn, query.realm_id)
        .await
        .unwrap_or(0);

    let rows: Vec<Value> = clients
        .into_iter()
        .map(|c| {
            json!({
                "id": c.id.to_string(),
                "realm_id": c.realm_id.to_string(),
                "client_id": c.client_id,
                "client_type": match c.client_type { ClientType::Confidential => "confidential", ClientType::Public => "public" },
                "name": c.name,
                "redirect_uris": c.redirect_uris,
                "allowed_scopes": c.allowed_scopes,
                "allowed_grant_types": c.allowed_grant_types,
                "pkce_required": c.pkce_required,
                "enabled": c.enabled,
                "subject_type": c.subject_type,
                "sector_identifier_uri": c.sector_identifier_uri,
            })
        })
        .collect();

    Json(json!({"items": rows, "total": total})).into_response()
}

async fn get_client(
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

    match ClientRepo.find_by_id(&mut conn, id).await {
        Ok(Some(c)) => Json(json!({
            "id": c.id.to_string(),
            "realm_id": c.realm_id.to_string(),
            "client_id": c.client_id,
            "client_type": match c.client_type { ClientType::Confidential => "confidential", ClientType::Public => "public" },
            "name": c.name,
            "redirect_uris": c.redirect_uris,
            "allowed_scopes": c.allowed_scopes,
            "allowed_grant_types": c.allowed_grant_types,
            "pkce_required": c.pkce_required,
            "enabled": c.enabled,
            "subject_type": c.subject_type,
            "sector_identifier_uri": c.sector_identifier_uri,
        }))
        .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
        Err(e) => {
            tracing::error!("get client error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct UpdateClientRequest {
    name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
    allowed_grant_types: Option<Vec<String>>,
    pkce_required: Option<bool>,
    enabled: Option<bool>,
    subject_type: Option<String>,
    sector_identifier_uri: Option<String>,
}

async fn update_client(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }

    let req: UpdateClientRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "bad_request"})),
            )
                .into_response();
        }
    };

    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    let mut client = match ClientRepo.find_by_id(&mut conn, id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
        }
        Err(e) => {
            tracing::error!("update client fetch error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    if let Some(v) = req.name {
        client.name = v;
    }
    if let Some(v) = req.redirect_uris {
        client.redirect_uris = v;
    }
    if let Some(v) = req.allowed_scopes {
        client.allowed_scopes = v;
    }
    if let Some(v) = req.allowed_grant_types {
        client.allowed_grant_types = v;
    }
    if let Some(v) = req.pkce_required {
        client.pkce_required = v;
    }
    if let Some(v) = req.enabled {
        client.enabled = v;
    }
    if let Some(v) = req.subject_type {
        client.subject_type = v;
    }
    if let Some(v) = req.sector_identifier_uri {
        client.sector_identifier_uri = Some(v);
    }

    match ClientRepo.update(&mut conn, &client).await {
        Ok(()) => Json(json!({"updated": true})).into_response(),
        Err(e) => {
            tracing::error!("update client error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn delete_client(
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

    match ClientRepo.delete(&mut conn, id).await {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => {
            tracing::error!("delete client error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

// ─── Realms ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RealmListQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
}

async fn list_realms(
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    let total = RealmRepo.count(&mut conn).await.unwrap_or(0);

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

async fn get_realm(
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
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
        Err(e) => {
            tracing::error!("get realm error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct UpdateRealmRequest {
    name: Option<String>,
    display_name: Option<String>,
    enabled: Option<bool>,
    config: Option<Value>,
}

async fn update_realm(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }

    let req: UpdateRealmRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "bad_request"})),
            )
                .into_response();
        }
    };

    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    let mut realm = match RealmRepo.find_by_id(&mut conn, id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
        }
        Err(e) => {
            tracing::error!("update realm fetch error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
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
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn delete_realm(
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

    // Hard-delete signing keys before soft-deleting the realm
    if let Err(e) = RealmSigningKeysRepo.delete_by_realm_id(&mut conn, id).await {
        tracing::warn!("delete realm signing keys error: {e}");
    }

    match RealmRepo.delete(&mut conn, id).await {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => {
            tracing::error!("delete realm error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

// ─── Sessions ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SessionListQuery {
    user_id: Option<Uuid>,
    realm_id: Option<Uuid>,
    revoked: Option<bool>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
}

async fn list_sessions(
    State(state): State<AppState>,
    Query(query): Query<SessionListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }

    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    let sessions = match SessionRepo
        .list(
            &mut conn,
            query.user_id,
            query.realm_id,
            query.revoked,
            query.limit,
            query.offset,
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("list sessions error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    let total = SessionRepo
        .count(&mut conn, query.user_id, query.realm_id, query.revoked)
        .await
        .unwrap_or(0);

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
            })
        })
        .collect();

    Json(json!({"items": rows, "total": total})).into_response()
}

async fn revoke_session(
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

    match SessionRepo.revoke(&mut conn, id).await {
        Ok(()) => Json(json!({"revoked": true})).into_response(),
        Err(e) => {
            tracing::error!("revoke session error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

// ─── Audit ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AuditListQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
    event_type: Option<String>,
    actor_id: Option<String>,
}

async fn list_audit_events(
    State(state): State<AppState>,
    Query(query): Query<AuditListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }

    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    let event_type_filter = query.event_type.as_deref();
    let actor_id_filter: Option<Uuid> = query.actor_id.as_deref().and_then(|s| s.parse().ok());
    let actor_id_ref = actor_id_filter.as_ref();

    let total = match AuditEventRepo
        .count(&mut conn, None, event_type_filter, actor_id_ref, None, None)
        .await
    {
        Ok(t) => t,
        Err(err) => {
            tracing::error!("count audit events error: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    let events = match AuditEventRepo
        .list_recent(
            &mut conn,
            query.limit,
            query.offset,
            event_type_filter,
            actor_id_ref,
            None,
            None,
        )
        .await
    {
        Ok(e) => e,
        Err(err) => {
            tracing::error!("list audit events error: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    let rows: Vec<Value> = events
        .into_iter()
        .map(|e| {
            json!({
                "id": e.id.to_string(),
                "realm_id": e.realm_id.map(|id| id.to_string()),
                "event_type": e.event_type,
                "actor_id": e.actor_id.map(|id| id.to_string()),
                "actor_type": match e.actor_type { ActorType::User => "user", ActorType::ApiKey => "api_key", ActorType::System => "system" },
                "target_type": e.target_type,
                "target_id": e.target_id.map(|id| id.to_string()),
                "details": e.details,
                "created_at": e.created_at.to_rfc3339(),
            })
        })
        .collect();

    Json(json!({"items": rows, "total": total})).into_response()
}

// ─── Create Handlers ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateUserRequest {
    realm_id: Uuid,
    email: String,
    password: String,
    username: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    enabled: Option<bool>,
}

async fn create_user(State(state): State<AppState>, auth: AdminAuth, body: String) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }

    let req: CreateUserRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "bad_request"})),
            )
                .into_response();
        }
    };

    // --- Input validation ---
    if !is_valid_email(&req.email) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_request", "error_description": "Invalid input"})),
        )
            .into_response();
    }
    if !is_strong_password(&req.password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_request", "error_description": "Invalid input"})),
        )
            .into_response();
    }
    if let Some(ref username) = req.username {
        if !is_valid_username(username) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_request", "error_description": "Invalid input"})),
            )
                .into_response();
        }
    }

    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    // Check for duplicate email in the realm
    match UserRepo
        .find_by_email(&mut conn, req.realm_id, &req.email)
        .await
    {
        Ok(Some(_)) => {
            return (StatusCode::CONFLICT, Json(json!({"error": "duplicate"}))).into_response();
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("create user duplicate check error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    }

    // Hash the password
    let password_hash = match state.hasher.hash(&req.password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("create user hash error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
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
        locale: "en".into(),
        attributes: serde_json::Value::Object(serde_json::Map::new()),
        enabled: req.enabled.unwrap_or(true),
        deleted_at: None,
        updated_at: chrono::Utc::now(),
    };

    match UserRepo.create(&mut conn, &user).await {
        Ok(()) => {}
        Err(e) => {
            tracing::error!("create user error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    }

    // Audit event
    let actor_type = if auth.is_api_key {
        ActorType::ApiKey
    } else {
        ActorType::User
    };
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
        "enabled": user.enabled,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct CreateClientRequest {
    realm_id: Uuid,
    client_id: String,
    client_type: Option<String>,
    client_secret: Option<String>,
    name: String,
    redirect_uris: Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
    allowed_grant_types: Option<Vec<String>>,
    pkce_required: Option<bool>,
    enabled: Option<bool>,
    subject_type: Option<String>,
    sector_identifier_uri: Option<String>,
}

async fn create_client(State(state): State<AppState>, auth: AdminAuth, body: String) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }

    let req: CreateClientRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "bad_request"})),
            )
                .into_response();
        }
    };

    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    // Check for duplicate client_id
    match ClientRepo
        .find_by_client_id(&mut conn, &req.client_id)
        .await
    {
        Ok(Some(_)) => {
            return (StatusCode::CONFLICT, Json(json!({"error": "duplicate"}))).into_response();
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("create client duplicate check error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    }

    // Determine client type
    let client_type = match req.client_type.as_deref() {
        Some("public") => ClientType::Public,
        _ => ClientType::Confidential, // default to confidential
    };

    // Handle client secret
    let (client_secret_hash, plain_secret) = match client_type {
        ClientType::Confidential => {
            let plain = req
                .client_secret
                .unwrap_or_else(|| generate_opaque_token().unwrap_or_default());
            let hash = match state.hasher.hash(&plain) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("create client hash error: {e}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "internal"})),
                    )
                        .into_response();
                }
            };
            (Some(hash), Some(plain))
        }
        ClientType::Public => (None, None),
    };

    let id = generate_uuid_v7();
    let redirect_uris = req.redirect_uris.unwrap_or_default();
    let allowed_scopes = req
        .allowed_scopes
        .unwrap_or_else(|| vec!["openid".to_string()]);
    let allowed_grant_types = req
        .allowed_grant_types
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);
    let pkce_required = req.pkce_required.unwrap_or(true);
    let enabled = req.enabled.unwrap_or(true);

    let client = oidc_core::models::Client {
        id,
        realm_id: req.realm_id,
        client_id: req.client_id,
        client_type,
        client_secret_hash,
        name: req.name,
        redirect_uris,
        allowed_scopes,
        allowed_grant_types,
        pkce_required,
        enabled,
        deleted_at: None,
        token_endpoint_auth_method: match client_type {
            oidc_core::models::ClientType::Confidential => "client_secret_basic".into(),
            oidc_core::models::ClientType::Public => "none".into(),
        },
        jwks_uri: None,
        jwks: None,
        request_uris: vec![],
        client_secret_encrypted: None,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        subject_type: req.subject_type.unwrap_or_else(|| "public".into()),
        sector_identifier_uri: req.sector_identifier_uri,
        response_modes: vec!["query".to_string(), "fragment".to_string()],
        id_token_encrypted_response_alg: None,
        id_token_encrypted_response_enc: None,
        id_token_encryption_key_encrypted: None,
        id_token_encryption_key_pem: None,
    };

    match ClientRepo.create(&mut conn, &client).await {
        Ok(()) => {}
        Err(e) => {
            tracing::error!("create client error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    }

    // Build response — include client_secret only for confidential clients
    let mut resp = json!({
        "id": client.id.to_string(),
        "realm_id": client.realm_id.to_string(),
        "client_id": client.client_id,
        "client_type": match client.client_type { ClientType::Confidential => "confidential", ClientType::Public => "public" },
        "name": client.name,
        "redirect_uris": client.redirect_uris,
        "allowed_scopes": client.allowed_scopes,
        "allowed_grant_types": client.allowed_grant_types,
        "pkce_required": client.pkce_required,
        "enabled": client.enabled,
        "subject_type": client.subject_type,
        "sector_identifier_uri": client.sector_identifier_uri,
    });
    if let Some(secret) = plain_secret {
        resp["client_secret"] = json!(secret);
    }

    Json(resp).into_response()
}

#[derive(Deserialize)]
struct CreateRealmRequest {
    name: String,
    display_name: String,
    enabled: Option<bool>,
    config: Option<Value>,
}

async fn create_realm(State(state): State<AppState>, auth: AdminAuth, body: String) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }

    let req: CreateRealmRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "bad_request"})),
            )
                .into_response();
        }
    };

    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    // Check for duplicate name
    match RealmRepo.find_by_name(&mut conn, &req.name).await {
        Ok(Some(_)) => {
            return (StatusCode::CONFLICT, Json(json!({"error": "duplicate"}))).into_response();
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("create realm duplicate check error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    }

    // Generate and store per-realm signing keys
    let keys = match oidc_oidc::tokens::generate_realm_keys(realm.id) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("generate realm keys error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    if let Err(e) = RealmSigningKeysRepo.create(&mut conn, &keys).await {
        tracing::error!("store realm keys error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "internal"})),
        )
            .into_response();
    }

    // Audit event
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

// ─── Scopes ───────────────────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ScopeListQuery {
    realm_id: Uuid,
}

async fn list_scopes(
    State(state): State<AppState>,
    Query(query): Query<ScopeListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let items = match ScopeRepo.list_by_realm(&mut conn, query.realm_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("list scopes error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    Json(json!({
        "items": items
            .iter()
            .map(|s| json!({
                "id": s.id.to_string(),
                "realm_id": s.realm_id.to_string(),
                "name": s.name,
                "description": s.description,
                "enabled": s.enabled,
            }))
            .collect::<Vec<_>>()
    }))
    .into_response()
}

#[derive(Deserialize)]
struct CreateScopeRequest {
    realm_id: Uuid,
    name: String,
    description: Option<String>,
    enabled: Option<bool>,
}

async fn create_scope(State(state): State<AppState>, auth: AdminAuth, body: String) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: CreateScopeRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "bad_request"})),
            )
                .into_response();
        }
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // Check for duplicate name in realm
    if let Ok(Some(_)) = ScopeRepo
        .find_by_name(&mut conn, req.realm_id, &req.name)
        .await
    {
        return (StatusCode::CONFLICT, Json(json!({"error": "duplicate"}))).into_response();
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
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn get_scope(
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
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
        Err(e) => {
            tracing::error!("get scope error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct UpdateScopeRequest {
    name: Option<String>,
    description: Option<String>,
    enabled: Option<bool>,
}

async fn update_scope(
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
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "bad_request"})),
            )
                .into_response();
        }
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut scope = match ScopeRepo.find_by_id(&mut conn, id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
        }
        Err(e) => {
            tracing::error!("update scope fetch error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
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
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn delete_scope(
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
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}
