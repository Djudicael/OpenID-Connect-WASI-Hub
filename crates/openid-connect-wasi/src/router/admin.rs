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
use oidc_core::models::audit_event::ActorType;
use oidc_repository::Connection;
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
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
        .route("/api/users/{id}", get(get_user))
        .route("/api/users/{id}", put(update_user))
        .route("/api/users/{id}", delete(delete_user))
        // Clients
        .route("/api/clients", get(list_clients))
        .route("/api/clients/{id}", get(get_client))
        .route("/api/clients/{id}", put(update_client))
        .route("/api/clients/{id}", delete(delete_client))
        // Realms
        .route("/api/realms", get(list_realms))
        .route("/api/realms/{id}", get(get_realm))
        .route("/api/realms/{id}", put(update_realm))
        .route("/api/realms/{id}", delete(delete_realm))
        // Sessions
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{id}/revoke", post(revoke_session))
        // Audit
        .route("/api/audit/events", get(list_audit_events))
}

async fn admin_index_handler(
    _path: axum::extract::Path<String>,
) -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../../../../front/admin/index.html"))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn admin_or_forbidden(auth: &AdminAuth) -> Option<Response> {
    if !auth.is_admin() {
        return Some((StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"}))).into_response());
    }
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
                "user_id": s.user_id.to_string(),
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

    let events = match AuditEventRepo.list_recent(&mut conn, query.limit).await {
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

    Json(json!({"items": rows, "total": rows.len() as i64})).into_response()
}
