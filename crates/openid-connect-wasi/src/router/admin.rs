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
use oidc_core::models::Group;
use oidc_core::models::PasswordPolicy;
use oidc_core::models::Role;
use oidc_core::models::Scope;
use oidc_core::models::account_recovery_token::AccountRecoveryToken;
use oidc_core::models::audit_event::ActorType;

use oidc_core::utils::{
    generate_opaque_token, generate_uuid_v7, is_strong_password, is_valid_email, is_valid_username,
};
use oidc_repository::Connection;
use oidc_repository::repositories::account_recovery_token_repo::AccountRecoveryTokenRepo;
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;
use oidc_repository::repositories::auth_code_repo::AuthCodeRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::device_code_repo::DeviceCodeRepo;
use oidc_repository::repositories::email_verification_token_repo::EmailVerificationTokenRepo;
use oidc_repository::repositories::group_repo::GroupRepo;
use oidc_repository::repositories::group_role_repo::GroupRoleRepo;
use oidc_repository::repositories::par_repo::ParRepo;
use oidc_repository::repositories::password_reset_token_repo::PasswordResetTokenRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::realm_signing_keys_repo::RealmSigningKeysRepo;
use oidc_repository::repositories::role_repo::RoleRepo;
use oidc_repository::repositories::scope_repo::ScopeRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_group_repo::UserGroupRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::repositories::user_role_repo::UserRoleRepo;

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
        // Roles
        .route("/api/roles", get(list_roles))
        .route("/api/roles", post(create_role))
        .route("/api/roles/{id}", get(get_role))
        .route("/api/roles/{id}", put(update_role))
        .route("/api/roles/{id}", delete(delete_role))
        // User-Role assignments
        .route("/api/users/{id}/roles", get(list_user_roles))
        .route("/api/users/{id}/roles", post(assign_role_to_user))
        .route(
            "/api/users/{id}/roles/{role_id}",
            delete(unassign_role_from_user),
        )
        // Groups
        .route("/api/groups", get(list_groups))
        .route("/api/groups", post(create_group))
        .route("/api/groups/{id}", get(get_group))
        .route("/api/groups/{id}", put(update_group))
        .route("/api/groups/{id}", delete(delete_group))
        // User-Group assignments
        .route("/api/users/{id}/groups", get(list_user_groups))
        .route("/api/users/{id}/groups", post(assign_group_to_user))
        .route(
            "/api/users/{id}/groups/{group_id}",
            delete(unassign_group_from_user),
        )
        // Group-Role assignments
        .route("/api/groups/{id}/roles", get(list_group_roles))
        .route("/api/groups/{id}/roles", post(assign_role_to_group))
        .route(
            "/api/groups/{id}/roles/{role_id}",
            delete(unassign_role_from_group),
        )
        // Account Recovery
        .route(
            "/api/users/{id}/account-recovery",
            post(initiate_account_recovery),
        )
        // User Impersonation
        .route("/api/users/{id}/impersonate", post(impersonate_user))
        // Token Cleanup
        .route("/api/maintenance/cleanup", post(cleanup_expired))
        // Password Policy
        .route("/api/realms/{id}/password-policy", get(get_password_policy))
        .route(
            "/api/realms/{id}/password-policy",
            put(update_password_policy),
        )
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
        street_address: None,
        locality: None,
        region: None,
        postal_code: None,
        country: None,
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
        request_object_encryption_alg: None,
        request_object_encryption_enc: None,
        request_object_encryption_key_encrypted: None,
        request_object_encryption_key_pem: None,
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

// ─── Roles CRUD ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RoleListQuery {
    realm_id: Uuid,
    search: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
}

async fn list_roles(
    State(state): State<AppState>,
    Query(query): Query<RoleListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let items = match RoleRepo
        .list(
            &mut conn,
            query.realm_id,
            query.search.as_deref(),
            query.limit,
            query.offset,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("list roles error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    let total = RoleRepo.count(&mut conn, query.realm_id).await.unwrap_or(0);
    let rows: Vec<Value> = items
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id.to_string(),
                "realm_id": r.realm_id.to_string(),
                "name": r.name,
                "description": r.description,
                "permissions": r.permissions,
                "created_at": r.created_at.to_rfc3339(),
                "updated_at": r.updated_at.to_rfc3339(),
            })
        })
        .collect();
    Json(json!({"items": rows, "total": total})).into_response()
}

#[derive(Deserialize)]
struct CreateRoleRequest {
    realm_id: Uuid,
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
}

async fn create_role(State(state): State<AppState>, auth: AdminAuth, body: String) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: CreateRoleRequest = match serde_json::from_str(&body) {
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
    let now = chrono::Utc::now();
    let role = Role {
        id: generate_uuid_v7(),
        realm_id: req.realm_id,
        name: req.name.clone(),
        description: req.description.clone(),
        permissions: req.permissions.clone(),
        created_at: now,
        updated_at: now,
    };
    if let Err(e) = role.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{e}")})),
        )
            .into_response();
    }
    // Check for duplicate name in realm
    if let Ok(Some(_)) = RoleRepo
        .find_by_name(&mut conn, req.realm_id, &req.name)
        .await
    {
        return (StatusCode::CONFLICT, Json(json!({"error": "duplicate"}))).into_response();
    }
    match RoleRepo.create(&mut conn, &role).await {
        Ok(()) => {
            // Audit event
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
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
            Json(json!({
                "id": role.id.to_string(),
                "realm_id": role.realm_id.to_string(),
                "name": role.name,
                "description": role.description,
                "permissions": role.permissions,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("create role error: {e}");
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn get_role(
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
        Ok(Some(r)) => {
            let _ = conn.close().await;
            Json(json!({
                "id": r.id.to_string(),
                "realm_id": r.realm_id.to_string(),
                "name": r.name,
                "description": r.description,
                "permissions": r.permissions,
                "created_at": r.created_at.to_rfc3339(),
                "updated_at": r.updated_at.to_rfc3339(),
            }))
            .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
        Err(e) => {
            tracing::error!("get role error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct UpdateRoleRequest {
    name: Option<String>,
    description: Option<String>,
    permissions: Option<Vec<String>>,
}

async fn update_role(
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
    let mut role = match RoleRepo.find_by_id(&mut conn, id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
        }
        Err(e) => {
            tracing::error!("update role fetch error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
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
    match RoleRepo.update(&mut conn, &role).await {
        Ok(()) => {
            // Audit event
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
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
            Json(json!({"updated": true})).into_response()
        }
        Err(e) => {
            tracing::error!("update role error: {e}");
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn delete_role(
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
    // Fetch role for audit before deleting
    let role = match RoleRepo.find_by_id(&mut conn, id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
        }
        Err(e) => {
            tracing::error!("delete role fetch error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    match RoleRepo.delete(&mut conn, id).await {
        Ok(()) => {
            // Audit event
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
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
            Json(json!({"deleted": true})).into_response()
        }
        Err(e) => {
            tracing::error!("delete role error: {e}");
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

// ─── User-Role assignments ─────────────────────────────────────────────────────

async fn list_user_roles(
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
    let roles = match RoleRepo.find_by_user_id(&mut conn, id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("list user roles error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    let _ = conn.close().await;
    let rows: Vec<Value> = roles
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id.to_string(),
                "realm_id": r.realm_id.to_string(),
                "name": r.name,
                "description": r.description,
                "permissions": r.permissions,
            })
        })
        .collect();
    Json(json!({"items": rows})).into_response()
}

#[derive(Deserialize)]
struct AssignRoleRequest {
    role_id: Uuid,
}

async fn assign_role_to_user(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: AssignRoleRequest = match serde_json::from_str(&body) {
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
    match UserRoleRepo.assign(&mut conn, id, req.role_id).await {
        Ok(()) => {
            // Audit event
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: None,
                event_type: "user.role_assigned".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("user".to_string()),
                target_id: Some(id),
                details: json!({"role_id": req.role_id.to_string()}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
            Json(json!({"assigned": true})).into_response()
        }
        Err(e) => {
            tracing::error!("assign role to user error: {e}");
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn unassign_role_from_user(
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
    match UserRoleRepo.unassign(&mut conn, id, role_id).await {
        Ok(()) => {
            // Audit event
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: None,
                event_type: "user.role_unassigned".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("user".to_string()),
                target_id: Some(id),
                details: json!({"role_id": role_id.to_string()}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
            Json(json!({"unassigned": true})).into_response()
        }
        Err(e) => {
            tracing::error!("unassign role from user error: {e}");
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

// ─── Groups CRUD ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GroupListQuery {
    realm_id: Uuid,
    search: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
}

async fn list_groups(
    State(state): State<AppState>,
    Query(query): Query<GroupListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let items = match GroupRepo
        .list(
            &mut conn,
            query.realm_id,
            query.search.as_deref(),
            query.limit,
            query.offset,
        )
        .await
    {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("list groups error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    let total = GroupRepo
        .count(&mut conn, query.realm_id)
        .await
        .unwrap_or(0);
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
struct CreateGroupRequest {
    realm_id: Uuid,
    name: String,
    description: Option<String>,
    parent_id: Option<Uuid>,
}

async fn create_group(State(state): State<AppState>, auth: AdminAuth, body: String) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: CreateGroupRequest = match serde_json::from_str(&body) {
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
    let now = chrono::Utc::now();
    let group = Group {
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
    // Check for duplicate name in realm
    if let Ok(Some(_)) = GroupRepo
        .find_by_name(&mut conn, req.realm_id, &req.name)
        .await
    {
        return (StatusCode::CONFLICT, Json(json!({"error": "duplicate"}))).into_response();
    }
    match GroupRepo.create(&mut conn, &group).await {
        Ok(()) => {
            // Audit event
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
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
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
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn get_group(
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
        Ok(Some(g)) => {
            let _ = conn.close().await;
            Json(json!({
                "id": g.id.to_string(),
                "realm_id": g.realm_id.to_string(),
                "name": g.name,
                "description": g.description,
                "parent_id": g.parent_id.map(|p| p.to_string()),
                "created_at": g.created_at.to_rfc3339(),
                "updated_at": g.updated_at.to_rfc3339(),
            }))
            .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
        Err(e) => {
            tracing::error!("get group error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct UpdateGroupRequest {
    name: Option<String>,
    description: Option<String>,
    parent_id: Option<Option<Uuid>>,
}

async fn update_group(
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
    let mut group = match GroupRepo.find_by_id(&mut conn, id).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
        }
        Err(e) => {
            tracing::error!("update group fetch error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
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
            // Audit event
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
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
            Json(json!({"updated": true})).into_response()
        }
        Err(e) => {
            tracing::error!("update group error: {e}");
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn delete_group(
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
    // Fetch group for audit before deleting
    let group = match GroupRepo.find_by_id(&mut conn, id).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
        }
        Err(e) => {
            tracing::error!("delete group fetch error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    match GroupRepo.delete(&mut conn, id).await {
        Ok(()) => {
            // Audit event
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
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
            Json(json!({"deleted": true})).into_response()
        }
        Err(e) => {
            tracing::error!("delete group error: {e}");
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

// ─── User-Group assignments ─────────────────────────────────────────────────────

async fn list_user_groups(
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
    let groups = match UserGroupRepo.find_groups_by_user(&mut conn, id).await {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("list user groups error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    let _ = conn.close().await;
    let rows: Vec<Value> = groups
        .into_iter()
        .map(|g| {
            json!({
                "id": g.id.to_string(),
                "realm_id": g.realm_id.to_string(),
                "name": g.name,
                "description": g.description,
                "parent_id": g.parent_id.map(|p| p.to_string()),
            })
        })
        .collect();
    Json(json!({"items": rows})).into_response()
}

#[derive(Deserialize)]
struct AssignGroupRequest {
    group_id: Uuid,
}

async fn assign_group_to_user(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: AssignGroupRequest = match serde_json::from_str(&body) {
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
    match UserGroupRepo.assign(&mut conn, id, req.group_id).await {
        Ok(()) => {
            // Audit event
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: None,
                event_type: "user.group_assigned".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("user".to_string()),
                target_id: Some(id),
                details: json!({"group_id": req.group_id.to_string()}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
            Json(json!({"assigned": true})).into_response()
        }
        Err(e) => {
            tracing::error!("assign group to user error: {e}");
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn unassign_group_from_user(
    State(state): State<AppState>,
    axum::extract::Path((id, group_id)): axum::extract::Path<(Uuid, Uuid)>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match UserGroupRepo.unassign(&mut conn, id, group_id).await {
        Ok(()) => {
            // Audit event
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: None,
                event_type: "user.group_unassigned".to_string(),
                actor_id: Uuid::parse_str(&auth.subject).ok(),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("user".to_string()),
                target_id: Some(id),
                details: json!({"group_id": group_id.to_string()}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
            Json(json!({"unassigned": true})).into_response()
        }
        Err(e) => {
            tracing::error!("unassign group from user error: {e}");
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

// ─── Group-Role assignments ─────────────────────────────────────────────────────

async fn list_group_roles(
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    let _ = conn.close().await;
    let rows: Vec<Value> = roles
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id.to_string(),
                "realm_id": r.realm_id.to_string(),
                "name": r.name,
                "description": r.description,
                "permissions": r.permissions,
            })
        })
        .collect();
    Json(json!({"items": rows})).into_response()
}

#[derive(Deserialize)]
struct AssignRoleToGroupRequest {
    role_id: Uuid,
}

async fn assign_role_to_group(
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
    match GroupRoleRepo.assign(&mut conn, id, req.role_id).await {
        Ok(()) => {
            // Audit event
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
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
            Json(json!({"assigned": true})).into_response()
        }
        Err(e) => {
            tracing::error!("assign role to group error: {e}");
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn unassign_role_from_group(
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
            // Audit event
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
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
            Json(json!({"unassigned": true})).into_response()
        }
        Err(e) => {
            tracing::error!("unassign role from group error: {e}");
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

// ─── Account Recovery ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AccountRecoveryRequest {
    creator_ip: Option<String>,
}

async fn initiate_account_recovery(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: AccountRecoveryRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            // Body is optional for this endpoint, use defaults
            AccountRecoveryRequest { creator_ip: None }
        }
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // Fetch user by ID
    let user = match UserRepo.find_by_id(&mut conn, id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "user not found"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("account recovery user fetch error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    // Parse admin ID from auth.subject
    let admin_uuid = match Uuid::parse_str(&auth.subject) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "invalid admin identity"})),
            )
                .into_response();
        }
    };
    // Create account recovery token
    let (token_entity, raw_token) =
        match AccountRecoveryToken::new(user.id, user.realm_id, admin_uuid, req.creator_ip) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("account recovery token creation error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "internal"})),
                )
                    .into_response();
            }
        };
    // Store the token
    match AccountRecoveryTokenRepo
        .create(&mut conn, &token_entity)
        .await
    {
        Ok(()) => {
            // Audit event
            let audit = oidc_core::models::AuditEvent {
                id: generate_uuid_v7(),
                realm_id: Some(user.realm_id),
                event_type: "user.account_recovery_initiated".to_string(),
                actor_id: Some(admin_uuid),
                actor_type: if auth.is_api_key {
                    ActorType::ApiKey
                } else {
                    ActorType::User
                },
                target_type: Some("user".to_string()),
                target_id: Some(user.id),
                details: json!({}),
                ip_address: None,
                user_agent: None,
                created_at: chrono::Utc::now(),
            };
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
            Json(json!({
                "recovery_token": raw_token,
                "user_id": user.id.to_string(),
                "expires_at": token_entity.expires_at.to_rfc3339(),
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("account recovery token store error: {e}");
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

// ─── User Impersonation ────────────────────────────────────────────────────────

async fn impersonate_user(
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
    // Fetch user by ID
    let user = match UserRepo.find_by_id(&mut conn, id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "user not found"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("impersonate user fetch error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    // Verify user is enabled
    if !user.enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "user is disabled"})),
        )
            .into_response();
    }
    // Create impersonation access token with act claim
    let sub = user.id.to_string();
    let act_sub = auth.subject.clone();
    let scope = "openid profile email";
    let audience = vec!["account".to_string()];
    let token = match state.token_service.encode_access_token_with_act(
        &sub, &act_sub, scope, &audience, 300, // 5 minutes
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("impersonate token encode error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    // Audit event
    let audit = oidc_core::models::AuditEvent {
        id: generate_uuid_v7(),
        realm_id: Some(user.realm_id),
        event_type: "user.impersonated".to_string(),
        actor_id: Uuid::parse_str(&auth.subject).ok(),
        actor_type: if auth.is_api_key {
            ActorType::ApiKey
        } else {
            ActorType::User
        },
        target_type: Some("user".to_string()),
        target_id: Some(user.id),
        details: json!({
            "impersonated_user_id": user.id.to_string(),
            "impersonated_by": auth.subject,
        }),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    let _ = AuditEventRepo.create(&mut conn, &audit).await;
    let _ = conn.close().await;
    Json(json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 300,
        "impersonated_user_id": user.id.to_string(),
        "impersonated_by": auth.subject,
    }))
    .into_response()
}

// ─── Token Cleanup ─────────────────────────────────────────────────────────────

async fn cleanup_expired(State(state): State<AppState>, auth: AdminAuth) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let sessions_deleted = SessionRepo.cleanup_expired(&mut conn).await.unwrap_or(0);
    let password_reset_deleted = PasswordResetTokenRepo
        .cleanup_expired(&mut conn)
        .await
        .unwrap_or(0);
    let email_verification_deleted = EmailVerificationTokenRepo
        .cleanup_expired(&mut conn)
        .await
        .unwrap_or(0);
    let account_recovery_deleted = AccountRecoveryTokenRepo
        .cleanup_expired(&mut conn)
        .await
        .unwrap_or(0);
    let device_codes_deleted = DeviceCodeRepo.cleanup_expired(&mut conn).await.unwrap_or(0);
    let auth_codes_deleted = AuthCodeRepo.cleanup_expired(&mut conn).await.unwrap_or(0);
    let par_deleted = ParRepo.cleanup_expired(&mut conn).await.unwrap_or(0);
    // Audit event
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
        }),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    let _ = AuditEventRepo.create(&mut conn, &audit).await;
    let _ = conn.close().await;
    Json(json!({
        "sessions_deleted": sessions_deleted,
        "password_reset_deleted": password_reset_deleted,
        "email_verification_deleted": email_verification_deleted,
        "account_recovery_deleted": account_recovery_deleted,
        "device_codes_deleted": device_codes_deleted,
        "auth_codes_deleted": auth_codes_deleted,
        "par_deleted": par_deleted,
    }))
    .into_response()
}

// ─── Password Policy ───────────────────────────────────────────────────────────

async fn get_password_policy(
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
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
        }
        Err(e) => {
            tracing::error!("get password policy realm fetch error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    let policy = PasswordPolicy::from_realm_config(&realm.config);
    let _ = conn.close().await;
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
struct UpdatePasswordPolicyRequest {
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

async fn update_password_policy(
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
            tracing::error!("update password policy realm fetch error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response();
        }
    };
    // Get current policy and apply updates
    let current = PasswordPolicy::from_realm_config(&realm.config);
    let updated_policy = PasswordPolicy {
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
    // Update realm config with the new password_policy
    let config = realm.config.as_object_mut();
    if let Some(config_map) = config {
        config_map.insert(
            "password_policy".to_string(),
            serde_json::to_value(&updated_policy).unwrap_or_default(),
        );
    }
    match RealmRepo.update(&mut conn, &realm).await {
        Ok(()) => {
            // Audit event
            let audit = oidc_core::models::AuditEvent {
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
            let _ = AuditEventRepo.create(&mut conn, &audit).await;
            let _ = conn.close().await;
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
            let _ = conn.close().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}
