//! Admin API routes for the management UI.

use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use serde_json::json;

use oidc_repository::Connection;

use crate::middleware::admin_auth::AdminAuth;
use crate::state::AppState;

pub mod audit;
pub mod clients;
pub mod realms;
pub mod users;

pub fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "internal"})),
    )
        .into_response()
}
pub fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
}
pub fn bad_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "bad_request"})),
    )
        .into_response()
}
pub fn conflict() -> Response {
    (StatusCode::CONFLICT, Json(json!({"error": "duplicate"}))).into_response()
}

/// Build the admin sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin", get(admin_index_handler))
        .route("/admin/", get(admin_index_handler))
        .route("/admin/{*path}", get(admin_index_handler))
        .route("/api/stats", get(audit::stats_handler))
        .route("/api/users", get(users::list))
        .route("/api/users", post(users::create))
        .route("/api/users/{id}", get(users::get))
        .route("/api/users/{id}", put(users::update))
        .route("/api/users/{id}", delete(users::delete))
        .route("/api/clients", get(clients::list))
        .route("/api/clients", post(clients::create))
        .route("/api/clients/{id}", get(clients::get))
        .route("/api/clients/{id}", put(clients::update))
        .route("/api/clients/{id}", delete(clients::delete))
        .route("/api/realms", get(realms::list))
        .route("/api/realms", post(realms::create))
        .route("/api/realms/{id}", get(realms::get))
        .route("/api/realms/{id}", put(realms::update))
        .route("/api/realms/{id}", delete(realms::delete))
        .route("/api/sessions", get(audit::list_sessions))
        .route("/api/sessions/{id}/revoke", post(audit::revoke_session))
        .route("/api/audit/events", get(audit::list))
        .route("/api/scopes", get(audit::list_scopes))
        .route("/api/scopes", post(audit::create_scope))
        .route("/api/scopes/{id}", get(audit::get_scope))
        .route("/api/scopes/{id}", put(audit::update_scope))
        .route("/api/scopes/{id}", delete(audit::delete_scope))
        .route("/api/roles", get(audit::list_roles))
        .route("/api/roles", post(audit::create_role))
        .route("/api/roles/{id}", get(audit::get_role))
        .route("/api/roles/{id}", put(audit::update_role))
        .route("/api/roles/{id}", delete(audit::delete_role))
        .route("/api/users/{id}/roles", get(users::list_roles))
        .route("/api/users/{id}/roles", post(users::assign_role))
        .route(
            "/api/users/{id}/roles/{role_id}",
            delete(users::unassign_role),
        )
        .route("/api/groups", get(audit::list_groups))
        .route("/api/groups", post(audit::create_group))
        .route("/api/groups/{id}", get(audit::get_group))
        .route("/api/groups/{id}", put(audit::update_group))
        .route("/api/groups/{id}", delete(audit::delete_group))
        .route("/api/users/{id}/groups", get(users::list_groups))
        .route("/api/users/{id}/groups", post(users::assign_group))
        .route(
            "/api/users/{id}/groups/{group_id}",
            delete(users::unassign_group),
        )
        .route("/api/groups/{id}/roles", get(audit::list_group_roles))
        .route("/api/groups/{id}/roles", post(audit::assign_role_to_group))
        .route(
            "/api/groups/{id}/roles/{role_id}",
            delete(audit::unassign_role_from_group),
        )
        .route(
            "/api/users/{id}/account-recovery",
            post(users::initiate_account_recovery),
        )
        .route("/api/users/{id}/impersonate", post(users::impersonate))
        .route("/api/maintenance/cleanup", post(audit::cleanup_expired))
        .route(
            "/api/maintenance/reencrypt-secrets",
            post(audit::reencrypt_legacy_secrets),
        )
        .route(
            "/api/realms/{id}/password-policy",
            get(realms::get_password_policy),
        )
        .route(
            "/api/realms/{id}/password-policy",
            put(realms::update_password_policy),
        )
        .route(
            "/api/identity-providers",
            get(realms::list_identity_providers),
        )
        .route(
            "/api/identity-providers",
            post(realms::create_identity_provider),
        )
        .route(
            "/api/identity-providers/{id}",
            get(realms::get_identity_provider),
        )
        .route(
            "/api/identity-providers/{id}",
            put(realms::update_identity_provider),
        )
        .route(
            "/api/identity-providers/{id}",
            delete(realms::delete_identity_provider),
        )
        .layer(axum::middleware::from_fn(
            crate::middleware::csrf::csrf_middleware,
        ))
}

async fn admin_index_handler(
    _path: axum::extract::Path<String>,
) -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../../../../../front/admin/index.html"))
}

pub fn admin_or_forbidden(_auth: &AdminAuth) -> Option<Response> {
    None
}

pub async fn connect(state: &AppState) -> Result<Connection, Response> {
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
