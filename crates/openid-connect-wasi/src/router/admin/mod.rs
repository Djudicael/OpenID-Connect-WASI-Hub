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
pub mod organizations;
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

/// Build the admin API sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/stats", get(audit::stats_handler))
        .route("/api/users", get(users::list))
        .route("/api/users", post(users::create))
        .route("/api/users/{id}", get(users::get))
        .route("/api/users/{id}", put(users::update))
        .route("/api/users/{id}", delete(users::delete))
        .route("/api/users/{id}/mfa", get(users::get_mfa))
        .route("/api/users/{id}/mfa", delete(users::reset_mfa))
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
        .route("/api/organizations", get(organizations::list))
        .route("/api/organizations", post(organizations::create))
        .route("/api/organizations/{id}", get(organizations::get))
        .route("/api/organizations/{id}", put(organizations::update))
        .route("/api/organizations/{id}", delete(organizations::delete))
        .route(
            "/api/organizations/{id}/domains",
            get(organizations::list_domains),
        )
        .route(
            "/api/organizations/{id}/domains",
            post(organizations::add_domain),
        )
        .route(
            "/api/organizations/{id}/domains/{domain_id}",
            delete(organizations::delete_domain),
        )
        .route(
            "/api/organizations/{id}/domains/{domain_id}/verify",
            post(organizations::verify_domain),
        )
        .route(
            "/api/organizations/{id}/members",
            get(organizations::list_members),
        )
        .route(
            "/api/organizations/{id}/members",
            post(organizations::add_member),
        )
        .route(
            "/api/organizations/{id}/members/{user_id}",
            delete(organizations::remove_member),
        )
        .route(
            "/api/organizations/{id}/identity-providers",
            get(organizations::list_identity_providers),
        )
        .route(
            "/api/organizations/{id}/identity-providers",
            post(organizations::link_identity_provider),
        )
        .route(
            "/api/organizations/{id}/identity-providers/{identity_provider_id}",
            delete(organizations::unlink_identity_provider),
        )
        .route(
            "/api/organizations/{id}/invitations",
            get(organizations::list_invitations),
        )
        .route(
            "/api/organizations/{id}/invitations",
            post(organizations::create_invitation),
        )
        .route(
            "/api/organizations/{id}/invitations/{invitation_id}",
            delete(organizations::revoke_invitation),
        )
        .route(
            "/api/organizations/{id}/groups",
            get(organizations::list_groups),
        )
        .route(
            "/api/organizations/{id}/groups",
            post(organizations::link_group),
        )
        .route(
            "/api/organizations/{id}/groups/{group_id}",
            delete(organizations::unlink_group),
        )
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

pub fn admin_or_forbidden(auth: &AdminAuth) -> Option<Response> {
    (!auth.route_authorized)
        .then(|| (StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"}))).into_response())
}

/// Resolve a requested realm against the caller's authenticated realm.
/// User and API-key administrators cannot read or mutate another realm.
pub fn scoped_realm(
    auth: &AdminAuth,
    requested: Option<uuid::Uuid>,
) -> Result<Option<uuid::Uuid>, Response> {
    if auth.is_global_admin() {
        return Ok(requested);
    }
    match (auth.realm_id, requested) {
        (Some(auth_realm), Some(requested_realm)) if auth_realm != requested_realm => {
            Err((StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"}))).into_response())
        }
        (Some(auth_realm), None) => Ok(Some(auth_realm)),
        (_, requested) => Ok(requested),
    }
}

pub fn realm_or_forbidden(auth: &AdminAuth, realm_id: uuid::Uuid) -> Option<Response> {
    scoped_realm(auth, Some(realm_id)).err()
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
