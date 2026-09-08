//! Admin authentication extractor.
//!
//! Supports both API key (`X-API-Key` or `Authorization: Bearer <api_key>`)
//! and OIDC access token (`Authorization: Bearer <jwt>`) authentication.
//! The broad `admin` permission grants all routes. Every management route also
//! accepts a resource/action permission supplied by API-key scopes or user roles.

use axum::extract::FromRequestParts;
use axum::http::Method;
use axum::http::request::Parts;
use axum::response::IntoResponse;
use oidc_apikey::auth::{ApiKeyAuth, ApiKeyError};
use oidc_core::traits::TokenService;
use oidc_repository::Connection;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::group_repo::GroupRepo;
use oidc_repository::repositories::identity_provider_repo::IdentityProviderRepo;
use oidc_repository::repositories::organization_repo::OrganizationRepo;
use oidc_repository::repositories::role_repo::RoleRepo;
use oidc_repository::repositories::scope_repo::ScopeRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::repositories::user_role_repo::UserRoleRepo;

use crate::state::AppState;

/// Authenticated admin identity.
///
/// Accepts either:
/// - An API key with a permission valid for the requested route
/// - A valid OIDC access token whose user roles grant the route permission
#[derive(Debug, Clone)]
pub struct AdminAuth {
    /// The authenticated subject (user ID or API key ID).
    pub subject: String,
    /// Whether this is an API key authentication.
    pub is_api_key: bool,
    /// The realm ID associated with this authentication.
    /// Populated from the API key's realm when `is_api_key` is true,
    /// or `None` for JWT-based authentication (realm must be specified
    /// in the request body instead).
    pub realm_id: Option<uuid::Uuid>,
    /// OAuth/API-key scopes plus permissions granted through user roles.
    pub permissions: Vec<String>,
    pub route_authorized: bool,
}

impl AdminAuth {
    pub fn is_global_admin(&self) -> bool {
        !self.is_api_key
            && self
                .permissions
                .iter()
                .any(|value| value == "admin" || value == "*")
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        let wildcard = permission
            .rsplit_once(':')
            .map(|(resource, _)| format!("{resource}:*"));
        self.permissions.iter().any(|value| {
            value == "admin"
                || value == "*"
                || value == permission
                || wildcard.as_ref().is_some_and(|wildcard| value == wildcard)
        })
    }

    pub fn has_any_organization_permission(&self) -> bool {
        self.permissions
            .iter()
            .any(|value| value == "admin" || value.starts_with("organizations:"))
    }

    pub fn has_organization_permission(&self, action: &str, organization_id: uuid::Uuid) -> bool {
        self.has_permission("organizations:*")
            || self.has_permission(&format!("organizations:{action}"))
            || self.has_permission(&format!("organizations:{organization_id}:{action}"))
    }

    pub fn organization_ids_with_permission(&self, action: &str) -> Vec<uuid::Uuid> {
        self.permissions
            .iter()
            .filter_map(|permission| {
                let parts: Vec<&str> = permission.split(':').collect();
                (parts.len() == 3 && parts[0] == "organizations" && parts[2] == action)
                    .then(|| parts[1].parse().ok())
                    .flatten()
            })
            .collect()
    }
}

fn route_is_authorized(method: &Method, path: &str, auth: &AdminAuth) -> bool {
    if auth.has_permission("admin") {
        return true;
    }
    if let Some(rest) = path.strip_prefix("/api/organizations") {
        let segments: Vec<&str> = rest
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let organization_id = segments.first().and_then(|value| value.parse().ok());
        let action = if method == Method::GET {
            "view"
        } else if segments
            .get(1)
            .is_some_and(|value| matches!(*value, "members" | "invitations"))
        {
            "members"
        } else {
            "manage"
        };
        return match organization_id {
            Some(id) => auth.has_organization_permission(action, id),
            None if method == Method::GET => {
                auth.has_permission("organizations:view")
                    || auth.has_permission("organizations:*")
                    || !auth.organization_ids_with_permission("view").is_empty()
            }
            None => auth.has_permission("organizations:manage"),
        };
    }

    let read = method == Method::GET || method == Method::HEAD;
    let permission = if path == "/api/stats" {
        "stats:read"
    } else if path == "/api/authorization" || path.starts_with("/api/authorization/") {
        if read {
            "authorization:read"
        } else {
            "authorization:write"
        }
    } else if path.starts_with("/api/users/") && path.ends_with("/impersonate") {
        "users:impersonate"
    } else if path.starts_with("/api/users/") && path.contains("/roles") {
        if read { "roles:read" } else { "roles:write" }
    } else if path.starts_with("/api/users/") && path.contains("/groups") {
        if read { "groups:read" } else { "groups:write" }
    } else if path == "/api/users" || path.starts_with("/api/users/") {
        if read { "users:read" } else { "users:write" }
    } else if path == "/api/clients" || path.starts_with("/api/clients/") {
        if read {
            "clients:read"
        } else {
            "clients:write"
        }
    } else if path.starts_with("/api/realms/") && path.ends_with("/export") {
        "realms:read"
    } else if path == "/api/realms" || path.starts_with("/api/realms/") {
        if read { "realms:read" } else { "realms:write" }
    } else if path == "/api/sessions" || path.starts_with("/api/sessions/") {
        if read {
            "sessions:read"
        } else {
            "sessions:revoke"
        }
    } else if path == "/api/audit/events" {
        "audit:read"
    } else if path == "/api/scopes" || path.starts_with("/api/scopes/") {
        if read { "scopes:read" } else { "scopes:write" }
    } else if path == "/api/roles" || path.starts_with("/api/roles/") {
        if read { "roles:read" } else { "roles:write" }
    } else if path == "/api/groups" || path.starts_with("/api/groups/") {
        if read { "groups:read" } else { "groups:write" }
    } else if path == "/api/user-federation" || path.starts_with("/api/user-federation/") {
        if read {
            "user_federation:read"
        } else {
            "user_federation:write"
        }
    } else if path == "/api/saml/clients" || path.starts_with("/api/saml/clients/") {
        if read {
            "clients:read"
        } else {
            "clients:write"
        }
    } else if path == "/api/identity-providers" || path.starts_with("/api/identity-providers/") {
        if read {
            "identity_providers:read"
        } else {
            "identity_providers:write"
        }
    } else if path == "/api/keys" || path.starts_with("/api/keys/") {
        if read {
            "api_keys:read"
        } else {
            "api_keys:write"
        }
    } else if path.starts_with("/api/maintenance/") {
        "maintenance:execute"
    } else if path == "/oidc/register" {
        "clients:write"
    } else {
        return false;
    };
    auth.has_permission(permission)
}

async fn route_realm_is_authorized(
    path: &str,
    auth: &AdminAuth,
    state: &AppState,
) -> Result<bool, ApiKeyError> {
    let Some(auth_realm) = auth.realm_id else {
        return Ok(true);
    };
    if auth.is_global_admin() {
        return Ok(true);
    }
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    if segments.first() != Some(&"api") || segments.len() < 3 {
        return Ok(true);
    }
    let Ok(resource_id) = segments[2].parse::<uuid::Uuid>() else {
        return Ok(true);
    };
    if segments[1] == "realms" {
        return Ok(resource_id == auth_realm);
    }

    let conn = wasi_pg_client::Connection::connect(&state.db_config)
        .await
        .map_err(|_| ApiKeyError::Invalid)?;
    let mut conn = Connection::from_pg_client(conn);
    let resource_realm = match segments[1] {
        "users" => UserRepo
            .find_by_id(&mut conn, resource_id)
            .await
            .map_err(|_| ApiKeyError::Invalid)?
            .map(|item| item.realm_id),
        "clients" => ClientRepo
            .find_by_id(&mut conn, resource_id)
            .await
            .map_err(|_| ApiKeyError::Invalid)?
            .map(|item| item.realm_id),
        "sessions" => SessionRepo
            .find_by_id(&mut conn, resource_id)
            .await
            .map_err(|_| ApiKeyError::Invalid)?
            .map(|item| item.realm_id),
        "scopes" => ScopeRepo
            .find_by_id(&mut conn, resource_id)
            .await
            .map_err(|_| ApiKeyError::Invalid)?
            .map(|item| item.realm_id),
        "roles" => RoleRepo
            .find_by_id(&mut conn, resource_id)
            .await
            .map_err(|_| ApiKeyError::Invalid)?
            .map(|item| item.realm_id),
        "groups" => GroupRepo
            .find_by_id(&mut conn, resource_id)
            .await
            .map_err(|_| ApiKeyError::Invalid)?
            .map(|item| item.realm_id),
        "identity-providers" => IdentityProviderRepo
            .find_by_id(&mut conn, resource_id)
            .await
            .map_err(|_| ApiKeyError::Invalid)?
            .map(|item| item.realm_id),
        "organizations" => OrganizationRepo
            .find_by_id(&mut conn, resource_id)
            .await
            .map_err(|_| ApiKeyError::Invalid)?
            .map(|item| item.realm_id),
        // API-key records perform this check after loading the record so the
        // extractor never tries to authenticate and query the same key twice.
        "keys" => None,
        _ => None,
    };
    let _ = conn.close().await;
    Ok(resource_realm.is_none_or(|realm_id| realm_id == auth_realm))
}

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = ApiKeyError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Try API key authentication first
        if let Ok(api_key_auth) = ApiKeyAuth::from_request_parts(parts, state).await {
            let mut auth = AdminAuth {
                subject: api_key_auth.api_key.id.to_string(),
                is_api_key: true,
                realm_id: Some(api_key_auth.api_key.realm_id),
                permissions: api_key_auth.api_key.scopes,
                route_authorized: false,
            };
            auth.route_authorized = route_is_authorized(&parts.method, parts.uri.path(), &auth);
            if auth.route_authorized {
                auth.route_authorized =
                    route_realm_is_authorized(parts.uri.path(), &auth, state).await?;
            }
            return auth
                .route_authorized
                .then_some(auth)
                .ok_or(ApiKeyError::InsufficientScope);
        }

        // Try OIDC Bearer token authentication
        if let Some(auth_header) = parts.headers.get(axum::http::header::AUTHORIZATION)
            && let Ok(auth_str) = auth_header.to_str()
            && let Some(token) = auth_str.strip_prefix("Bearer ")
        {
            match state
                .token_service
                .verify_access_token_with_claims(token)
                .await
            {
                Ok(claims) => {
                    let mut permissions: Vec<String> = claims
                        .scope
                        .split_whitespace()
                        .map(str::to_string)
                        .collect();
                    let mut realm_id = None;
                    if let Ok(user_id) = claims.sub.parse::<uuid::Uuid>() {
                        let conn = wasi_pg_client::Connection::connect(&state.db_config)
                            .await
                            .map_err(|_| ApiKeyError::Invalid)?;
                        let mut conn = Connection::from_pg_client(conn);
                        if let Some(user) = UserRepo
                            .find_by_id(&mut conn, user_id)
                            .await
                            .map_err(|_| ApiKeyError::Invalid)?
                        {
                            realm_id = Some(user.realm_id);
                            // A user's administrative authority comes from current
                            // direct and group roles. OAuth scopes requested by a
                            // client must never elevate that user to administrator.
                            permissions = UserRoleRepo
                                .find_effective_permissions(&mut conn, user_id)
                                .await
                                .map_err(|_| ApiKeyError::Invalid)?;
                        } else {
                            let _ = conn.close().await;
                            return Err(ApiKeyError::Invalid);
                        }
                        let _ = conn.close().await;
                    }
                    let mut auth = AdminAuth {
                        subject: claims.sub,
                        is_api_key: false,
                        realm_id,
                        permissions,
                        route_authorized: false,
                    };
                    auth.route_authorized =
                        route_is_authorized(&parts.method, parts.uri.path(), &auth);
                    if auth.route_authorized {
                        auth.route_authorized =
                            route_realm_is_authorized(parts.uri.path(), &auth, state).await?;
                    }
                    return auth
                        .route_authorized
                        .then_some(auth)
                        .ok_or(ApiKeyError::InsufficientScope);
                }
                Err(e) => {
                    tracing::debug!("OIDC token verification failed: {}", e);
                }
            }
        }

        Err(ApiKeyError::Missing)
    }
}

/// Convert AdminAuth extraction failure into an HTTP response.
pub fn admin_auth_rejection(err: ApiKeyError) -> axum::response::Response {
    err.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(permissions: &[String]) -> AdminAuth {
        AdminAuth {
            subject: "user".into(),
            is_api_key: false,
            realm_id: None,
            permissions: permissions.to_vec(),
            route_authorized: false,
        }
    }

    #[test]
    fn organization_permissions_are_action_and_resource_scoped() {
        let id = uuid::Uuid::now_v7();
        let value = auth(&[
            format!("organizations:{id}:view"),
            format!("organizations:{id}:members"),
        ]);
        assert!(route_is_authorized(
            &Method::GET,
            &format!("/api/organizations/{id}"),
            &value
        ));
        assert!(route_is_authorized(
            &Method::POST,
            &format!("/api/organizations/{id}/members"),
            &value
        ));
        assert!(!route_is_authorized(
            &Method::PUT,
            &format!("/api/organizations/{id}"),
            &value
        ));
        assert!(!route_is_authorized(
            &Method::GET,
            &format!("/api/organizations/{}", uuid::Uuid::now_v7()),
            &value
        ));
    }

    #[test]
    fn realm_manage_permission_can_create_organizations() {
        let value = auth(&["organizations:manage".into()]);
        assert!(route_is_authorized(
            &Method::POST,
            "/api/organizations",
            &value
        ));
        assert!(!route_is_authorized(&Method::GET, "/api/users", &value));
    }

    #[test]
    fn every_admin_resource_requires_its_action_permission() {
        let cases = [
            (Method::GET, "/api/stats", "stats:read"),
            (Method::GET, "/api/users", "users:read"),
            (Method::POST, "/api/users", "users:write"),
            (
                Method::POST,
                "/api/users/01990000-0000-7000-8000-000000000001/impersonate",
                "users:impersonate",
            ),
            (Method::GET, "/api/clients", "clients:read"),
            (Method::POST, "/api/clients", "clients:write"),
            (Method::GET, "/api/realms", "realms:read"),
            (
                Method::POST,
                "/api/realms/01990000-0000-7000-8000-000000000001/export",
                "realms:read",
            ),
            (Method::POST, "/api/realms/import", "realms:write"),
            (
                Method::PUT,
                "/api/realms/01990000-0000-7000-8000-000000000001",
                "realms:write",
            ),
            (Method::GET, "/api/sessions", "sessions:read"),
            (
                Method::POST,
                "/api/sessions/01990000-0000-7000-8000-000000000001/revoke",
                "sessions:revoke",
            ),
            (Method::GET, "/api/audit/events", "audit:read"),
            (Method::GET, "/api/scopes", "scopes:read"),
            (Method::POST, "/api/scopes", "scopes:write"),
            (Method::GET, "/api/roles", "roles:read"),
            (Method::POST, "/api/roles", "roles:write"),
            (Method::GET, "/api/groups", "groups:read"),
            (Method::POST, "/api/groups", "groups:write"),
            (
                Method::GET,
                "/api/identity-providers",
                "identity_providers:read",
            ),
            (
                Method::POST,
                "/api/identity-providers",
                "identity_providers:write",
            ),
            (Method::GET, "/api/user-federation", "user_federation:read"),
            (
                Method::POST,
                "/api/user-federation",
                "user_federation:write",
            ),
            (
                Method::POST,
                "/api/user-federation/01990000-0000-7000-8000-000000000001/sync",
                "user_federation:write",
            ),
            (Method::GET, "/api/keys", "api_keys:read"),
            (Method::POST, "/api/keys", "api_keys:write"),
            (
                Method::POST,
                "/api/maintenance/cleanup",
                "maintenance:execute",
            ),
            (Method::POST, "/oidc/register", "clients:write"),
        ];
        for (method, path, permission) in cases {
            let allowed = auth(&[permission.to_string()]);
            let denied = auth(&["unrelated:read".into()]);
            assert!(
                route_is_authorized(&method, path, &allowed),
                "{method} {path} must accept {permission}"
            );
            assert!(
                !route_is_authorized(&method, path, &denied),
                "{method} {path} must reject unrelated permissions"
            );
        }
    }

    #[test]
    fn resource_wildcards_do_not_cross_resource_boundaries() {
        let value = auth(&["users:*".into()]);
        assert!(route_is_authorized(&Method::GET, "/api/users", &value));
        assert!(route_is_authorized(
            &Method::DELETE,
            "/api/users/01990000-0000-7000-8000-000000000001",
            &value
        ));
        assert!(!route_is_authorized(&Method::GET, "/api/clients", &value));
        assert!(route_is_authorized(
            &Method::POST,
            "/api/users/01990000-0000-7000-8000-000000000001/impersonate",
            &value
        ));
    }
}
