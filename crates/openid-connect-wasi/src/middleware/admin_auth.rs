//! Admin authentication extractor.
//!
//! Supports both API key (`X-API-Key` or `Authorization: Bearer <api_key>`)
//! and OIDC access token (`Authorization: Bearer <jwt>`) authentication.
//! The broad `admin` permission grants all routes. Organization routes also
//! accept fine-grained permissions supplied by API-key scopes or user roles.

use axum::extract::FromRequestParts;
use axum::http::Method;
use axum::http::request::Parts;
use axum::response::IntoResponse;
use oidc_apikey::auth::{ApiKeyAuth, ApiKeyError};
use oidc_core::traits::TokenService;
use oidc_repository::Connection;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::repositories::user_role_repo::UserRoleRepo;

use crate::state::AppState;

/// Authenticated admin identity.
///
/// Accepts either:
/// - An API key with a permission valid for the requested route
/// - A valid OIDC access token with `admin` scope or organization permissions
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
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions
            .iter()
            .any(|value| value == "admin" || value == permission)
    }

    pub fn has_any_organization_permission(&self) -> bool {
        self.permissions
            .iter()
            .any(|value| value == "admin" || value.starts_with("organizations:"))
    }

    pub fn has_organization_permission(&self, action: &str, organization_id: uuid::Uuid) -> bool {
        self.has_permission(&format!("organizations:{action}"))
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
    let Some(rest) = path.strip_prefix("/api/organizations") else {
        return false;
    };
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
    match organization_id {
        Some(id) => auth.has_organization_permission(action, id),
        None if method == Method::GET => {
            auth.has_permission("organizations:view")
                || !auth.organization_ids_with_permission("view").is_empty()
        }
        None => auth.has_permission("organizations:manage"),
    }
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
                            permissions.extend(
                                UserRoleRepo
                                    .find_effective_permissions(&mut conn, user_id)
                                    .await
                                    .map_err(|_| ApiKeyError::Invalid)?,
                            );
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
}
