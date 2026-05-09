//! Admin authentication extractor.
//!
//! Supports both API key (`X-API-Key` or `Authorization: Bearer <api_key>`)
//! and OIDC access token (`Authorization: Bearer <jwt>`) authentication.
//! For OIDC tokens, the `admin` scope must be present.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::IntoResponse;
use oidc_apikey::auth::{ApiKeyAuth, ApiKeyError, has_scope};
use oidc_core::traits::TokenService;

use crate::state::AppState;

/// Authenticated admin identity.
///
/// Accepts either:
/// - An API key with `admin` scope
/// - A valid OIDC access token with `admin` in its scopes
#[derive(Debug, Clone)]
pub struct AdminAuth {
    /// The authenticated subject (user ID or API key ID).
    pub subject: String,
    /// Whether this is an API key authentication.
    pub is_api_key: bool,
}

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = ApiKeyError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Try API key authentication first
        if let Ok(api_key_auth) = ApiKeyAuth::from_request_parts(parts, state).await {
            if has_scope(&api_key_auth.api_key, "admin") {
                return Ok(AdminAuth {
                    subject: api_key_auth.api_key.id.to_string(),
                    is_api_key: true,
                });
            }
            // API key found but lacks admin scope
            return Err(ApiKeyError::InsufficientScope);
        }

        // Try OIDC Bearer token authentication
        if let Some(auth_header) = parts.headers.get(axum::http::header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    match state
                        .token_service
                        .verify_access_token_with_claims(token)
                        .await
                    {
                        Ok(claims) => {
                            // Verify the token has the "admin" scope
                            let scopes: Vec<&str> = claims.scope.split_whitespace().collect();
                            if !scopes.contains(&"admin") {
                                return Err(ApiKeyError::InsufficientScope);
                            }
                            return Ok(AdminAuth {
                                subject: claims.sub,
                                is_api_key: false,
                            });
                        }
                        Err(e) => {
                            tracing::debug!("OIDC token verification failed: {}", e);
                        }
                    }
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
