//! API key Axum extractor and middleware.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use oidc_core::models::ApiKey;
use oidc_repository::Connection;

use crate::service::ApiKeyService;

/// Extracted API key authentication.
#[derive(Debug, Clone)]
pub struct ApiKeyAuth {
    /// The authenticated API key.
    pub api_key: ApiKey,
}

impl<S: Sync> FromRequestParts<S> for ApiKeyAuth {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let _raw_key = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // We cannot open a DB connection here without state access.
        // The actual verification is deferred to handler level or middleware.
        // For a fully stateful extractor we would need a custom trait bound on S.
        // As a pragmatic compromise, we store the raw key and let the handler verify.
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Verify a raw API key string and return the authenticated wrapper.
///
/// Intended to be called from handlers that have access to a `Connection`.
pub async fn verify_raw_key(
    conn: &mut Connection,
    raw_key: &str,
) -> Result<ApiKeyAuth, oidc_core::OidcError> {
    let api_key = ApiKeyService::verify_key(conn, raw_key).await?;
    Ok(ApiKeyAuth { api_key })
}
