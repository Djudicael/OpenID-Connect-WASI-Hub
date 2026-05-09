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

/// Custom rejection type for API key authentication.
#[derive(Debug, Clone)]
pub enum ApiKeyError {
    /// Missing API key header.
    Missing,
    /// Invalid key format or signature.
    Invalid,
    /// Key expired or revoked.
    Inactive,
    /// Insufficient scope for the requested operation.
    InsufficientScope,
}

impl axum::response::IntoResponse for ApiKeyError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ApiKeyError::Missing => (StatusCode::UNAUTHORIZED, "Missing API key".to_string()),
            ApiKeyError::Invalid => (StatusCode::UNAUTHORIZED, "Invalid API key".to_string()),
            ApiKeyError::Inactive => (
                StatusCode::UNAUTHORIZED,
                "API key expired or revoked".to_string(),
            ),
            ApiKeyError::InsufficientScope => {
                (StatusCode::FORBIDDEN, "insufficient_scope".to_string())
            }
        };

        let body = axum::Json(serde_json::json!({
            "error": message,
            "status": status.as_u16(),
        }));

        let mut response = (status, body).into_response();
        if matches!(
            self,
            ApiKeyError::Missing | ApiKeyError::Invalid | ApiKeyError::Inactive
        ) {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer"),
            );
        }
        response
    }
}

/// State trait required for the API key extractor.
///
/// The concrete `AppState` must implement this.
pub trait ApiKeyVerifierState: Clone + Send + Sync + 'static {
    /// Obtain a database configuration so we can open a per-request connection.
    fn db_config(&self) -> &wasi_pg_client::Config;
}

impl<S: ApiKeyVerifierState> FromRequestParts<S> for ApiKeyAuth {
    type Rejection = ApiKeyError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let raw_key = extract_raw_key(parts).ok_or(ApiKeyError::Missing)?;

        let conn = wasi_pg_client::Connection::connect(state.db_config())
            .await
            .map_err(|_| ApiKeyError::Invalid)?;
        let mut conn = Connection::from_pg_client(conn);

        let api_key = ApiKeyService::verify_key(&mut conn, &raw_key)
            .await
            .map_err(|e| match e {
                oidc_core::OidcError::AuthenticationFailed(msg) => {
                    if msg.contains("expired")
                        || msg.contains("revoked")
                        || msg.contains("rotation")
                    {
                        ApiKeyError::Inactive
                    } else {
                        ApiKeyError::Invalid
                    }
                }
                _ => ApiKeyError::Invalid,
            })?;

        // Best-effort usage tracking (fire-and-forget)
        let _ = ApiKeyService::increment_usage(&mut conn, api_key.id).await;

        Ok(ApiKeyAuth { api_key })
    }
}

/// Extract the raw API key string from request parts.
///
/// Supports:
/// - `X-API-Key: <key>`
/// - `Authorization: Bearer <key>`
pub fn extract_raw_key(parts: &Parts) -> Option<String> {
    // Check X-API-Key first
    if let Some(header) = parts.headers.get("X-API-Key") {
        if let Ok(val) = header.to_str() {
            return Some(val.trim().to_string());
        }
    }

    // Fall back to Authorization: Bearer <key>
    if let Some(header) = parts.headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.trim().to_string());
            }
            if let Some(token) = auth_str.strip_prefix("bearer ") {
                return Some(token.trim().to_string());
            }
        }
    }

    None
}

/// Extract the raw API key string from a `HeaderMap`.
///
/// This is the shared version used by both the extractor and the router.
/// It only treats Bearer tokens without dots as API keys (JWTs contain dots).
///
/// Supports:
/// - `X-API-Key: <key>`
/// - `Authorization: Bearer <key>` (only if the token does not contain dots)
pub fn extract_raw_key_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    // Check X-API-Key first
    if let Some(header) = headers.get("X-API-Key") {
        if let Ok(val) = header.to_str() {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    // Check Authorization: Bearer <key>
    // Only treat as API key if the token does NOT contain dots (JWTs have dots)
    if let Some(header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let trimmed = token.trim();
                if !trimmed.is_empty() && !trimmed.contains('.') {
                    return Some(trimmed.to_string());
                }
            }
            if let Some(token) = auth_str.strip_prefix("bearer ") {
                let trimmed = token.trim();
                if !trimmed.is_empty() && !trimmed.contains('.') {
                    return Some(trimmed.to_string());
                }
            }
        }
    }

    None
}

/// Verify a request's authentication — either via API key or JWT Bearer token.
///
/// This is the shared logic used by the router to authenticate API key routes.
/// Returns the authenticated identity as an `ApiRouteAuth` enum.
///
/// # Arguments
/// * `headers` - The request headers
/// * `db_config` - Database configuration for opening a connection
/// * `token_service` - The JWT token service for verifying Bearer tokens
pub async fn verify_request_auth<S: oidc_core::traits::TokenService + Sync>(
    headers: &axum::http::HeaderMap,
    db_config: &wasi_pg_client::Config,
    token_service: &S,
) -> Result<ApiRouteAuth, StatusCode> {
    // Try API key first
    if let Some(raw_key) = extract_raw_key_from_headers(headers) {
        let conn = wasi_pg_client::Connection::connect(db_config)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let mut conn = Connection::from_pg_client(conn);

        let api_key = ApiKeyService::verify_key(&mut conn, &raw_key)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        // Best-effort usage tracking
        let _ = ApiKeyService::increment_usage(&mut conn, api_key.id).await;

        return Ok(ApiRouteAuth::ApiKey(ApiKeyAuth { api_key }));
    }

    // Try JWT Bearer token
    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                match token_service.verify_access_token(token).await {
                    Ok(subject) => {
                        return Ok(ApiRouteAuth::JwtBearer { subject });
                    }
                    Err(e) => {
                        tracing::debug!("JWT verification failed for API route: {}", e);
                    }
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Authentication result for API key routes.
///
/// Represents either an API key or a JWT Bearer token authentication.
#[derive(Debug)]
pub enum ApiRouteAuth {
    /// Authenticated via API key.
    ApiKey(ApiKeyAuth),
    /// Authenticated via JWT Bearer token.
    JwtBearer { subject: String },
}

/// Check if an API key has the required scope.
///
/// Supports wildcard `*` scope.
pub fn has_scope(api_key: &ApiKey, required: &str) -> bool {
    api_key.scopes.contains(&"*".to_string()) || api_key.scopes.contains(&required.to_string())
}

/// Scope guard that returns an error if the API key lacks the required scope.
pub fn require_scope(api_key: &ApiKey, scope: &str) -> Result<(), ApiKeyError> {
    if has_scope(api_key, scope) {
        Ok(())
    } else {
        Err(ApiKeyError::InsufficientScope)
    }
}
