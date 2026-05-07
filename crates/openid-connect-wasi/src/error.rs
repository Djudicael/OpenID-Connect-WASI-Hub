//! Global error handling and HTTP response mapping.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use oidc_core::OidcError;
use serde_json::json;
use tracing::error;

/// A wrapper around [`OidcError`] that implements [`IntoResponse`].
pub struct AppError(pub OidcError);

impl From<OidcError> for AppError {
    fn from(err: OidcError) -> Self {
        AppError(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match &self.0 {
            OidcError::AuthenticationFailed(msg) => (
                StatusCode::UNAUTHORIZED,
                json!({"error": "invalid_client", "error_description": msg}),
            ),
            OidcError::AuthorizationDenied(msg) => (
                StatusCode::FORBIDDEN,
                json!({"error": "access_denied", "error_description": msg}),
            ),
            OidcError::InvalidInput(msg) => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_request", "error_description": msg}),
            ),
            OidcError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                json!({"error": "not_found", "error_description": msg}),
            ),
            OidcError::Conflict(msg) => (
                StatusCode::CONFLICT,
                json!({"error": "conflict", "error_description": msg}),
            ),
            OidcError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                json!({"error": "invalid_token", "error_description": "token expired"}),
            ),
            OidcError::InvalidTokenSignature => (
                StatusCode::UNAUTHORIZED,
                json!({"error": "invalid_token", "error_description": "invalid signature"}),
            ),
            OidcError::Internal(msg) => {
                error!("internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "server_error", "error_description": "internal server error"}),
                )
            }
            _ => {
                error!("unexpected error variant");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "server_error", "error_description": "internal server error"}),
                )
            }
        };

        (status, Json(body)).into_response()
    }
}

/// A convenience result type for handlers.
pub type AppResult<T> = Result<T, AppError>;
