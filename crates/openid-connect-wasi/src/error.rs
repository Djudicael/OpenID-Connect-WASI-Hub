//! Global error handler mapping domain errors to HTTP responses.

use axum::{
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Convert any `oidc_core::OidcError` into an HTTP response.
pub fn into_response(e: oidc_core::OidcError) -> Response {
    let oidc_err = oidc_oidc::errors::from_oidc_error(&e);
    oidc_err.into_response()
}

/// A wrapper type that implements `IntoResponse` for `oidc_core::OidcError`.
pub struct AppError(pub oidc_core::OidcError);

impl From<oidc_core::OidcError> for AppError {
    fn from(e: oidc_core::OidcError) -> Self {
        Self(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        into_response(self.0)
    }
}

/// Health check error response.
pub fn health_error(msg: &str) -> Response {
    (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(json!({"status": "error", "message": msg}))).into_response()
}
