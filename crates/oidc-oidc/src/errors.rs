//! OIDC-specific error responses per RFC 6749 / RFC 6750.

use axum::{
    Json,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// OAuth2 error response body.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OidcErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

impl OidcErrorResponse {
    /// Invalid request.
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_request".to_string(),
            error_description: Some(description.into()),
            error_uri: None,
        }
    }

    /// Invalid client.
    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_client".to_string(),
            error_description: Some(description.into()),
            error_uri: None,
        }
    }

    /// Invalid grant.
    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_grant".to_string(),
            error_description: Some(description.into()),
            error_uri: None,
        }
    }

    /// Unauthorized client.
    pub fn unauthorized_client(description: impl Into<String>) -> Self {
        Self {
            error: "unauthorized_client".to_string(),
            error_description: Some(description.into()),
            error_uri: None,
        }
    }

    /// Unsupported grant type.
    pub fn unsupported_grant_type() -> Self {
        Self {
            error: "unsupported_grant_type".to_string(),
            error_description: Some("The authorization grant type is not supported".to_string()),
            error_uri: None,
        }
    }

    /// Invalid scope.
    pub fn invalid_scope(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_scope".to_string(),
            error_description: Some(description.into()),
            error_uri: None,
        }
    }

    /// Access denied.
    pub fn access_denied(description: impl Into<String>) -> Self {
        Self {
            error: "access_denied".to_string(),
            error_description: Some(description.into()),
            error_uri: None,
        }
    }

    /// Server error.
    pub fn server_error(description: impl Into<String>) -> Self {
        Self {
            error: "server_error".to_string(),
            error_description: Some(description.into()),
            error_uri: None,
        }
    }
}

impl IntoResponse for OidcErrorResponse {
    fn into_response(self) -> Response {
        let status = match self.error.as_str() {
            "invalid_request" | "invalid_grant" | "invalid_scope" => 400,
            "invalid_client" | "unauthorized_client" => 401,
            "access_denied" => 403,
            "unsupported_grant_type" => 400,
            _ => 500,
        };
        (
            axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::BAD_REQUEST),
            Json(json!(self)),
        )
            .into_response()
    }
}

/// Convert domain errors into OIDC error responses.
pub fn from_oidc_error(e: &oidc_core::OidcError) -> OidcErrorResponse {
    use oidc_core::OidcError;
    match e {
        OidcError::InvalidRequest => {
            OidcErrorResponse::invalid_request("Invalid request parameters")
        }
        OidcError::InvalidClient => {
            OidcErrorResponse::invalid_client("Client authentication failed")
        }
        OidcError::UnsupportedGrantType => OidcErrorResponse::unsupported_grant_type(),
        OidcError::InvalidScope(msg) => OidcErrorResponse::invalid_scope(msg),
        OidcError::AuthenticationFailed(msg) => {
            OidcErrorResponse::invalid_grant(format!("Authentication failed: {msg}"))
        }
        OidcError::TokenExpired => OidcErrorResponse::invalid_grant("Token has expired"),
        OidcError::InvalidTokenSignature => OidcErrorResponse::invalid_grant("Invalid token"),
        OidcError::AuthorizationDenied(msg) => OidcErrorResponse::access_denied(msg),
        OidcError::NotFound(msg) => OidcErrorResponse::invalid_request(format!("Not found: {msg}")),
        OidcError::Conflict(msg) => OidcErrorResponse::invalid_request(format!("Conflict: {msg}")),
        OidcError::InvalidInput(msg) => {
            OidcErrorResponse::invalid_request(format!("Invalid input: {msg}"))
        }
        OidcError::Internal(msg) => {
            OidcErrorResponse::server_error(format!("Internal error: {msg}"))
        }
        _ => OidcErrorResponse::server_error("unknown error"),
    }
}
