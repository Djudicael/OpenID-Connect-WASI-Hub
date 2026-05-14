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

/// Generic message returned to clients when an internal error occurs.
const INTERNAL_ERROR_MESSAGE: &str = "An internal error occurred";

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

    /// Temporarily unavailable.
    pub fn temporarily_unavailable(description: impl Into<String>) -> Self {
        Self {
            error: "temporarily_unavailable".to_string(),
            error_description: Some(description.into()),
            error_uri: None,
        }
    }

    /// Create a sanitized error response from an internal error.
    ///
    /// Logs the real error with `tracing::error!` and returns a generic
    /// `server_error` response that does **not** expose internal details
    /// (PostgreSQL errors, stack traces, etc.) to the client.
    pub fn from_internal(internal_error: impl std::fmt::Display) -> Self {
        tracing::error!("Internal error: {}", internal_error);
        Self {
            error: "server_error".to_string(),
            error_description: Some(INTERNAL_ERROR_MESSAGE.to_string()),
            error_uri: None,
        }
    }

    /// Return the HTTP status code for this error variant.
    ///
    /// Maps per RFC 6749 §5.2 and common OIDC practice:
    /// - `invalid_request` → 400
    /// - `invalid_client` → 401
    /// - `invalid_grant` → 400
    /// - `invalid_scope` → 400
    /// - `unauthorized_client` → 403
    /// - `access_denied` → 403
    /// - `server_error` → 500
    /// - `temporarily_unavailable` → 503
    pub fn http_status(&self) -> u16 {
        match self.error.as_str() {
            "invalid_request" | "invalid_grant" | "invalid_scope" | "unsupported_grant_type" => 400,
            "invalid_client" => 401,
            "unauthorized_client" | "access_denied" => 403,
            "server_error" => 500,
            "temporarily_unavailable" => 503,
            _ => 500,
        }
    }
}

impl IntoResponse for OidcErrorResponse {
    fn into_response(self) -> Response {
        let status = self.http_status();
        (
            axum::http::StatusCode::from_u16(status)
                .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
            Json(json!(self)),
        )
            .into_response()
    }
}

/// Convert domain errors into OIDC error responses.
///
/// Internal errors are logged but **never** exposed to the client.
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
        OidcError::UnauthorizedClient => {
            OidcErrorResponse::unauthorized_client("Client is not authorized for this grant type")
        }
        OidcError::InvalidScope(msg) => OidcErrorResponse::invalid_scope(msg),
        OidcError::AuthenticationFailed(_msg) => {
            // Do not expose the internal reason — just say credentials are invalid
            OidcErrorResponse::invalid_grant("Invalid credentials")
        }
        OidcError::TokenExpired => OidcErrorResponse::invalid_grant("Token has expired"),
        OidcError::InvalidTokenSignature => OidcErrorResponse::invalid_grant("Invalid token"),
        OidcError::AuthorizationDenied(msg) => OidcErrorResponse::access_denied(msg),
        OidcError::NotFound(_msg) => OidcErrorResponse::invalid_request("Resource not found"),
        OidcError::Conflict(_msg) => {
            tracing::warn!("Conflict error: {}", _msg);
            OidcErrorResponse::invalid_request("A resource with that identifier already exists")
        }
        OidcError::InvalidInput(msg) => {
            OidcErrorResponse::invalid_request(format!("Invalid input: {msg}"))
        }
        OidcError::InvalidClientAssertion(_) => {
            OidcErrorResponse::invalid_client("Invalid client assertion")
        }
        OidcError::Internal(msg) => OidcErrorResponse::from_internal(msg),
        _ => OidcErrorResponse::from_internal("unknown error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- http_status tests ----

    #[test]
    fn test_http_status_invalid_request() {
        let err = OidcErrorResponse::invalid_request("bad");
        assert_eq!(err.http_status(), 400);
    }

    #[test]
    fn test_http_status_invalid_grant() {
        let err = OidcErrorResponse::invalid_grant("expired");
        assert_eq!(err.http_status(), 400);
    }

    #[test]
    fn test_http_status_invalid_scope() {
        let err = OidcErrorResponse::invalid_scope("bad scope");
        assert_eq!(err.http_status(), 400);
    }

    #[test]
    fn test_http_status_unsupported_grant_type() {
        let err = OidcErrorResponse::unsupported_grant_type();
        assert_eq!(err.http_status(), 400);
    }

    #[test]
    fn test_http_status_invalid_client() {
        let err = OidcErrorResponse::invalid_client("bad creds");
        assert_eq!(err.http_status(), 401);
    }

    #[test]
    fn test_http_status_unauthorized_client() {
        let err = OidcErrorResponse::unauthorized_client("forbidden");
        assert_eq!(err.http_status(), 403);
    }

    #[test]
    fn test_http_status_access_denied() {
        let err = OidcErrorResponse::access_denied("no");
        assert_eq!(err.http_status(), 403);
    }

    #[test]
    fn test_http_status_server_error() {
        let err = OidcErrorResponse::server_error("oops");
        assert_eq!(err.http_status(), 500);
    }

    #[test]
    fn test_http_status_temporarily_unavailable() {
        let err = OidcErrorResponse::temporarily_unavailable("maintenance");
        assert_eq!(err.http_status(), 503);
    }

    #[test]
    fn test_http_status_unknown_falls_back_to_500() {
        let err = OidcErrorResponse {
            error: "some_new_error".to_string(),
            error_description: None,
            error_uri: None,
        };
        assert_eq!(err.http_status(), 500);
    }

    // ---- from_internal sanitization tests ----

    #[test]
    fn test_from_internal_returns_generic_message() {
        let err = OidcErrorResponse::from_internal(
            "PostgreSQL error: connection refused to db.example.com:5432",
        );
        assert_eq!(err.error, "server_error");
        assert_eq!(
            err.error_description.as_deref(),
            Some(INTERNAL_ERROR_MESSAGE)
        );
    }

    #[test]
    fn test_from_internal_does_not_expose_postgres_details() {
        let internal_msg =
            "FATAL: password authentication failed for user \"admin\" (db host: prod-db.internal)";
        let err = OidcErrorResponse::from_internal(internal_msg);
        let body = serde_json::to_string(&err).unwrap();
        assert!(
            !body.contains("admin"),
            "Response body must not contain user names"
        );
        assert!(
            !body.contains("prod-db.internal"),
            "Response body must not contain hostnames"
        );
        assert!(
            !body.contains("password"),
            "Response body must not contain password-related strings"
        );
    }

    #[test]
    fn test_from_internal_does_not_expose_stack_trace() {
        let internal_msg = "called `Result::unwrap()` on an `Err` value: Os { code: 111, kind: ConnectionRefused, message: \"Connection refused\" } at src/db.rs:42";
        let err = OidcErrorResponse::from_internal(internal_msg);
        let body = serde_json::to_string(&err).unwrap();
        assert!(
            !body.contains("src/db.rs"),
            "Response body must not contain file paths"
        );
        assert!(
            !body.contains("unwrap"),
            "Response body must not contain Rust internals"
        );
    }

    #[test]
    fn test_from_oidc_error_internal_is_sanitized() {
        let internal = oidc_core::OidcError::Internal(
            "PostgreSQL error: relation \"users\" does not exist".to_string(),
        );
        let err = from_oidc_error(&internal);
        assert_eq!(err.error, "server_error");
        assert_eq!(
            err.error_description.as_deref(),
            Some(INTERNAL_ERROR_MESSAGE)
        );
        let body = serde_json::to_string(&err).unwrap();
        assert!(!body.contains("PostgreSQL"));
        assert!(!body.contains("users"));
    }

    #[test]
    fn test_from_oidc_error_non_internal_preserves_description() {
        let err = from_oidc_error(&oidc_core::OidcError::InvalidRequest);
        assert_eq!(err.error, "invalid_request");
        assert!(err.error_description.is_some());
    }

    #[test]
    fn test_from_oidc_error_invalid_scope_preserves_message() {
        let err = from_oidc_error(&oidc_core::OidcError::InvalidScope("profile".to_string()));
        assert_eq!(err.error, "invalid_scope");
        assert_eq!(err.error_description.as_deref(), Some("profile"));
    }

    #[test]
    fn test_from_oidc_error_token_expired() {
        let err = from_oidc_error(&oidc_core::OidcError::TokenExpired);
        assert_eq!(err.error, "invalid_grant");
        assert_eq!(err.http_status(), 400);
    }

    #[test]
    fn test_from_oidc_error_invalid_token_signature() {
        let err = from_oidc_error(&oidc_core::OidcError::InvalidTokenSignature);
        assert_eq!(err.error, "invalid_grant");
        assert_eq!(err.http_status(), 400);
    }

    #[test]
    fn test_from_oidc_error_authentication_failed_is_sanitized() {
        let err = from_oidc_error(&oidc_core::OidcError::AuthenticationFailed(
            "wrong password".to_string(),
        ));
        assert_eq!(err.error, "invalid_grant");
        assert_eq!(err.http_status(), 400);
        // Must NOT expose the internal reason
        let body = serde_json::to_string(&err).unwrap();
        assert!(
            !body.contains("wrong password"),
            "Must not expose internal auth failure reason"
        );
        assert_eq!(
            err.error_description.as_deref(),
            Some("Invalid credentials")
        );
    }

    #[test]
    fn test_from_oidc_error_access_denied() {
        let err = from_oidc_error(&oidc_core::OidcError::AuthorizationDenied(
            "user disabled".to_string(),
        ));
        assert_eq!(err.error, "access_denied");
        assert_eq!(err.http_status(), 403);
    }

    #[test]
    fn test_from_oidc_error_invalid_client() {
        let err = from_oidc_error(&oidc_core::OidcError::InvalidClient);
        assert_eq!(err.error, "invalid_client");
        assert_eq!(err.http_status(), 401);
    }

    #[test]
    fn test_from_oidc_error_unauthorized_client() {
        let err = from_oidc_error(&oidc_core::OidcError::UnauthorizedClient);
        assert_eq!(err.error, "unauthorized_client");
        assert_eq!(err.http_status(), 403);
    }

    #[test]
    fn test_from_oidc_error_conflict_is_sanitized() {
        let err = from_oidc_error(&oidc_core::OidcError::Conflict(
            "duplicate key value violates unique constraint \"clients_client_id_key\"".to_string(),
        ));
        assert_eq!(err.error, "invalid_request");
        let body = serde_json::to_string(&err).unwrap();
        assert!(
            !body.contains("clients_client_id_key"),
            "Conflict response must not expose constraint names"
        );
        assert!(
            !body.contains("duplicate key"),
            "Conflict response must not expose DB internals"
        );
    }

    #[test]
    fn test_from_oidc_error_not_found_is_sanitized() {
        let err = from_oidc_error(&oidc_core::OidcError::NotFound(
            "users table row with id=abc-123".to_string(),
        ));
        assert_eq!(err.error, "invalid_request");
        let body = serde_json::to_string(&err).unwrap();
        assert!(
            !body.contains("users table"),
            "NotFound response must not expose table names"
        );
        assert!(
            !body.contains("abc-123"),
            "NotFound response must not expose record IDs"
        );
    }
}
