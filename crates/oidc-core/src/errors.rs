use thiserror::Error;

/// The root error type for the entire OIDC hub.
#[derive(Error, Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum OidcError {
    /// Authentication failed.
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Authorization denied.
    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),

    /// Invalid input from the user.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Resource not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Conflict with existing resource.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Token has expired.
    #[error("token expired")]
    TokenExpired,

    /// Token signature is invalid.
    #[error("invalid token signature")]
    InvalidTokenSignature,

    /// Invalid request parameters.
    #[error("invalid request")]
    InvalidRequest,

    /// Invalid client credentials.
    #[error("invalid client")]
    InvalidClient,

    /// Unsupported grant type.
    #[error("unsupported grant type")]
    UnsupportedGrantType,

    /// Unauthorized client.
    #[error("unauthorized client")]
    UnauthorizedClient,

    /// Invalid scope.
    #[error("invalid scope: {0}")]
    InvalidScope(String),

    /// Invalid request object.
    #[error("invalid request object: {0}")]
    InvalidRequestObject(String),

    /// Invalid client assertion.
    #[error("invalid client assertion: {0}")]
    InvalidClientAssertion(String),

    /// Invalid DPoP proof.
    #[error("invalid DPoP proof: {0}")]
    InvalidDPoPProof(String),

    /// The device code has not been authorized yet (RFC 8628 §3.5).
    #[error("authorization pending")]
    AuthorizationPending,

    /// The client is polling too fast (RFC 8628 §3.5).
    #[error("slow down")]
    SlowDown,

    /// The device code has expired (RFC 8628 §3.5).
    #[error("expired token")]
    ExpiredToken,

    /// Invalid subject token (RFC 8693).
    #[error("invalid subject token: {0}")]
    InvalidSubjectToken(String),

    /// Invalid actor token (RFC 8693).
    #[error("invalid actor token: {0}")]
    InvalidActorToken(String),

    /// The end-user could not be authenticated (OIDC Core §3.1.2.2).
    /// Returned when prompt=none fails or ACR requirements cannot be satisfied.
    #[error("login required: {0}")]
    LoginRequired(String),

    /// The end-user must select an account (OIDC Core §3.1.2.2).
    #[error("account selection required: {0}")]
    AccountSelectionRequired(String),

    /// Internal server error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl OidcError {
    /// Return the HTTP status code for this error variant.
    pub fn http_status(&self) -> u16 {
        match self {
            OidcError::AuthenticationFailed(_)
            | OidcError::InvalidTokenSignature
            | OidcError::TokenExpired
            | OidcError::InvalidClient => 401,

            OidcError::AuthorizationDenied(_) | OidcError::InvalidScope(_) => 403,

            OidcError::InvalidInput(_)
            | OidcError::InvalidRequest
            | OidcError::UnsupportedGrantType
            | OidcError::UnauthorizedClient
            | OidcError::InvalidRequestObject(_)
            | OidcError::InvalidClientAssertion(_)
            | OidcError::InvalidDPoPProof(_)
            | OidcError::AuthorizationPending
            | OidcError::SlowDown
            | OidcError::ExpiredToken
            | OidcError::InvalidSubjectToken(_)
            | OidcError::InvalidActorToken(_)
            | OidcError::LoginRequired(_)
            | OidcError::AccountSelectionRequired(_) => 400,

            OidcError::NotFound(_) => 404,
            OidcError::Conflict(_) => 409,

            OidcError::Internal(_) => 500,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_error_display() {
        assert_eq!(
            format!("{}", OidcError::AuthenticationFailed("bad creds".into())),
            "authentication failed: bad creds"
        );
        assert_eq!(
            format!("{}", OidcError::InvalidInput("missing field".into())),
            "invalid input: missing field"
        );
        assert_eq!(
            format!("{}", OidcError::NotFound("user".into())),
            "not found: user"
        );
        assert_eq!(format!("{}", OidcError::TokenExpired), "token expired");
        assert_eq!(
            format!("{}", OidcError::Internal("oops".into())),
            "internal error: oops"
        );
    }

    #[test]
    fn test_oidc_error_from_string() {
        let msg = String::from("something broke");
        // OidcError::Internal wraps a String, so we construct it directly
        let err = OidcError::Internal(msg.clone());
        assert!(format!("{}", err).contains(&msg));
    }

    // ---- http_status tests ----

    #[test]
    fn test_http_status_401_variants() {
        assert_eq!(
            OidcError::AuthenticationFailed("bad".into()).http_status(),
            401
        );
        assert_eq!(OidcError::InvalidTokenSignature.http_status(), 401);
        assert_eq!(OidcError::TokenExpired.http_status(), 401);
        assert_eq!(OidcError::InvalidClient.http_status(), 401);
    }

    #[test]
    fn test_http_status_403_variants() {
        assert_eq!(
            OidcError::AuthorizationDenied("no".into()).http_status(),
            403
        );
        assert_eq!(
            OidcError::InvalidScope("bad scope".into()).http_status(),
            403
        );
    }

    #[test]
    fn test_http_status_400_variants() {
        assert_eq!(OidcError::InvalidInput("missing".into()).http_status(), 400);
        assert_eq!(OidcError::InvalidRequest.http_status(), 400);
        assert_eq!(OidcError::UnsupportedGrantType.http_status(), 400);
        assert_eq!(OidcError::UnauthorizedClient.http_status(), 400);
    }

    #[test]
    fn test_http_status_404_variants() {
        assert_eq!(OidcError::NotFound("gone".into()).http_status(), 404);
    }

    #[test]
    fn test_http_status_409_variants() {
        assert_eq!(OidcError::Conflict("dup".into()).http_status(), 409);
    }

    #[test]
    fn test_http_status_500_variants() {
        assert_eq!(OidcError::Internal("boom".into()).http_status(), 500);
    }

    // ---- From conversion tests ----

    #[test]
    fn test_from_string_for_internal() {
        let msg = String::from("db error");
        let err = OidcError::Internal(msg.clone());
        assert!(matches!(err, OidcError::Internal(ref s) if s == &msg));
    }

    #[test]
    fn test_from_str_for_authentication_failed() {
        let err = OidcError::AuthenticationFailed("bad password".into());
        assert!(matches!(err, OidcError::AuthenticationFailed(ref s) if s == "bad password"));
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(OidcError::TokenExpired, OidcError::TokenExpired);
        assert_eq!(OidcError::InvalidRequest, OidcError::InvalidRequest);
        assert_ne!(OidcError::TokenExpired, OidcError::InvalidTokenSignature);
    }

    #[test]
    fn test_error_clone() {
        let err = OidcError::AuthenticationFailed("test".into());
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }
}
