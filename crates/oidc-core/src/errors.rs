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

    /// Internal server error.
    #[error("internal error: {0}")]
    Internal(String),
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
}
