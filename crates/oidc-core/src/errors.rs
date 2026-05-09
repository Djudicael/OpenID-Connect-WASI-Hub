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
