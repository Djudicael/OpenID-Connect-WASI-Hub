//! Token service trait and related types.

use crate::errors::OidcError;
use async_trait::async_trait;

/// Claims to include in an ID token.
#[derive(Debug, Clone, Default)]
pub struct IdTokenExtraClaims {
    /// `nonce` from the authorization request.
    pub nonce: Option<String>,
    /// `at_hash` — left-half hash of access token.
    pub at_hash: Option<String>,
    /// `c_hash` — left-half hash of authorization code.
    pub c_hash: Option<String>,
    /// `auth_time` — when the user authenticated (Unix seconds).
    pub auth_time: Option<i64>,
    /// User email.
    pub email: Option<String>,
    /// Whether email is verified.
    pub email_verified: Option<bool>,
    /// User display name.
    pub name: Option<String>,
    /// User given name.
    pub given_name: Option<String>,
    /// User family name.
    pub family_name: Option<String>,
}

/// Verified access token claims returned by the token service.
#[derive(Debug, Clone)]
pub struct VerifiedAccessToken {
    /// Subject (user or client identifier).
    pub sub: String,
    /// Audience (client_id the token was issued to).
    pub aud: String,
    /// Issuer.
    pub iss: String,
    /// Expiration timestamp (seconds since epoch).
    pub exp: i64,
    /// Issued-at timestamp (seconds since epoch).
    pub iat: i64,
    /// Space-separated scope string.
    pub scope: String,
}

/// Abstract token issuance and verification service.
#[async_trait]
pub trait TokenService: Send + Sync {
    /// Issue an access token for the given subject and audience.
    async fn issue_access_token(
        &self,
        subject: &str,
        audience: &str,
        scopes: &[String],
    ) -> Result<String, OidcError>;

    /// Verify an access token and return the subject.
    async fn verify_access_token(&self, token: &str) -> Result<String, OidcError>;

    /// Verify an access token and return the full claims.
    async fn verify_access_token_with_claims(
        &self,
        token: &str,
    ) -> Result<VerifiedAccessToken, OidcError>;

    /// Issue an ID token.
    async fn issue_id_token(
        &self,
        subject: &str,
        audience: &str,
        extra: Option<IdTokenExtraClaims>,
    ) -> Result<String, OidcError>;

    /// Verify an ID token and return the subject.
    async fn verify_id_token(&self, token: &str) -> Result<String, OidcError>;
}
