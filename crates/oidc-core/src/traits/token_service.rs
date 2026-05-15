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
    /// `sid` — Session ID per OIDC Session Management §3.
    /// Included when the client supports front/back-channel logout.
    pub sid: Option<String>,
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
    /// User middle name.
    pub middle_name: Option<String>,
    /// User nickname.
    pub nickname: Option<String>,
    /// User preferred username.
    pub preferred_username: Option<String>,
    /// User profile URL.
    pub profile: Option<String>,
    /// User picture URL.
    pub picture: Option<String>,
    /// User website URL.
    pub website: Option<String>,
    /// User gender.
    pub gender: Option<String>,
    /// User birthdate (ISO-8601).
    pub birthdate: Option<String>,
    /// User zoneinfo (IANA TZ).
    pub zoneinfo: Option<String>,
    /// User locale.
    pub locale: Option<String>,
    /// User phone number.
    pub phone_number: Option<String>,
    /// Whether phone number is verified.
    pub phone_number_verified: Option<bool>,
    /// When the user record was last updated (Unix seconds).
    pub updated_at: Option<i64>,
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
    /// Confirmation claim for DPoP-bound tokens (RFC 9449).
    /// Contains `{"jkt": "<thumbprint>"}` when the token is sender-constrained.
    pub cnf: Option<serde_json::Value>,
}

/// Abstract token issuance and verification service.
#[async_trait]
pub trait TokenService: Send + Sync {
    /// Issue an access token for the given subject and audience.
    /// When `dpop_jkt` is provided, the token is bound to the DPoP key
    /// via a `cnf` claim containing `{"jkt": "<thumbprint>"}` (RFC 9449).
    async fn issue_access_token(
        &self,
        subject: &str,
        audience: &str,
        scopes: &[String],
        dpop_jkt: Option<&str>,
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
