use crate::errors::OidcError;
use async_trait::async_trait;

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

    /// Issue an ID token.
    async fn issue_id_token(
        &self,
        subject: &str,
        audience: &str,
        nonce: Option<&str>,
    ) -> Result<String, OidcError>;
}
