use crate::OidcError;
use crate::traits::email::EmailSender;

/// A no-op email sender that logs but doesn't actually send emails.
/// Useful for development and testing.
pub struct NoOpEmailSender;

#[async_trait::async_trait]
impl EmailSender for NoOpEmailSender {
    async fn send_password_reset_email(&self, to: &str, reset_url: &str) -> Result<(), OidcError> {
        tracing::info!("Password reset email to {}: {}", to, reset_url);
        Ok(())
    }

    async fn send_email_verification(
        &self,
        to: &str,
        verification_url: &str,
    ) -> Result<(), OidcError> {
        tracing::info!("Email verification to {}: {}", to, verification_url);
        Ok(())
    }
}
