use crate::OidcError;

/// Email sending trait for password reset and email verification.
/// Implementations can use SMTP, API-based services, or be no-ops for testing.
#[async_trait::async_trait]
pub trait EmailSender: Send + Sync {
    /// Send a password reset email.
    /// `to` is the recipient's email address.
    /// `reset_url` is the full URL the user should click to reset their password.
    async fn send_password_reset_email(&self, to: &str, reset_url: &str) -> Result<(), OidcError>;

    /// Send an email verification email.
    /// `to` is the recipient's email address.
    /// `verification_url` is the full URL the user should click to verify their email.
    async fn send_email_verification(
        &self,
        to: &str,
        verification_url: &str,
    ) -> Result<(), OidcError>;
}
