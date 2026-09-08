use crate::OidcError;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EmailMessage {
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
}

/// Transport abstraction for transactional email.
/// Implementations can use SMTP, API-based services, or be no-ops for testing.
#[async_trait::async_trait]
pub trait EmailSender: Send + Sync {
    async fn send_email(&self, to: &str, message: &EmailMessage) -> Result<(), OidcError>;

    /// Send a password reset email.
    /// `to` is the recipient's email address.
    /// `reset_url` is the full URL the user should click to reset their password.
    async fn send_password_reset_email(&self, to: &str, reset_url: &str) -> Result<(), OidcError> {
        self.send_email(
            to,
            &EmailMessage {
                subject: "Reset your password".into(),
                text: format!("Use this link to reset your password:\n\n{reset_url}"),
                html: None,
            },
        )
        .await
    }

    /// Send an email verification email.
    /// `to` is the recipient's email address.
    /// `verification_url` is the full URL the user should click to verify their email.
    async fn send_email_verification(
        &self,
        to: &str,
        verification_url: &str,
    ) -> Result<(), OidcError> {
        self.send_email(
            to,
            &EmailMessage {
                subject: "Verify your email address".into(),
                text: format!("Use this link to verify your email address:\n\n{verification_url}"),
                html: None,
            },
        )
        .await
    }

    /// Send an invitation to join an organization.
    async fn send_organization_invitation(
        &self,
        to: &str,
        organization_name: &str,
        invitation_url: &str,
    ) -> Result<(), OidcError> {
        self.send_email(
            to,
            &EmailMessage {
                subject: format!("Invitation to join {organization_name}"),
                text: format!(
                    "You have been invited to join {organization_name}.\n\nAccept the invitation:\n{invitation_url}"
                ),
                html: None,
            },
        )
        .await
    }
}
