use oidc_core::OidcError;
use oidc_core::traits::EmailSender;
use serde_json::json;

/// Transactional email sender backed by the Resend HTTP API.
pub struct ResendEmailSender {
    api_key: String,
    from: String,
    endpoint: String,
}

impl ResendEmailSender {
    pub fn new(api_key: String, from: String, endpoint: Option<String>) -> Self {
        Self {
            api_key,
            from,
            endpoint: endpoint.unwrap_or_else(|| "https://api.resend.com/emails".into()),
        }
    }

    async fn send(&self, to: &str, subject: &str, text: String) -> Result<(), OidcError> {
        let body = json!({
            "from": self.from,
            "to": [to],
            "subject": subject,
            "text": text,
        })
        .to_string();

        #[cfg(not(target_arch = "wasm32"))]
        {
            let response = reqwest::Client::new()
                .post(&self.endpoint)
                .bearer_auth(&self.api_key)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|error| OidcError::Internal(format!("email request failed: {error}")))?;
            if !response.status().is_success() {
                return Err(OidcError::Internal(format!(
                    "email provider returned HTTP {}",
                    response.status().as_u16()
                )));
            }
        }

        #[cfg(target_arch = "wasm32")]
        {
            let request = wstd::http::Request::post(&self.endpoint)
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .body(wstd::http::Body::from(body.into_bytes()))
                .map_err(|error| {
                    OidcError::Internal(format!("email request build failed: {error}"))
                })?;
            let response = wstd::http::Client::new()
                .send(request)
                .await
                .map_err(|error| OidcError::Internal(format!("email request failed: {error}")))?;
            if !response.status().is_success() {
                return Err(OidcError::Internal(format!(
                    "email provider returned HTTP {}",
                    response.status().as_u16()
                )));
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl EmailSender for ResendEmailSender {
    async fn send_password_reset_email(&self, to: &str, reset_url: &str) -> Result<(), OidcError> {
        self.send(
            to,
            "Reset your password",
            format!("Use this link to reset your password:\n\n{reset_url}\n\nIf you did not request this, ignore this email."),
        )
        .await
    }

    async fn send_email_verification(
        &self,
        to: &str,
        verification_url: &str,
    ) -> Result<(), OidcError> {
        self.send(
            to,
            "Verify your email address",
            format!("Use this link to verify your email address:\n\n{verification_url}"),
        )
        .await
    }

    async fn send_organization_invitation(
        &self,
        to: &str,
        organization_name: &str,
        invitation_url: &str,
    ) -> Result<(), OidcError> {
        self.send(
            to,
            &format!("Invitation to join {organization_name}"),
            format!("You have been invited to join {organization_name}.\n\nAccept the invitation:\n{invitation_url}"),
        )
        .await
    }
}
