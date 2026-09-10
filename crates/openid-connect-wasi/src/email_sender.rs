use oidc_core::OidcError;
use oidc_core::traits::{EmailMessage, EmailSender};
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

    async fn send(&self, to: &str, message: &EmailMessage) -> Result<(), OidcError> {
        let body = json!({
            "from": self.from,
            "to": [to],
            "subject": message.subject,
            "text": message.text,
            "html": message.html,
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
    async fn send_email(&self, to: &str, message: &EmailMessage) -> Result<(), OidcError> {
        self.send(to, message).await
    }
}
