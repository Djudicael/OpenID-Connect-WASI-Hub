use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::OidcError;

/// An OAuth2/OIDC client registered within a realm.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Client {
    /// Unique identifier.
    pub id: Uuid,
    /// The realm this client belongs to.
    pub realm_id: Uuid,
    /// OAuth2 client_id (unique globally).
    pub client_id: String,
    /// Client type: confidential or public.
    pub client_type: ClientType,
    /// Argon2id hash of the client_secret (None for public clients).
    pub client_secret_hash: Option<String>,
    /// Human-readable name.
    pub name: String,
    /// Registered redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Allowed OAuth2 scopes.
    pub allowed_scopes: Vec<String>,
    /// Allowed grant types.
    pub allowed_grant_types: Vec<String>,
    /// Whether PKCE is required.
    pub pkce_required: bool,
    /// Whether the client is enabled.
    pub enabled: bool,
    /// When the client was soft-deleted.
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: String,
    /// URL for the client's JSON Web Key Set.
    pub jwks_uri: Option<String>,
    /// Client's JSON Web Key Set (inline).
    pub jwks: Option<serde_json::Value>,
    /// Registered request URIs (e.g. for request objects).
    pub request_uris: Vec<String>,
    /// Encrypted client secret for `client_secret_jwt` authentication.
    pub client_secret_encrypted: Option<String>,
    /// Front-channel logout URI (Front-Channel Logout §6).
    /// The OP sends an iframe to this URI when the user logs out.
    pub frontchannel_logout_uri: Option<String>,
    /// Whether to include the `sid` claim in front-channel logout notifications.
    pub frontchannel_logout_session_required: bool,
    /// Back-channel logout URI (Back-Channel Logout §7).
    /// The OP sends a signed logout token to this URI via HTTP POST.
    pub backchannel_logout_uri: Option<String>,
    /// Whether to include the `sid` claim in back-channel logout tokens.
    pub backchannel_logout_session_required: bool,
    /// Registered post-logout redirect URIs (Session §5).
    pub post_logout_redirect_uris: Vec<String>,
}

/// The type of OAuth2 client.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    /// Can keep secrets (server-side app).
    Confidential,
    /// Cannot keep secrets (SPA, mobile).
    Public,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_client() -> Client {
        Client {
            id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            client_id: "my-app".into(),
            client_type: ClientType::Confidential,
            client_secret_hash: Some("$argon2id$...".into()),
            name: "My App".into(),
            redirect_uris: vec!["https://example.com/callback".into()],
            allowed_scopes: vec!["openid".into()],
            allowed_grant_types: vec!["authorization_code".into()],
            pkce_required: true,
            enabled: true,
            deleted_at: None,
            token_endpoint_auth_method: "client_secret_basic".into(),
            jwks_uri: None,
            jwks: None,
            request_uris: vec![],
            client_secret_encrypted: None,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            post_logout_redirect_uris: vec![],
        }
    }

    #[test]
    fn test_client_validate_valid() {
        let client = valid_client();
        assert!(client.validate().is_ok());
    }

    #[test]
    fn test_client_validate_empty_client_id() {
        let mut client = valid_client();
        client.client_id = "".into();
        let err = client.validate().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("client_id")));
    }

    #[test]
    fn test_client_validate_empty_name() {
        // The current validate() only checks client_id and redirect_urIs,
        // so an empty name should still pass validation.
        let mut client = valid_client();
        client.name = "".into();
        // Name is not validated by validate(), so this should succeed
        assert!(client.validate().is_ok());
    }
}

impl Client {
    /// Validate the client fields.
    pub fn validate(&self) -> Result<(), OidcError> {
        if self.client_id.trim().is_empty() {
            return Err(OidcError::InvalidInput(
                "client_id must not be empty".into(),
            ));
        }
        for uri in &self.redirect_uris {
            if uri.parse::<url::Url>().is_err() {
                return Err(OidcError::InvalidInput(format!(
                    "Invalid redirect URI: {}",
                    uri
                )));
            }
        }
        Ok(())
    }
}
