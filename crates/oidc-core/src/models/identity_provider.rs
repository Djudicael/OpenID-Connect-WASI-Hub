use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::OidcError;

/// An upstream OIDC identity provider for social login / federation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityProvider {
    /// Unique identifier.
    pub id: Uuid,
    /// The realm this provider belongs to.
    pub realm_id: Uuid,
    /// Human-readable alias (e.g., "google", "github").
    pub alias: String,
    /// Display name (e.g., "Sign in with Google").
    pub display_name: String,
    /// The provider type.
    pub provider_type: IdentityProviderType,
    /// Whether the provider is enabled.
    pub enabled: bool,
    /// Upstream OIDC issuer URL (from .well-known/openid-configuration).
    pub issuer: String,
    /// Authorization endpoint URL.
    pub authorization_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// UserInfo endpoint URL.
    pub userinfo_url: String,
    /// JWKS URI for token verification.
    pub jwks_url: String,
    /// Client ID registered with the upstream IdP.
    pub client_id: String,
    /// Client secret (stored encrypted or hashed — for now, plain for simplicity).
    pub client_secret: String,
    /// Scopes to request from the upstream IdP.
    pub scopes: Vec<String>,
    /// Whether to create local users automatically on first login.
    pub auto_create_users: bool,
    /// Whether to link existing users by email.
    pub link_users_by_email: bool,
    /// When the provider was soft-deleted.
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The type of upstream identity provider.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityProviderType {
    /// Generic OIDC provider.
    Oidc,
    /// Google (specialized OIDC).
    Google,
    /// GitHub (OAuth2 + user info).
    GitHub,
}

impl std::fmt::Display for IdentityProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityProviderType::Oidc => write!(f, "oidc"),
            IdentityProviderType::Google => write!(f, "google"),
            IdentityProviderType::GitHub => write!(f, "github"),
        }
    }
}

impl std::str::FromStr for IdentityProviderType {
    type Err = OidcError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "oidc" => Ok(IdentityProviderType::Oidc),
            "google" => Ok(IdentityProviderType::Google),
            "github" => Ok(IdentityProviderType::GitHub),
            _ => Err(OidcError::InvalidInput(format!(
                "Unknown identity provider type: {}",
                s
            ))),
        }
    }
}

impl IdentityProvider {
    /// Validate the identity provider fields.
    pub fn validate(&self) -> Result<(), OidcError> {
        if self.alias.trim().is_empty() {
            return Err(OidcError::InvalidInput("alias must not be empty".into()));
        }
        if self.issuer.trim().is_empty() {
            return Err(OidcError::InvalidInput("issuer must not be empty".into()));
        }
        if self.client_id.trim().is_empty() {
            return Err(OidcError::InvalidInput(
                "client_id must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_provider() -> IdentityProvider {
        IdentityProvider {
            id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            alias: "google".into(),
            display_name: "Sign in with Google".into(),
            provider_type: IdentityProviderType::Google,
            enabled: true,
            issuer: "https://accounts.google.com".into(),
            authorization_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_url: "https://oauth2.googleapis.com/token".into(),
            userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo".into(),
            jwks_url: "https://www.googleapis.com/oauth2/v3/certs".into(),
            client_id: "my-client-id".into(),
            client_secret: "my-client-secret".into(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            auto_create_users: true,
            link_users_by_email: true,
            deleted_at: None,
        }
    }

    #[test]
    fn test_validate_valid() {
        let provider = valid_provider();
        assert!(provider.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_alias() {
        let mut provider = valid_provider();
        provider.alias = "".into();
        let err = provider.validate().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("alias")));
    }

    #[test]
    fn test_validate_empty_issuer() {
        let mut provider = valid_provider();
        provider.issuer = "".into();
        let err = provider.validate().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("issuer")));
    }

    #[test]
    fn test_validate_empty_client_id() {
        let mut provider = valid_provider();
        provider.client_id = "".into();
        let err = provider.validate().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("client_id")));
    }

    #[test]
    fn test_provider_type_display() {
        assert_eq!(IdentityProviderType::Oidc.to_string(), "oidc");
        assert_eq!(IdentityProviderType::Google.to_string(), "google");
        assert_eq!(IdentityProviderType::GitHub.to_string(), "github");
    }

    #[test]
    fn test_provider_type_from_str() {
        assert_eq!(
            "oidc".parse::<IdentityProviderType>().unwrap(),
            IdentityProviderType::Oidc
        );
        assert_eq!(
            "google".parse::<IdentityProviderType>().unwrap(),
            IdentityProviderType::Google
        );
        assert_eq!(
            "github".parse::<IdentityProviderType>().unwrap(),
            IdentityProviderType::GitHub
        );
    }

    #[test]
    fn test_provider_type_from_str_unknown() {
        let err = "unknown".parse::<IdentityProviderType>().unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(_)));
    }

    #[test]
    fn test_provider_type_serde_roundtrip() {
        let json = serde_json::to_string(&IdentityProviderType::Google).unwrap();
        assert_eq!(json, "\"google\"");
        let parsed: IdentityProviderType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, IdentityProviderType::Google);
    }
}
