use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::OidcError;

/// A business tenant inside a realm.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Organization {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub name: String,
    pub alias: String,
    pub enabled: bool,
    pub attributes: Value,
    /// Top-level attribute names that may be exposed in OIDC claims.
    pub claim_attribute_names: Vec<String>,
    pub redirect_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Organization {
    pub fn validate(&self) -> Result<(), OidcError> {
        let name = self.name.trim();
        if !(2..=255).contains(&name.len()) {
            return Err(OidcError::InvalidInput(
                "organization name must be between 2 and 255 characters".into(),
            ));
        }
        let alias = self.alias.trim();
        if !(2..=100).contains(&alias.len())
            || !alias
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            || alias.starts_with('-')
            || alias.ends_with('-')
        {
            return Err(OidcError::InvalidInput(
                "organization alias must contain lowercase letters, digits, or internal hyphens"
                    .into(),
            ));
        }
        if !self.attributes.is_object() {
            return Err(OidcError::InvalidInput(
                "organization attributes must be a JSON object".into(),
            ));
        }
        if self
            .claim_attribute_names
            .iter()
            .any(|name| name.is_empty() || name.len() > 100 || !self.attributes.get(name).is_some())
        {
            return Err(OidcError::InvalidInput(
                "claim attribute names must reference organization attributes".into(),
            ));
        }
        if let Some(redirect_url) = self.redirect_url.as_deref() {
            let parsed = url::Url::parse(redirect_url).map_err(|_| {
                OidcError::InvalidInput(
                    "organization redirect URL must be an absolute HTTP(S) URL".into(),
                )
            })?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(OidcError::InvalidInput(
                    "organization redirect URL must use HTTP or HTTPS".into(),
                ));
            }
        }
        Ok(())
    }
}

/// How an email domain is matched to an organization.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationDomainKind {
    Exact,
    Wildcard,
}

/// An email domain used for organization discovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationDomain {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub domain: String,
    pub kind: OrganizationDomainKind,
    pub verified: bool,
    #[serde(skip_serializing)]
    pub verification_token_hash: Option<String>,
}

impl OrganizationDomain {
    pub fn validate(&self) -> Result<(), OidcError> {
        let domain = self.domain.trim();
        if domain.is_empty()
            || domain.len() > 253
            || domain.contains('@')
            || domain.contains('/')
            || domain.chars().any(char::is_whitespace)
            || !domain.contains('.')
        {
            return Err(OidcError::InvalidInput(
                "organization domain must be a valid DNS name".into(),
            ));
        }
        Ok(())
    }
}

/// Controls whether the user or the organization owns the account lifecycle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationMembershipKind {
    Managed,
    Unmanaged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationMembership {
    pub organization_id: Uuid,
    pub user_id: Uuid,
    pub kind: OrganizationMembershipKind,
    pub joined_at: DateTime<Utc>,
}

/// Member summary returned by organization management APIs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationMember {
    pub user_id: Uuid,
    pub email: String,
    pub username: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub enabled: bool,
    pub kind: OrganizationMembershipKind,
    pub joined_at: DateTime<Utc>,
}

/// Association between an organization and a realm identity provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationIdentityProviderLink {
    pub organization_id: Uuid,
    pub identity_provider_id: Uuid,
    pub alias: String,
    pub display_name: String,
    pub provider_type: String,
    pub enabled: bool,
    pub redirect_on_email_domain: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationGroupLink {
    pub organization_id: Uuid,
    pub group_id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationInvitationStatus {
    Pending,
    Accepted,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationInvitation {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub status: OrganizationInvitationStatus,
    pub invited_by: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn organization() -> Organization {
        Organization {
            id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            name: "Acme Corporation".into(),
            alias: "acme-corp".into(),
            enabled: true,
            attributes: serde_json::json!({"plan": ["enterprise"]}),
            claim_attribute_names: vec!["plan".into()],
            redirect_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn validates_organization() {
        assert!(organization().validate().is_ok());
    }

    #[test]
    fn rejects_unsafe_alias() {
        let mut value = organization();
        value.alias = "Acme Corp".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_non_object_attributes() {
        let mut value = organization();
        value.attributes = serde_json::json!([]);
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_claim_attribute_name_that_is_not_defined() {
        let mut value = organization();
        value.claim_attribute_names = vec!["secret".into()];
        assert!(value.validate().is_err());
    }

    #[test]
    fn validates_domain() {
        let domain = OrganizationDomain {
            id: Uuid::now_v7(),
            organization_id: Uuid::now_v7(),
            domain: "example.com".into(),
            kind: OrganizationDomainKind::Exact,
            verified: false,
            verification_token_hash: None,
        };
        assert!(domain.validate().is_ok());
    }
}
