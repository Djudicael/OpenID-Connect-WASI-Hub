use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::OidcError;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserFederationType {
    Ldap,
    ActiveDirectory,
    Kerberos,
}

impl std::fmt::Display for UserFederationType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Ldap => "ldap",
            Self::ActiveDirectory => "active_directory",
            Self::Kerberos => "kerberos",
        })
    }
}

impl std::str::FromStr for UserFederationType {
    type Err = OidcError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ldap" => Ok(Self::Ldap),
            "active_directory" => Ok(Self::ActiveDirectory),
            "kerberos" => Ok(Self::Kerberos),
            _ => Err(OidcError::InvalidInput(
                "unknown user federation type".into(),
            )),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct UserFederationProvider {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub name: String,
    pub provider_type: UserFederationType,
    pub enabled: bool,
    pub priority: i32,
    pub gateway_url: String,
    #[serde(skip_serializing)]
    pub gateway_secret: String,
    pub config: Value,
    pub import_users: bool,
    pub sync_groups: bool,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_status: Option<String>,
    pub last_sync_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Debug for UserFederationProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UserFederationProvider")
            .field("id", &self.id)
            .field("realm_id", &self.realm_id)
            .field("name", &self.name)
            .field("provider_type", &self.provider_type)
            .field("enabled", &self.enabled)
            .field("priority", &self.priority)
            .field("gateway_url", &self.gateway_url)
            .field("gateway_secret", &"[REDACTED]")
            .field("config", &self.config)
            .field("import_users", &self.import_users)
            .field("sync_groups", &self.sync_groups)
            .field("last_sync_at", &self.last_sync_at)
            .field("last_sync_status", &self.last_sync_status)
            .field("last_sync_error", &self.last_sync_error)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl UserFederationProvider {
    pub fn uses_direct_directory(&self) -> bool {
        url::Url::parse(&self.gateway_url)
            .map(|url| matches!(url.scheme(), "ldap" | "ldaps" | "ldap+starttls"))
            .unwrap_or(false)
    }

    pub fn validate(&self) -> Result<(), OidcError> {
        if self.name.trim().is_empty() {
            return Err(OidcError::InvalidInput("name must not be empty".into()));
        }
        let parsed = url::Url::parse(&self.gateway_url)
            .map_err(|_| OidcError::InvalidInput("gateway_url must be a valid URL".into()))?;
        let local = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        let allow_insecure_ldap = self
            .config
            .get("allow_insecure_transport")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let valid_transport = matches!(parsed.scheme(), "https" | "ldaps" | "ldap+starttls")
            || (parsed.scheme() == "http" && local)
            || (parsed.scheme() == "ldap" && (local || allow_insecure_ldap));
        if !valid_transport {
            return Err(OidcError::InvalidInput(
                "connection URL must use HTTPS or LDAPS; plain HTTP/LDAP is restricted to localhost unless allow_insecure_transport is enabled".into(),
            ));
        }
        if self.uses_direct_directory() && self.provider_type == UserFederationType::Kerberos {
            return Err(OidcError::InvalidInput(
                "Kerberos providers require a federation gateway URL".into(),
            ));
        }
        if !self.config.is_object() {
            return Err(OidcError::InvalidInput(
                "config must be a JSON object".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DirectoryUser {
    pub external_id: String,
    pub username: String,
    pub email: String,
    #[serde(default)]
    pub dn: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default = "empty_object")]
    pub attributes: Value,
}

fn default_enabled() -> bool {
    true
}
fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

impl DirectoryUser {
    pub fn validate(&self) -> Result<(), OidcError> {
        if self.external_id.trim().is_empty() || self.username.trim().is_empty() {
            return Err(OidcError::InvalidInput(
                "directory user needs an external ID and username".into(),
            ));
        }
        if !crate::utils::is_valid_email(&self.email) {
            return Err(OidcError::InvalidInput(
                "directory user returned an invalid email".into(),
            ));
        }
        if !self.attributes.is_object() {
            return Err(OidcError::InvalidInput(
                "directory user attributes must be a JSON object".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederatedDirectoryUser {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub user_id: Uuid,
    pub external_id: String,
    pub external_username: String,
    pub external_dn: Option<String>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_synced_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_requires_https_away_from_localhost() {
        let mut provider = UserFederationProvider {
            id: Uuid::new_v4(),
            realm_id: Uuid::new_v4(),
            name: "Corporate".into(),
            provider_type: UserFederationType::Ldap,
            enabled: true,
            priority: 0,
            gateway_url: "http://directory.example.com".into(),
            gateway_secret: "secret".into(),
            config: serde_json::json!({}),
            import_users: true,
            sync_groups: true,
            last_sync_at: None,
            last_sync_status: None,
            last_sync_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(provider.validate().is_err());
        provider.gateway_url = "http://127.0.0.1:8081".into();
        assert!(provider.validate().is_ok());
    }

    #[test]
    fn provider_debug_output_redacts_the_gateway_secret() {
        let provider = UserFederationProvider {
            id: Uuid::new_v4(),
            realm_id: Uuid::new_v4(),
            name: "Corporate".into(),
            provider_type: UserFederationType::Ldap,
            enabled: true,
            priority: 0,
            gateway_url: "https://directory.example.com".into(),
            gateway_secret: "never-log-this".into(),
            config: serde_json::json!({}),
            import_users: true,
            sync_groups: true,
            last_sync_at: None,
            last_sync_status: None,
            last_sync_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let output = format!("{provider:?}");
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("never-log-this"));
    }

    #[test]
    fn direct_ldap_requires_tls_or_explicit_insecure_transport() {
        let mut provider = UserFederationProvider {
            id: Uuid::new_v4(),
            realm_id: Uuid::new_v4(),
            name: "Directory".into(),
            provider_type: UserFederationType::Ldap,
            enabled: true,
            priority: 0,
            gateway_url: "ldap://directory.example.com:389".into(),
            gateway_secret: String::new(),
            config: serde_json::json!({"base_dn":"dc=example,dc=com"}),
            import_users: true,
            sync_groups: true,
            last_sync_at: None,
            last_sync_status: None,
            last_sync_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(provider.validate().is_err());
        provider.config["allow_insecure_transport"] = serde_json::json!(true);
        assert!(provider.validate().is_ok());
        provider.gateway_url = "ldaps://directory.example.com:636".into();
        assert!(provider.validate().is_ok());
        assert!(provider.uses_direct_directory());
    }
}
