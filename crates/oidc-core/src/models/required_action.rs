use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredActionKind {
    UpdatePassword,
    VerifyEmail,
    UpdateProfile,
    ConfigureMfa,
    AcceptTerms,
}

impl RequiredActionKind {
    pub const ALL: [Self; 5] = [
        Self::UpdatePassword,
        Self::VerifyEmail,
        Self::UpdateProfile,
        Self::ConfigureMfa,
        Self::AcceptTerms,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UpdatePassword => "update_password",
            Self::VerifyEmail => "verify_email",
            Self::UpdateProfile => "update_profile",
            Self::ConfigureMfa => "configure_mfa",
            Self::AcceptTerms => "accept_terms",
        }
    }
}

impl std::str::FromStr for RequiredActionKind {
    type Err = ();
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == value)
            .ok_or(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFlowConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_order")]
    pub action_order: Vec<RequiredActionKind>,
    #[serde(default)]
    pub require_verified_email: bool,
    #[serde(default)]
    pub require_complete_profile: bool,
    #[serde(default)]
    pub require_mfa: bool,
    #[serde(default)]
    pub terms: TermsPolicy,
    #[serde(default)]
    pub step_up: StepUpPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TermsPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub text: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StepUpPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub client_ids: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub max_auth_age_seconds: Option<i64>,
}

fn default_order() -> Vec<RequiredActionKind> {
    RequiredActionKind::ALL.to_vec()
}

impl Default for AuthenticationFlowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            action_order: default_order(),
            require_verified_email: false,
            require_complete_profile: false,
            require_mfa: false,
            terms: TermsPolicy::default(),
            step_up: StepUpPolicy::default(),
        }
    }
}

impl AuthenticationFlowConfig {
    pub fn from_realm_config(config: &serde_json::Value) -> Self {
        config
            .get("authentication_flow")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default()
    }
    pub fn normalize(&mut self) {
        let mut order = Vec::new();
        for action in self
            .action_order
            .iter()
            .chain(RequiredActionKind::ALL.iter())
        {
            if !order.contains(action) {
                order.push(*action);
            }
        }
        self.action_order = order;
        self.terms.version = self.terms.version.trim().to_string();
        self.terms.text = self.terms.text.trim().to_string();
        self.step_up.client_ids = self
            .step_up
            .client_ids
            .iter()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect();
        self.step_up.scopes = self
            .step_up
            .scopes
            .iter()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect();
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.terms.enabled && self.terms.version.trim().is_empty() {
            return Err("A terms version is required when terms acceptance is enabled".into());
        }
        if self.terms.enabled && self.terms.text.trim().is_empty() {
            return Err("Terms text is required when terms acceptance is enabled".into());
        }
        if self
            .step_up
            .max_auth_age_seconds
            .is_some_and(|value| value < 0)
        {
            return Err("Maximum authentication age cannot be negative".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RequiredActionSession {
    pub id: Uuid,
    pub token_hash: String,
    pub user_id: Uuid,
    pub realm_id: Uuid,
    pub client_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_and_normalizes_flow_configuration() {
        let config = serde_json::json!({"authentication_flow":{"enabled":true,"action_order":["accept_terms","verify_email"],"require_verified_email":true}});
        let mut flow = AuthenticationFlowConfig::from_realm_config(&config);
        flow.normalize();
        assert!(flow.enabled);
        assert_eq!(flow.action_order[0], RequiredActionKind::AcceptTerms);
        assert_eq!(flow.action_order.len(), 5);
    }
}
