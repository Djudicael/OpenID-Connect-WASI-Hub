use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    OidcError,
    models::{Client, ClientType},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientRegistrationContext {
    Admin,
    Dynamic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    #[default]
    Any,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientPolicyCondition {
    Always,
    RegistrationContext {
        contexts: Vec<ClientRegistrationContext>,
    },
    ClientType {
        client_type: ClientType,
    },
    ClientId {
        pattern: String,
    },
    GrantTypes {
        values: Vec<String>,
        #[serde(default)]
        match_mode: MatchMode,
    },
    Scopes {
        values: Vec<String>,
        #[serde(default)]
        match_mode: MatchMode,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientPolicyExecutor {
    RequirePkce,
    SecureRedirectUris {
        #[serde(default)]
        allow_loopback_http: bool,
    },
    AllowedGrantTypes {
        values: Vec<String>,
    },
    AllowedScopes {
        values: Vec<String>,
    },
    AllowedClientAuthMethods {
        values: Vec<String>,
    },
    RequireClientType {
        client_type: ClientType,
    },
    MaximumRedirectUris {
        maximum: u32,
    },
    RequirePairwiseSubject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientPolicyProfile {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub executors: Vec<ClientPolicyExecutor>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientPolicy {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub priority: i32,
    pub conditions: Vec<ClientPolicyCondition>,
    pub profile_ids: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientPolicyViolation {
    pub policy: String,
    pub profile: String,
    pub executor: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientPolicyEvaluation {
    pub allowed: bool,
    pub matched_policies: Vec<String>,
    pub matched_profiles: Vec<String>,
    pub violations: Vec<ClientPolicyViolation>,
}

impl ClientPolicyProfile {
    pub fn validate(&self) -> Result<(), OidcError> {
        if self.name.trim().is_empty() {
            return Err(OidcError::InvalidInput("profile name is required".into()));
        }
        if self.executors.is_empty() {
            return Err(OidcError::InvalidInput(
                "a profile needs at least one executor".into(),
            ));
        }
        for executor in &self.executors {
            match executor {
                ClientPolicyExecutor::AllowedGrantTypes { values }
                | ClientPolicyExecutor::AllowedScopes { values }
                | ClientPolicyExecutor::AllowedClientAuthMethods { values }
                    if values.is_empty() =>
                {
                    return Err(OidcError::InvalidInput(
                        "executor allow-list must not be empty".into(),
                    ));
                }
                ClientPolicyExecutor::MaximumRedirectUris { maximum: 0 } => {
                    return Err(OidcError::InvalidInput(
                        "maximum redirect URIs must be greater than zero".into(),
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl ClientPolicy {
    pub fn validate(&self) -> Result<(), OidcError> {
        if self.name.trim().is_empty() {
            return Err(OidcError::InvalidInput("policy name is required".into()));
        }
        if self.conditions.is_empty() {
            return Err(OidcError::InvalidInput(
                "a policy needs at least one condition".into(),
            ));
        }
        if self.profile_ids.is_empty() {
            return Err(OidcError::InvalidInput(
                "a policy needs at least one profile".into(),
            ));
        }
        for condition in &self.conditions {
            match condition {
                ClientPolicyCondition::RegistrationContext { contexts } if contexts.is_empty() => {
                    return Err(OidcError::InvalidInput(
                        "registration context condition must not be empty".into(),
                    ));
                }
                ClientPolicyCondition::ClientId { pattern } if pattern.trim().is_empty() => {
                    return Err(OidcError::InvalidInput(
                        "client ID pattern must not be empty".into(),
                    ));
                }
                ClientPolicyCondition::GrantTypes { values, .. }
                | ClientPolicyCondition::Scopes { values, .. }
                    if values.is_empty() =>
                {
                    return Err(OidcError::InvalidInput(
                        "condition values must not be empty".into(),
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

pub fn evaluate_client_policies(
    client: &Client,
    context: ClientRegistrationContext,
    policies: &[ClientPolicy],
    profiles: &[ClientPolicyProfile],
) -> ClientPolicyEvaluation {
    let mut ordered: Vec<_> = policies.iter().filter(|p| p.enabled).collect();
    ordered.sort_by_key(|p| (p.priority, p.name.as_str()));
    let mut result = ClientPolicyEvaluation {
        allowed: true,
        matched_policies: vec![],
        matched_profiles: vec![],
        violations: vec![],
    };
    for policy in ordered {
        if !policy
            .conditions
            .iter()
            .all(|c| condition_matches(c, client, context))
        {
            continue;
        }
        result.matched_policies.push(policy.name.clone());
        for profile_id in &policy.profile_ids {
            let Some(profile) = profiles
                .iter()
                .find(|p| p.id == *profile_id && p.realm_id == client.realm_id)
            else {
                result.violations.push(ClientPolicyViolation {
                    policy: policy.name.clone(),
                    profile: "missing profile".into(),
                    executor: "profile_reference".into(),
                    message: format!(
                        "Referenced profile {profile_id} does not exist in this realm"
                    ),
                });
                continue;
            };
            if !result.matched_profiles.contains(&profile.name) {
                result.matched_profiles.push(profile.name.clone());
            }
            for executor in &profile.executors {
                if let Some((kind, message)) = executor_violation(executor, client) {
                    result.violations.push(ClientPolicyViolation {
                        policy: policy.name.clone(),
                        profile: profile.name.clone(),
                        executor: kind.into(),
                        message,
                    });
                }
            }
        }
    }
    result.allowed = result.violations.is_empty();
    result
}

pub fn enforce_client_policies(
    client: &Client,
    context: ClientRegistrationContext,
    policies: &[ClientPolicy],
    profiles: &[ClientPolicyProfile],
) -> Result<ClientPolicyEvaluation, OidcError> {
    let result = evaluate_client_policies(client, context, policies, profiles);
    if let Some(v) = result.violations.first() {
        return Err(OidcError::InvalidInput(format!(
            "client policy '{}' / profile '{}': {}",
            v.policy, v.profile, v.message
        )));
    }
    Ok(result)
}

fn condition_matches(
    condition: &ClientPolicyCondition,
    client: &Client,
    context: ClientRegistrationContext,
) -> bool {
    match condition {
        ClientPolicyCondition::Always => true,
        ClientPolicyCondition::RegistrationContext { contexts } => contexts.contains(&context),
        ClientPolicyCondition::ClientType { client_type } => *client_type == client.client_type,
        ClientPolicyCondition::ClientId { pattern } => glob_matches(pattern, &client.client_id),
        ClientPolicyCondition::GrantTypes { values, match_mode } => {
            matches_values(values, &client.allowed_grant_types, *match_mode)
        }
        ClientPolicyCondition::Scopes { values, match_mode } => {
            matches_values(values, &client.allowed_scopes, *match_mode)
        }
    }
}

fn matches_values(expected: &[String], actual: &[String], mode: MatchMode) -> bool {
    match mode {
        MatchMode::Any => expected.iter().any(|v| actual.contains(v)),
        MatchMode::All => expected.iter().all(|v| actual.contains(v)),
    }
}

fn executor_violation(
    executor: &ClientPolicyExecutor,
    client: &Client,
) -> Option<(&'static str, String)> {
    match executor {
        ClientPolicyExecutor::RequirePkce if !client.pkce_required => {
            Some(("require_pkce", "PKCE must be required".into()))
        }
        ClientPolicyExecutor::SecureRedirectUris {
            allow_loopback_http,
        } => client.redirect_uris.iter().find_map(|uri| {
            let parsed = match url::Url::parse(uri) {
                Ok(value) => value,
                Err(_) => {
                    return Some((
                        "secure_redirect_uris",
                        format!("redirect URI '{uri}' is not a valid absolute URL"),
                    ));
                }
            };
            let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
            (parsed.scheme() != "https"
                && !(*allow_loopback_http && loopback && parsed.scheme() == "http"))
                .then(|| {
                    (
                        "secure_redirect_uris",
                        format!("redirect URI '{uri}' must use HTTPS"),
                    )
                })
        }),
        ClientPolicyExecutor::AllowedGrantTypes { values } => client
            .allowed_grant_types
            .iter()
            .find(|v| !values.contains(v))
            .map(|v| {
                (
                    "allowed_grant_types",
                    format!("grant type '{v}' is not allowed"),
                )
            }),
        ClientPolicyExecutor::AllowedScopes { values } => client
            .allowed_scopes
            .iter()
            .find(|v| !values.contains(v))
            .map(|v| ("allowed_scopes", format!("scope '{v}' is not allowed"))),
        ClientPolicyExecutor::AllowedClientAuthMethods { values }
            if !values.contains(&client.token_endpoint_auth_method) =>
        {
            Some((
                "allowed_client_auth_methods",
                format!(
                    "client authentication method '{}' is not allowed",
                    client.token_endpoint_auth_method
                ),
            ))
        }
        ClientPolicyExecutor::RequireClientType { client_type }
            if *client_type != client.client_type =>
        {
            Some((
                "require_client_type",
                format!(
                    "client type must be {}",
                    match client_type {
                        ClientType::Public => "public",
                        ClientType::Confidential => "confidential",
                    }
                ),
            ))
        }
        ClientPolicyExecutor::MaximumRedirectUris { maximum }
            if client.redirect_uris.len() > *maximum as usize =>
        {
            Some((
                "maximum_redirect_uris",
                format!("at most {maximum} redirect URIs are allowed"),
            ))
        }
        ClientPolicyExecutor::RequirePairwiseSubject if client.subject_type != "pairwise" => {
            Some((
                "require_pairwise_subject",
                "pairwise subject identifiers are required".into(),
            ))
        }
        _ => None,
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let (p, v) = (pattern.as_bytes(), value.as_bytes());
    let (mut pi, mut vi, mut star, mut checkpoint) = (0, 0, None, 0);
    while vi < v.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            checkpoint = vi;
        } else if let Some(s) = star {
            pi = s + 1;
            checkpoint += 1;
            vi = checkpoint;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn client() -> Client {
        Client {
            id: Uuid::nil(),
            realm_id: Uuid::nil(),
            client_id: "spa-app".into(),
            client_type: ClientType::Public,
            client_secret_hash: None,
            name: "SPA".into(),
            redirect_uris: vec!["http://example.test/cb".into()],
            allowed_scopes: vec!["openid".into()],
            allowed_grant_types: vec!["authorization_code".into()],
            pkce_required: false,
            enabled: true,
            deleted_at: None,
            token_endpoint_auth_method: "none".into(),
            jwks_uri: None,
            jwks: None,
            request_uris: vec![],
            client_secret_encrypted: None,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            post_logout_redirect_uris: vec![],
            subject_type: "public".into(),
            sector_identifier_uri: None,
            response_modes: vec!["query".into()],
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            id_token_encryption_key_encrypted: None,
            id_token_encryption_key_pem: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            request_object_encryption_key_encrypted: None,
            request_object_encryption_key_pem: None,
        }
    }
    #[test]
    fn applies_conditions_and_reports_every_violation() {
        let c = client();
        let now = Utc::now();
        let profile = ClientPolicyProfile {
            id: Uuid::now_v7(),
            realm_id: c.realm_id,
            name: "Browser security".into(),
            description: None,
            executors: vec![
                ClientPolicyExecutor::RequirePkce,
                ClientPolicyExecutor::SecureRedirectUris {
                    allow_loopback_http: false,
                },
            ],
            created_at: now,
            updated_at: now,
        };
        let policy = ClientPolicy {
            id: Uuid::now_v7(),
            realm_id: c.realm_id,
            name: "Public apps".into(),
            description: None,
            enabled: true,
            priority: 10,
            conditions: vec![
                ClientPolicyCondition::ClientType {
                    client_type: ClientType::Public,
                },
                ClientPolicyCondition::ClientId {
                    pattern: "spa-*".into(),
                },
            ],
            profile_ids: vec![profile.id],
            created_at: now,
            updated_at: now,
        };
        let out =
            evaluate_client_policies(&c, ClientRegistrationContext::Admin, &[policy], &[profile]);
        assert!(!out.allowed);
        assert_eq!(out.violations.len(), 2);
    }
    #[test]
    fn supports_loopback_http_exception() {
        let mut c = client();
        c.redirect_uris = vec!["http://127.0.0.1:3000/cb".into()];
        assert!(
            executor_violation(
                &ClientPolicyExecutor::SecureRedirectUris {
                    allow_loopback_http: true
                },
                &c
            )
            .is_none()
        );
    }
    #[test]
    fn rejects_malformed_redirect_uri() {
        let mut c = client();
        c.redirect_uris = vec!["not a URL".into()];
        let violation = executor_violation(
            &ClientPolicyExecutor::SecureRedirectUris {
                allow_loopback_http: true,
            },
            &c,
        );
        assert!(matches!(violation, Some(("secure_redirect_uris", _))));
    }
    #[test]
    fn glob_matching_is_anchored() {
        assert!(glob_matches("mobile-*-prod", "mobile-ios-prod"));
        assert!(!glob_matches("mobile-*", "x-mobile-ios"));
    }
}
