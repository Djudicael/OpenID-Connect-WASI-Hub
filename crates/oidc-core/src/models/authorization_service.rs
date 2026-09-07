use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtectedResource {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub resource_server_id: Uuid,
    pub owner_id: Option<Uuid>,
    pub name: String,
    pub display_name: Option<String>,
    pub resource_type: Option<String>,
    pub uris: Vec<String>,
    pub scopes: Vec<String>,
    pub attributes: Value,
    pub icon_uri: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationPolicy {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub resource_server_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// `user`, `role`, `group`, `client`, `owner`, `attribute`, or `time`.
    pub policy_type: String,
    pub logic: String,
    pub config: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationPermission {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub resource_server_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// Empty resources means every resource owned by the resource server.
    pub resources: Vec<Uuid>,
    /// Empty scopes means every scope on the selected resources.
    pub scopes: Vec<String>,
    pub policies: Vec<Uuid>,
    pub decision_strategy: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PermissionTicket {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub resource_server_id: Uuid,
    pub requester_id: Option<Uuid>,
    pub resource_id: Uuid,
    pub scopes: Vec<String>,
    pub granted: bool,
    pub used: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RptGrant {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub resource_server_id: Uuid,
    pub subject_id: Uuid,
    pub client_id: Uuid,
    pub permissions: Value,
    pub revoked: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct AuthorizationContext {
    pub subject_id: Option<Uuid>,
    pub client_id: String,
    pub owner_id: Option<Uuid>,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub user_attributes: Value,
    pub resource_attributes: Value,
    pub token_claims: Value,
    pub now: DateTime<Utc>,
}

impl AuthorizationPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("policy name is required".into());
        }
        if !matches!(
            self.policy_type.as_str(),
            "user" | "role" | "group" | "client" | "owner" | "attribute" | "time"
        ) {
            return Err("unsupported policy type".into());
        }
        if !matches!(self.logic.as_str(), "positive" | "negative") {
            return Err("policy logic must be positive or negative".into());
        }
        Ok(())
    }

    pub fn evaluate(&self, context: &AuthorizationContext) -> bool {
        let matched = match self.policy_type.as_str() {
            "user" => contains_uuid(&self.config, "users", context.subject_id),
            "role" => matches_values(&self.config, "roles", &context.roles),
            "group" => matches_values(&self.config, "groups", &context.groups),
            "client" => value_list(&self.config, "clients")
                .iter()
                .any(|value| value == &context.client_id),
            "owner" => context.subject_id.is_some() && context.subject_id == context.owner_id,
            "attribute" => evaluate_attribute(&self.config, context),
            "time" => evaluate_time(&self.config, context.now),
            _ => false,
        };
        if self.logic == "negative" {
            !matched
        } else {
            matched
        }
    }
}

impl AuthorizationPermission {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("permission name is required".into());
        }
        if self.policies.is_empty() {
            return Err("at least one policy is required".into());
        }
        if !matches!(
            self.decision_strategy.as_str(),
            "affirmative" | "unanimous" | "consensus"
        ) {
            return Err("invalid decision strategy".into());
        }
        Ok(())
    }

    pub fn applies_to(&self, resource_id: Uuid, requested_scopes: &[String]) -> bool {
        (self.resources.is_empty() || self.resources.contains(&resource_id))
            && (self.scopes.is_empty()
                || requested_scopes
                    .iter()
                    .all(|scope| self.scopes.contains(scope)))
    }

    pub fn decide(&self, results: &[bool]) -> bool {
        if results.is_empty() {
            return false;
        }
        match self.decision_strategy.as_str() {
            "unanimous" => results.iter().all(|value| *value),
            "consensus" => results.iter().filter(|value| **value).count() * 2 > results.len(),
            _ => results.iter().any(|value| *value),
        }
    }
}

fn value_list(config: &Value, key: &str) -> Vec<String> {
    config
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn contains_uuid(config: &Value, key: &str, actual: Option<Uuid>) -> bool {
    actual.is_some_and(|actual| {
        value_list(config, key)
            .iter()
            .any(|expected| expected == &actual.to_string())
    })
}

fn matches_values(config: &Value, key: &str, actual: &[String]) -> bool {
    let expected = value_list(config, key);
    let require_all = config.get("match").and_then(Value::as_str) == Some("all");
    if require_all {
        !expected.is_empty() && expected.iter().all(|value| actual.contains(value))
    } else {
        expected.iter().any(|value| actual.contains(value))
    }
}

fn evaluate_attribute(config: &Value, context: &AuthorizationContext) -> bool {
    let key = config
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if key.is_empty() {
        return false;
    }
    let source = match config.get("source").and_then(Value::as_str) {
        Some("token") => &context.token_claims,
        Some("resource") => &context.resource_attributes,
        _ => &context.user_attributes,
    };
    let actual = key
        .split('.')
        .try_fold(source, |value, part| value.get(part));
    let operator = config
        .get("operator")
        .and_then(Value::as_str)
        .unwrap_or("equals");
    let expected = config.get("value").unwrap_or(&Value::Null);
    match operator {
        "present" => actual.is_some_and(|value| !value.is_null()),
        "not_equals" => actual != Some(expected),
        "contains" => actual.is_some_and(|value| match value {
            Value::Array(values) => values.contains(expected),
            Value::String(value) => expected.as_str().is_some_and(|item| value.contains(item)),
            _ => false,
        }),
        _ => actual == Some(expected),
    }
}

fn evaluate_time(config: &Value, now: DateTime<Utc>) -> bool {
    let after_start = config
        .get("not_before")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .is_none_or(|value| now >= value.with_timezone(&Utc));
    let before_end = config
        .get("not_on_or_after")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .is_none_or(|value| now < value.with_timezone(&Utc));
    let weekday_allowed = config
        .get("weekdays")
        .and_then(Value::as_array)
        .is_none_or(|days| {
            let day = now.weekday().num_days_from_monday() as u64 + 1;
            days.iter().any(|value| value.as_u64() == Some(day))
        });
    after_start && before_end && weekday_allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn context() -> AuthorizationContext {
        AuthorizationContext {
            subject_id: Some(Uuid::nil()),
            client_id: "portal".into(),
            owner_id: Some(Uuid::nil()),
            roles: vec!["editor".into()],
            groups: vec!["finance".into()],
            user_attributes: json!({"department":"finance"}),
            resource_attributes: json!({"classification":"internal"}),
            token_claims: json!({"risk":"low"}),
            now: Utc::now(),
        }
    }

    #[test]
    fn evaluates_rbac_abac_owner_and_negative_logic() {
        let mut policy = AuthorizationPolicy {
            id: Uuid::nil(),
            realm_id: Uuid::nil(),
            resource_server_id: Uuid::nil(),
            name: "editors".into(),
            description: None,
            policy_type: "role".into(),
            logic: "positive".into(),
            config: json!({"roles":["editor"]}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(policy.evaluate(&context()));
        policy.policy_type = "attribute".into();
        policy.config = json!({"key":"department","value":"finance"});
        assert!(policy.evaluate(&context()));
        policy.policy_type = "owner".into();
        assert!(policy.evaluate(&context()));
        policy.logic = "negative".into();
        assert!(!policy.evaluate(&context()));
    }

    #[test]
    fn applies_scope_and_decision_strategies() {
        let resource = Uuid::new_v4();
        let mut permission = AuthorizationPermission {
            id: Uuid::nil(),
            realm_id: Uuid::nil(),
            resource_server_id: Uuid::nil(),
            name: "read".into(),
            description: None,
            resources: vec![resource],
            scopes: vec!["view".into()],
            policies: vec![Uuid::nil()],
            decision_strategy: "affirmative".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(permission.applies_to(resource, &["view".into()]));
        assert!(permission.decide(&[false, true]));
        permission.decision_strategy = "unanimous".into();
        assert!(!permission.decide(&[false, true]));
        permission.decision_strategy = "consensus".into();
        assert!(permission.decide(&[true, true, false]));
    }

    #[test]
    fn evaluates_token_resource_and_time_conditions() {
        let mut policy = AuthorizationPolicy {
            id: Uuid::nil(),
            realm_id: Uuid::nil(),
            resource_server_id: Uuid::nil(),
            name: "context".into(),
            description: None,
            policy_type: "attribute".into(),
            logic: "positive".into(),
            config: json!({"source":"token","key":"risk","operator":"equals","value":"low"}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(policy.evaluate(&context()));

        policy.config = json!({"source":"resource","key":"classification","operator":"contains","value":"intern"});
        assert!(policy.evaluate(&context()));

        policy.policy_type = "time".into();
        let now = context().now;
        policy.config = json!({
            "not_before": (now - chrono::Duration::minutes(1)).to_rfc3339(),
            "not_on_or_after": (now + chrono::Duration::minutes(1)).to_rfc3339(),
            "weekdays": [now.weekday().num_days_from_monday() + 1]
        });
        assert!(policy.evaluate(&context()));
    }
}
