use std::collections::HashSet;

use oidc_core::OidcError;
use oidc_repository::Connection;
use oidc_repository::repositories::organization_repo::OrganizationRepo;
use serde_json::{Map, Value, json};
use uuid::Uuid;

const ORGANIZATION_SCOPE: &str = "organization";
const ORGANIZATION_SCOPE_PREFIX: &str = "organization:";

pub fn is_scope_allowed(requested: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|scope| scope == requested)
        || (requested.starts_with(ORGANIZATION_SCOPE_PREFIX)
            && allowed.iter().any(|scope| scope == ORGANIZATION_SCOPE))
}

fn disclosed_attributes(attributes: &Value, names: &[String]) -> Map<String, Value> {
    attributes
        .as_object()
        .map(|values| {
            names
                .iter()
                .filter_map(|name| values.get(name).cloned().map(|value| (name.clone(), value)))
                .collect()
        })
        .unwrap_or_default()
}

pub async fn resolve_organization_claim(
    conn: &mut Connection,
    user_id: Uuid,
    scopes: &[String],
) -> Result<Option<Value>, OidcError> {
    let has_any = scopes.iter().any(|scope| scope == ORGANIZATION_SCOPE);
    let requested: Vec<&str> = scopes
        .iter()
        .filter_map(|scope| scope.strip_prefix(ORGANIZATION_SCOPE_PREFIX))
        .collect();

    if !has_any && requested.is_empty() {
        return Ok(None);
    }
    if requested.iter().any(|alias| alias.is_empty()) {
        return Err(OidcError::InvalidScope(
            "organization scope must include a non-empty alias".into(),
        ));
    }

    let organizations = OrganizationRepo
        .find_enabled_by_user_id(conn, user_id)
        .await?;
    let all_requested = requested.contains(&"*");
    let has_specific = requested.iter().any(|alias| *alias != "*");
    if (has_any && !requested.is_empty()) || (all_requested && has_specific) {
        return Err(OidcError::InvalidScope(
            "organization, organization:*, and organization:<alias> scope formats cannot be mixed"
                .into(),
        ));
    }
    let aliases: HashSet<&str> = requested.into_iter().collect();
    let mut claim = Map::new();

    if has_any && organizations.len() > 1 {
        return Err(OidcError::AccountSelectionRequired(
            "the user belongs to multiple organizations; request organization:<alias> or organization:*"
                .into(),
        ));
    }

    for organization in organizations {
        if has_any || all_requested || aliases.contains(organization.alias.as_str()) {
            let (groups, roles) = OrganizationRepo
                .find_user_group_names_and_roles(conn, organization.id, user_id)
                .await?;
            let attributes = disclosed_attributes(
                &organization.attributes,
                &organization.claim_attribute_names,
            );
            claim.insert(
                organization.alias.clone(),
                json!({
                    "id": organization.id,
                    "name": organization.name,
                    "attributes": attributes,
                    "groups": groups,
                    "roles": roles,
                }),
            );
        }
    }

    if !all_requested {
        let missing: Vec<&str> = aliases
            .into_iter()
            .filter(|alias| !claim.contains_key(*alias))
            .collect();
        if !missing.is_empty() {
            return Err(OidcError::InvalidScope(format!(
                "user is not a member of requested organization(s): {}",
                missing.join(", ")
            )));
        }
    }

    Ok(Some(Value::Object(claim)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_parameterized_scope_when_base_scope_is_allowed() {
        assert!(is_scope_allowed(
            "organization:acme",
            &["openid".into(), "organization".into()]
        ));
    }

    #[test]
    fn rejects_parameterized_scope_without_organization_permission() {
        assert!(!is_scope_allowed(
            "organization:acme",
            &["openid".into(), "profile".into()]
        ));
    }

    #[test]
    fn organization_claims_only_include_explicitly_disclosed_attributes() {
        let attributes = json!({"plan": "enterprise", "internal": "private"});
        let visible = disclosed_attributes(&attributes, &["plan".into()]);
        assert_eq!(
            visible,
            json!({"plan": "enterprise"}).as_object().unwrap().clone()
        );
    }
}
