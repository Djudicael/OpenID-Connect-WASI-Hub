use std::collections::BTreeSet;

use oidc_core::models::{ProtocolMapperType, User};
use oidc_repository::{
    Connection,
    repositories::{protocol_mapper_repo::ProtocolMapperRepo, role_repo::RoleRepo},
};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use oidc_core::OidcError;

#[derive(Debug, Default)]
pub struct MappedClaims {
    pub access_token: Map<String, Value>,
    pub id_token: Map<String, Value>,
    pub userinfo: Map<String, Value>,
    pub access_audiences: Vec<String>,
    pub id_audiences: Vec<String>,
}

pub async fn resolve_mapped_claims(
    conn: &mut Connection,
    client_id: Uuid,
    user: Option<&User>,
    granted_scopes: &[String],
) -> Result<MappedClaims, OidcError> {
    let mappers = ProtocolMapperRepo
        .list_active_for_client(conn, client_id, granted_scopes)
        .await?;
    let effective_roles = if user.is_some()
        && mappers.iter().any(|mapper| {
            matches!(
                mapper.mapper_type,
                ProtocolMapperType::RealmRoles | ProtocolMapperType::ClientRoles
            )
        }) {
        RoleRepo
            .find_effective_names_by_user_id(conn, user.unwrap().id)
            .await?
    } else {
        Vec::new()
    };
    let mut result = MappedClaims::default();
    let mut access_audiences = BTreeSet::new();
    let mut id_audiences = BTreeSet::new();

    for mapper in mappers {
        if mapper.mapper_type == ProtocolMapperType::Audience {
            if let Some(audience) = mapper
                .claim_value
                .as_ref()
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            {
                if mapper.add_to_access_token {
                    access_audiences.insert(audience.to_string());
                }
                if mapper.add_to_id_token {
                    id_audiences.insert(audience.to_string());
                }
            }
            continue;
        }
        let Some(claim_name) = mapper.claim_name.as_deref() else {
            continue;
        };
        let value = match mapper.mapper_type {
            ProtocolMapperType::UserProperty => user
                .and_then(|user| user_property(user, mapper.source.as_deref().unwrap_or_default())),
            ProtocolMapperType::UserAttribute => user.and_then(|user| {
                value_at_path(
                    &user.attributes,
                    mapper.source.as_deref().unwrap_or_default(),
                )
                .cloned()
            }),
            ProtocolMapperType::HardcodedClaim => mapper.claim_value.clone(),
            ProtocolMapperType::RealmRoles => Some(json!(
                effective_roles
                    .iter()
                    .filter_map(|(name, client)| client.is_none().then_some(name))
                    .collect::<Vec<_>>()
            )),
            ProtocolMapperType::ClientRoles => {
                let requested_client = mapper.source.as_deref().unwrap_or_default();
                Some(json!(
                    effective_roles
                        .iter()
                        .filter_map(
                            |(name, client)| (client.as_deref() == Some(requested_client))
                                .then_some(name)
                        )
                        .collect::<Vec<_>>()
                ))
            }
            ProtocolMapperType::Audience => None,
        };
        let Some(mut value) = value else { continue };
        if mapper.multivalued && !value.is_array() {
            value = Value::Array(vec![value]);
        }
        if mapper.add_to_access_token {
            insert_claim(&mut result.access_token, claim_name, value.clone());
        }
        if mapper.add_to_id_token {
            insert_claim(&mut result.id_token, claim_name, value.clone());
        }
        if mapper.add_to_userinfo {
            insert_claim(&mut result.userinfo, claim_name, value);
        }
    }
    result.access_audiences = access_audiences.into_iter().collect();
    result.id_audiences = id_audiences.into_iter().collect();
    Ok(result)
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .filter(|part| !part.is_empty())
        .try_fold(value, |current, part| current.get(part))
}

fn user_property(user: &User, source: &str) -> Option<Value> {
    match source {
        "id" => Some(json!(user.id)),
        "email" => Some(json!(user.email)),
        "email_verified" => Some(json!(user.email_verified)),
        "username" => user.username.as_ref().map(|v| json!(v)),
        "given_name" => user.given_name.as_ref().map(|v| json!(v)),
        "family_name" => user.family_name.as_ref().map(|v| json!(v)),
        "middle_name" => user.middle_name.as_ref().map(|v| json!(v)),
        "nickname" => user.nickname.as_ref().map(|v| json!(v)),
        "preferred_username" => user.preferred_username.as_ref().map(|v| json!(v)),
        "profile" => user.profile.as_ref().map(|v| json!(v)),
        "picture" => user.picture.as_ref().map(|v| json!(v)),
        "website" => user.website.as_ref().map(|v| json!(v)),
        "gender" => user.gender.as_ref().map(|v| json!(v)),
        "birthdate" => user.birthdate.as_ref().map(|v| json!(v)),
        "zoneinfo" => user.zoneinfo.as_ref().map(|v| json!(v)),
        "locale" => Some(json!(user.locale)),
        "phone_number" => user.phone_number.as_ref().map(|v| json!(v)),
        "phone_number_verified" => user.phone_number_verified.map(|v| json!(v)),
        "updated_at" => Some(json!(user.updated_at.timestamp())),
        _ => None,
    }
}

fn insert_claim(target: &mut Map<String, Value>, path: &str, value: Value) {
    let parts: Vec<&str> = path.split('.').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return;
    }
    let mut current = target;
    for part in &parts[..parts.len() - 1] {
        let entry = current
            .entry((*part).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        current = entry.as_object_mut().expect("object inserted above");
    }
    current.insert(parts[parts.len() - 1].to_string(), value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_claims_are_created() {
        let mut claims = Map::new();
        insert_claim(&mut claims, "employee.department", json!("sales"));
        assert_eq!(claims["employee"]["department"], "sales");
    }
}
