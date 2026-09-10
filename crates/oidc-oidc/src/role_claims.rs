use std::collections::BTreeMap;

use oidc_core::OidcError;
use oidc_repository::{Connection, repositories::role_repo::RoleRepo};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct TokenRoleClaims {
    pub roles: Option<Vec<String>>,
    pub realm_access: Option<Value>,
    pub resource_access: Option<Value>,
}

pub async fn resolve_role_claims(
    conn: &mut Connection,
    user_id: Uuid,
) -> Result<TokenRoleClaims, OidcError> {
    let effective = RoleRepo
        .find_effective_names_by_user_id(conn, user_id)
        .await?;
    let mut realm_roles = Vec::new();
    let mut client_roles: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (role, client_id) in effective {
        if let Some(client_id) = client_id {
            client_roles.entry(client_id).or_default().push(role);
        } else {
            realm_roles.push(role);
        }
    }
    let realm_access = (!realm_roles.is_empty()).then(|| json!({"roles": realm_roles}));
    let resource_access = (!client_roles.is_empty()).then(|| {
        Value::Object(
            client_roles
                .into_iter()
                .map(|(client_id, roles)| (client_id, json!({"roles": roles})))
                .collect(),
        )
    });
    Ok(TokenRoleClaims {
        roles: realm_access
            .as_ref()
            .and_then(|value| value.get("roles"))
            .and_then(Value::as_array)
            .map(|roles| {
                roles
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            }),
        realm_access,
        resource_access,
    })
}
