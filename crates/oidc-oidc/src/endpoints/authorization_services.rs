use axum::Json;
use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use oidc_core::OidcError;
use oidc_core::models::{AuthorizationContext, PermissionTicket, ProtectedResource, RptGrant};
use oidc_core::traits::token_service::{AccessTokenExtraClaims, TokenService};
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7, sha2_256_hex};
use oidc_repository::repositories::authorization_service_repo::AuthorizationServiceRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::role_repo::RoleRepo;
use oidc_repository::repositories::user_group_repo::UserGroupRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::state::OidcState;

pub const UMA_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:uma-ticket";

#[derive(Debug, Deserialize)]
pub struct ResourceRegistrationRequest {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(rename = "type", default)]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub owner: Option<Uuid>,
    #[serde(default)]
    pub uris: Vec<String>,
    #[serde(default, alias = "resource_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "empty_object")]
    pub attributes: Value,
    #[serde(default)]
    pub icon_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PermissionTicketRequest {
    pub resource_id: Uuid,
    #[serde(default)]
    pub resource_scopes: Vec<String>,
    #[serde(default)]
    pub requester: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct DecisionRequest {
    pub resource_id: Uuid,
    #[serde(default)]
    pub scopes: Vec<String>,
}

fn empty_object() -> Value {
    json!({})
}

fn bearer(headers: &HeaderMap) -> Result<&str, OidcError> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| OidcError::AuthenticationFailed("Bearer token required".into()))
}

fn aud_contains(aud: &Value, expected: &str) -> bool {
    match aud {
        Value::String(value) => value == expected,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

async fn realm_and_server(
    state: &OidcState,
    realm_name: &str,
    server_client_id: &str,
) -> Result<(oidc_core::models::Realm, oidc_core::models::Client), OidcError> {
    let mut conn = state.connect().await?;
    let realm = RealmRepo
        .find_by_name(&mut conn, realm_name)
        .await?
        .ok_or_else(|| OidcError::NotFound("realm".into()))?;
    let server = ClientRepo
        .find_by_client_id_in_realm(&mut conn, server_client_id, realm.id)
        .await?
        .filter(|client| client.enabled)
        .ok_or_else(|| OidcError::NotFound("resource server".into()))?;
    Ok((realm, server))
}

async fn require_resource_server_token(
    state: &OidcState,
    headers: &HeaderMap,
    server: &oidc_core::models::Client,
) -> Result<(), OidcError> {
    let claims = state
        .verify_access_token_with_claims_any_issuer(bearer(headers)?)
        .await?;
    if claims.sub != server.client_id && !aud_contains(&claims.aud, &server.client_id) {
        return Err(OidcError::AuthorizationDenied(
            "token is not valid for this resource server".into(),
        ));
    }
    Ok(())
}

pub async fn register_resource(
    state: OidcState,
    realm_name: String,
    server_client_id: String,
    headers: HeaderMap,
    req: ResourceRegistrationRequest,
) -> Result<Json<Value>, OidcError> {
    let (realm, server) = realm_and_server(&state, &realm_name, &server_client_id).await?;
    require_resource_server_token(&state, &headers, &server).await?;
    if req.name.trim().is_empty() {
        return Err(OidcError::InvalidInput("resource name is required".into()));
    }
    if !req.attributes.is_object() {
        return Err(OidcError::InvalidInput(
            "resource attributes must be a JSON object".into(),
        ));
    }
    let now = Utc::now();
    let resource = ProtectedResource {
        id: generate_uuid_v7(),
        realm_id: realm.id,
        resource_server_id: server.id,
        owner_id: req.owner,
        name: req.name.trim().into(),
        display_name: req.display_name,
        resource_type: req.resource_type,
        uris: req.uris,
        scopes: req.scopes,
        attributes: req.attributes,
        icon_uri: req.icon_uri,
        created_at: now,
        updated_at: now,
    };
    let mut conn = state.connect().await?;
    if AuthorizationServiceRepo
        .list_resources(&mut conn, server.id)
        .await?
        .iter()
        .any(|item| item.name.eq_ignore_ascii_case(&resource.name))
    {
        return Err(OidcError::InvalidInput(
            "a resource with this name already exists".into(),
        ));
    }
    if let Some(owner_id) = resource.owner_id {
        UserRepo
            .find_by_id(&mut conn, owner_id)
            .await?
            .filter(|user| user.realm_id == realm.id)
            .ok_or_else(|| OidcError::InvalidInput("resource owner is not in this realm".into()))?;
    }
    AuthorizationServiceRepo
        .create_resource(&mut conn, &resource)
        .await?;
    Ok(Json(resource_json(&resource)))
}

pub async fn list_registered_resources(
    state: OidcState,
    realm_name: String,
    server_client_id: String,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let (_, server) = realm_and_server(&state, &realm_name, &server_client_id).await?;
    require_resource_server_token(&state, &headers, &server).await?;
    let mut conn = state.connect().await?;
    let items = AuthorizationServiceRepo
        .list_resources(&mut conn, server.id)
        .await?;
    Ok(Json(json!(
        items.iter().map(resource_json).collect::<Vec<_>>()
    )))
}

pub async fn get_registered_resource(
    state: OidcState,
    realm_name: String,
    server_client_id: String,
    resource_id: Uuid,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let (_, server) = realm_and_server(&state, &realm_name, &server_client_id).await?;
    require_resource_server_token(&state, &headers, &server).await?;
    let mut conn = state.connect().await?;
    let resource = AuthorizationServiceRepo
        .find_resource(&mut conn, resource_id)
        .await?
        .filter(|resource| resource.resource_server_id == server.id)
        .ok_or_else(|| OidcError::NotFound("resource".into()))?;
    Ok(Json(resource_json(&resource)))
}

pub async fn update_registered_resource(
    state: OidcState,
    realm_name: String,
    server_client_id: String,
    resource_id: Uuid,
    headers: HeaderMap,
    req: ResourceRegistrationRequest,
) -> Result<Json<Value>, OidcError> {
    let (_, server) = realm_and_server(&state, &realm_name, &server_client_id).await?;
    require_resource_server_token(&state, &headers, &server).await?;
    if req.name.trim().is_empty() || !req.attributes.is_object() {
        return Err(OidcError::InvalidInput(
            "resource name and JSON object attributes are required".into(),
        ));
    }
    let mut conn = state.connect().await?;
    let mut resource = AuthorizationServiceRepo
        .find_resource(&mut conn, resource_id)
        .await?
        .filter(|resource| resource.resource_server_id == server.id)
        .ok_or_else(|| OidcError::NotFound("resource".into()))?;
    if AuthorizationServiceRepo
        .list_resources(&mut conn, server.id)
        .await?
        .iter()
        .any(|item| item.id != resource.id && item.name.eq_ignore_ascii_case(req.name.trim()))
    {
        return Err(OidcError::InvalidInput(
            "a resource with this name already exists".into(),
        ));
    }
    if let Some(owner_id) = req.owner {
        UserRepo
            .find_by_id(&mut conn, owner_id)
            .await?
            .filter(|user| user.realm_id == resource.realm_id)
            .ok_or_else(|| OidcError::InvalidInput("resource owner is not in this realm".into()))?;
    }
    resource.name = req.name.trim().into();
    resource.display_name = req.display_name;
    resource.resource_type = req.resource_type;
    resource.owner_id = req.owner;
    resource.uris = req.uris;
    resource.scopes = req.scopes;
    resource.attributes = req.attributes;
    resource.icon_uri = req.icon_uri;
    AuthorizationServiceRepo
        .update_resource(&mut conn, &resource)
        .await?;
    Ok(Json(resource_json(&resource)))
}

pub async fn delete_registered_resource(
    state: OidcState,
    realm_name: String,
    server_client_id: String,
    resource_id: Uuid,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let (_, server) = realm_and_server(&state, &realm_name, &server_client_id).await?;
    require_resource_server_token(&state, &headers, &server).await?;
    let mut conn = state.connect().await?;
    let resource = AuthorizationServiceRepo
        .find_resource(&mut conn, resource_id)
        .await?
        .filter(|resource| resource.resource_server_id == server.id)
        .ok_or_else(|| OidcError::NotFound("resource".into()))?;
    AuthorizationServiceRepo
        .delete_resource(&mut conn, resource.id)
        .await?;
    Ok(Json(json!({"deleted": true})))
}

pub async fn create_permission_ticket(
    state: OidcState,
    realm_name: String,
    server_client_id: String,
    headers: HeaderMap,
    req: PermissionTicketRequest,
) -> Result<Json<Value>, OidcError> {
    let (realm, server) = realm_and_server(&state, &realm_name, &server_client_id).await?;
    require_resource_server_token(&state, &headers, &server).await?;
    let mut conn = state.connect().await?;
    let resource = AuthorizationServiceRepo
        .find_resource(&mut conn, req.resource_id)
        .await?
        .filter(|resource| resource.resource_server_id == server.id)
        .ok_or_else(|| OidcError::NotFound("resource".into()))?;
    if !req
        .resource_scopes
        .iter()
        .all(|scope| resource.scopes.contains(scope))
    {
        return Err(OidcError::InvalidScope(
            "resource scope is not registered".into(),
        ));
    }
    let token = generate_opaque_token()?;
    let now = Utc::now();
    let ticket = PermissionTicket {
        id: generate_uuid_v7(),
        realm_id: realm.id,
        resource_server_id: server.id,
        requester_id: req.requester,
        resource_id: resource.id,
        scopes: req.resource_scopes,
        granted: false,
        used: false,
        expires_at: now + Duration::minutes(5),
        created_at: now,
    };
    AuthorizationServiceRepo
        .create_ticket(&mut conn, &ticket, &sha2_256_hex(&token))
        .await?;
    Ok(Json(json!({"ticket": token, "expires_in": 300})))
}

pub async fn uma_ticket_grant(
    state: &OidcState,
    client: &oidc_core::models::Client,
    params: &HashMap<String, String>,
    dpop_jkt: Option<&str>,
) -> Result<Value, OidcError> {
    let claim_token = params
        .get("claim_token")
        .ok_or_else(|| OidcError::InvalidInput("claim_token is required".into()))?;
    if params
        .get("claim_token_format")
        .is_some_and(|format| format != "urn:ietf:params:oauth:token-type:jwt")
    {
        return Err(OidcError::InvalidInput(
            "unsupported claim_token_format".into(),
        ));
    }
    let claims = state
        .verify_access_token_with_claims_any_issuer(claim_token)
        .await
        .map_err(|_| OidcError::InvalidSubjectToken("claim token is invalid".into()))?;
    let subject_id = Uuid::parse_str(&claims.sub).map_err(|_| {
        OidcError::InvalidSubjectToken("an end-user claim token is required".into())
    })?;
    let mut conn = state.connect().await?;
    let user = UserRepo
        .find_by_id(&mut conn, subject_id)
        .await?
        .filter(|user| user.enabled && user.realm_id == client.realm_id)
        .ok_or_else(|| OidcError::InvalidSubjectToken("user is not active in this realm".into()))?;

    let previous_grant = if let Some(rpt) = params.get("rpt") {
        let previous_claims = state
            .verify_access_token_with_claims_any_issuer(rpt)
            .await
            .map_err(|_| OidcError::InvalidSubjectToken("RPT is invalid".into()))?;
        let id = previous_claims
            .custom_claims
            .get("rpt_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or_else(|| OidcError::InvalidSubjectToken("RPT identifier is missing".into()))?;
        Some(
            AuthorizationServiceRepo
                .find_active_rpt(&mut conn, id)
                .await?
                .filter(|grant| grant.subject_id == subject_id && grant.client_id == client.id)
                .ok_or_else(|| OidcError::AuthorizationDenied("RPT cannot be upgraded".into()))?,
        )
    } else {
        None
    };

    let mut requested = Vec::new();
    let mut ticket_id = None;
    let resource_server_id;
    if let Some(ticket_token) = params.get("ticket") {
        let ticket = AuthorizationServiceRepo
            .find_active_ticket(&mut conn, &sha2_256_hex(ticket_token))
            .await?
            .ok_or_else(|| {
                OidcError::InvalidInput("permission ticket is invalid or expired".into())
            })?;
        if ticket.realm_id != client.realm_id
            || ticket.requester_id.is_some_and(|id| id != subject_id)
        {
            return Err(OidcError::AuthorizationDenied(
                "permission ticket requester does not match".into(),
            ));
        }
        resource_server_id = ticket.resource_server_id;
        requested.push((ticket.resource_id, ticket.scopes.clone()));
        ticket_id = Some(ticket.id);
    } else {
        resource_server_id = if let Some(audience) = params.get("audience") {
            ClientRepo
                .find_by_client_id_in_realm(&mut conn, audience, client.realm_id)
                .await?
                .ok_or_else(|| OidcError::NotFound("resource server".into()))?
                .id
        } else if let Some(previous) = previous_grant.as_ref() {
            previous.resource_server_id
        } else {
            return Err(OidcError::InvalidInput(
                "audience is required without a ticket".into(),
            ));
        };
        requested = parse_permission_parameter(params.get("permission").map(String::as_str))?;
        if requested.is_empty() {
            return Err(OidcError::InvalidInput("permission is required".into()));
        }
    }
    if previous_grant
        .as_ref()
        .is_some_and(|grant| grant.resource_server_id != resource_server_id)
    {
        return Err(OidcError::AuthorizationDenied(
            "RPT belongs to a different resource server".into(),
        ));
    }

    let mut granted = evaluate_requests(
        &mut conn,
        resource_server_id,
        &user,
        &client.client_id,
        &claims.custom_claims,
        &requested,
    )
    .await?;
    if granted.len() != requested.len() {
        if let Some(id) = ticket_id {
            let _ = AuthorizationServiceRepo
                .consume_ticket(&mut conn, id, false)
                .await;
        }
        return Err(OidcError::AuthorizationDenied(
            "the requested permission was denied".into(),
        ));
    }
    if let Some(id) = ticket_id {
        if !AuthorizationServiceRepo
            .consume_ticket(&mut conn, id, true)
            .await?
        {
            return Err(OidcError::InvalidInput(
                "permission ticket was already used".into(),
            ));
        }
    }

    if let Some(previous) = previous_grant.as_ref() {
        merge_permissions(&mut granted, &previous.permissions);
    }

    let result = issue_rpt(
        state,
        &mut conn,
        client,
        resource_server_id,
        subject_id,
        granted,
        dpop_jkt,
        previous_grant.is_some(),
    )
    .await?;
    if let Some(previous) = previous_grant {
        AuthorizationServiceRepo
            .revoke_rpt(&mut conn, previous.id)
            .await?;
    }
    Ok(result)
}

pub async fn entitlement(
    state: OidcState,
    realm_name: String,
    server_client_id: String,
    headers: HeaderMap,
) -> Result<Json<Value>, OidcError> {
    let (_, server) = realm_and_server(&state, &realm_name, &server_client_id).await?;
    let claims = state
        .verify_access_token_with_claims_any_issuer(bearer(&headers)?)
        .await?;
    let subject_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| OidcError::AuthorizationDenied("end-user token required".into()))?;
    let mut conn = state.connect().await?;
    let user = UserRepo
        .find_by_id(&mut conn, subject_id)
        .await?
        .filter(|user| user.enabled && user.realm_id == server.realm_id)
        .ok_or_else(|| OidcError::AuthorizationDenied("user is not active".into()))?;
    let requesting_client_id = claims
        .aud
        .as_str()
        .or_else(|| claims.aud.as_array()?.iter().find_map(Value::as_str))
        .ok_or_else(|| OidcError::AuthorizationDenied("requesting client is missing".into()))?;
    let requesting_client = ClientRepo
        .find_by_client_id_in_realm(&mut conn, requesting_client_id, server.realm_id)
        .await?
        .filter(|client| client.enabled)
        .ok_or_else(|| OidcError::AuthorizationDenied("requesting client is inactive".into()))?;
    let resources = AuthorizationServiceRepo
        .list_resources(&mut conn, server.id)
        .await?;
    let requested = resources
        .into_iter()
        .flat_map(|resource| {
            if resource.scopes.is_empty() {
                vec![(resource.id, Vec::new())]
            } else {
                resource
                    .scopes
                    .into_iter()
                    .map(|scope| (resource.id, vec![scope]))
                    .collect()
            }
        })
        .collect::<Vec<_>>();
    let granted = evaluate_requests(
        &mut conn,
        server.id,
        &user,
        &requesting_client.client_id,
        &claims.custom_claims,
        &requested,
    )
    .await?;
    let mut combined = Vec::new();
    merge_permissions(&mut combined, &Value::Array(granted));
    let result = issue_rpt(
        &state,
        &mut conn,
        &requesting_client,
        server.id,
        subject_id,
        combined,
        None,
        false,
    )
    .await?;
    Ok(Json(result))
}

pub async fn evaluate_rpt(
    state: OidcState,
    realm_name: String,
    server_client_id: String,
    headers: HeaderMap,
    req: DecisionRequest,
) -> Result<Json<Value>, OidcError> {
    let (_, server) = realm_and_server(&state, &realm_name, &server_client_id).await?;
    let claims = state
        .verify_access_token_with_claims_any_issuer(bearer(&headers)?)
        .await?;
    if !aud_contains(&claims.aud, &server.client_id) {
        return Err(OidcError::AuthorizationDenied(
            "RPT audience does not match".into(),
        ));
    }
    let rpt_id = claims
        .custom_claims
        .get("rpt_id")
        .and_then(Value::as_str)
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or_else(|| OidcError::AuthorizationDenied("RPT required".into()))?;
    let mut conn = state.connect().await?;
    let grant = AuthorizationServiceRepo
        .find_active_rpt(&mut conn, rpt_id)
        .await?
        .filter(|grant| grant.resource_server_id == server.id)
        .ok_or_else(|| OidcError::AuthorizationDenied("RPT is inactive".into()))?;
    let allowed = grant.permissions.as_array().is_some_and(|permissions| {
        permissions.iter().any(|permission| {
            permission.get("rsid").and_then(Value::as_str) == Some(&req.resource_id.to_string())
                && req.scopes.iter().all(|scope| {
                    permission
                        .get("scopes")
                        .and_then(Value::as_array)
                        .is_some_and(|values| {
                            values.iter().any(|value| value.as_str() == Some(scope))
                        })
                })
        })
    });
    Ok(Json(json!({"result": allowed})))
}

async fn evaluate_requests(
    conn: &mut oidc_repository::Connection,
    resource_server_id: Uuid,
    user: &oidc_core::models::User,
    requesting_client: &str,
    token_claims: &serde_json::Map<String, Value>,
    requested: &[(Uuid, Vec<String>)],
) -> Result<Vec<Value>, OidcError> {
    let permissions = AuthorizationServiceRepo
        .list_permissions(conn, resource_server_id)
        .await?;
    let policies = AuthorizationServiceRepo
        .list_policies(conn, resource_server_id)
        .await?;
    let roles: Vec<String> = RoleRepo
        .find_effective_names_by_user_id(conn, user.id)
        .await?
        .into_iter()
        .flat_map(|(name, client)| {
            [
                name.clone(),
                client
                    .map(|client| format!("{client}:{name}"))
                    .unwrap_or_default(),
            ]
        })
        .filter(|value| !value.is_empty())
        .collect();
    let groups: Vec<String> = UserGroupRepo
        .find_groups_by_user(conn, user.id)
        .await?
        .into_iter()
        .map(|group| group.name)
        .collect();
    let context_claims = Value::Object(token_claims.clone());
    let mut granted = Vec::new();
    for (resource_id, scopes) in requested {
        let Some(resource) = AuthorizationServiceRepo
            .find_resource(conn, *resource_id)
            .await?
            .filter(|resource| resource.resource_server_id == resource_server_id)
        else {
            continue;
        };
        if !scopes.iter().all(|scope| resource.scopes.contains(scope)) {
            continue;
        }
        let context = AuthorizationContext {
            subject_id: Some(user.id),
            client_id: requesting_client.into(),
            owner_id: resource.owner_id,
            roles: roles.clone(),
            groups: groups.clone(),
            user_attributes: user.attributes.clone(),
            resource_attributes: resource.attributes.clone(),
            token_claims: context_claims.clone(),
            now: Utc::now(),
        };
        let allowed = permissions
            .iter()
            .filter(|permission| permission.applies_to(*resource_id, scopes))
            .any(|permission| {
                let results = permission
                    .policies
                    .iter()
                    .map(|id| {
                        policies
                            .iter()
                            .find(|policy| policy.id == *id)
                            .is_some_and(|policy| policy.evaluate(&context))
                    })
                    .collect::<Vec<_>>();
                permission.decide(&results)
            });
        if allowed {
            granted.push(json!({"rsid": resource.id, "rsname": resource.name, "scopes": scopes}));
        }
    }
    Ok(granted)
}

async fn issue_rpt(
    state: &OidcState,
    conn: &mut oidc_repository::Connection,
    client: &oidc_core::models::Client,
    resource_server_id: Uuid,
    subject_id: Uuid,
    permissions: Vec<Value>,
    dpop_jkt: Option<&str>,
    upgraded: bool,
) -> Result<Value, OidcError> {
    if permissions.is_empty() {
        return Err(OidcError::AuthorizationDenied(
            "no permissions were granted".into(),
        ));
    }
    let server = ClientRepo
        .find_by_id(conn, resource_server_id)
        .await?
        .ok_or_else(|| OidcError::NotFound("resource server".into()))?;
    let id = generate_uuid_v7();
    let now = Utc::now();
    let permissions_value = Value::Array(permissions);
    let scopes = permissions_value
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|permission| {
            permission
                .get("scopes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut custom_claims = serde_json::Map::new();
    custom_claims.insert(
        "authorization".into(),
        json!({"permissions": permissions_value}),
    );
    custom_claims.insert("rpt_id".into(), json!(id));
    let resources = vec![server.client_id.clone()];
    let token_service = state.token_service_for_realm(client.realm_id).await?;
    let token = token_service
        .issue_access_token_with_extra(
            &subject_id.to_string(),
            &client.client_id,
            &scopes,
            dpop_jkt,
            None,
            Some(&resources),
            Some(AccessTokenExtraClaims {
                custom_claims,
                ..Default::default()
            }),
        )
        .await?;
    AuthorizationServiceRepo
        .create_rpt(
            conn,
            &RptGrant {
                id,
                realm_id: client.realm_id,
                resource_server_id,
                subject_id,
                client_id: client.id,
                permissions: permissions_value.clone(),
                revoked: false,
                expires_at: now + Duration::minutes(15),
                created_at: now,
            },
        )
        .await?;
    Ok(
        json!({"access_token":token,"token_type":if dpop_jkt.is_some(){"DPoP"}else{"Bearer"},"expires_in":900,"scope":scopes.join(" "),"permissions":permissions_value,"upgraded":upgraded}),
    )
}

fn merge_permissions(current: &mut Vec<Value>, previous: &Value) {
    let Some(previous_permissions) = previous.as_array() else {
        return;
    };
    for previous_permission in previous_permissions {
        let Some(resource_id) = previous_permission.get("rsid").and_then(Value::as_str) else {
            continue;
        };
        if let Some(existing) = current
            .iter_mut()
            .find(|permission| permission.get("rsid").and_then(Value::as_str) == Some(resource_id))
        {
            let previous_scopes = previous_permission
                .get("scopes")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let scopes = existing.get_mut("scopes").and_then(Value::as_array_mut);
            if let Some(scopes) = scopes {
                for scope in previous_scopes {
                    if !scopes.contains(&scope) {
                        scopes.push(scope);
                    }
                }
            }
        } else {
            current.push(previous_permission.clone());
        }
    }
}

fn parse_permission_parameter(value: Option<&str>) -> Result<Vec<(Uuid, Vec<String>)>, OidcError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| {
            let (resource, scopes) = part.split_once('#').unwrap_or((part, ""));
            let id = Uuid::parse_str(resource.trim()).map_err(|_| {
                OidcError::InvalidInput("permission resource must be a UUID".into())
            })?;
            let scopes = scopes
                .split_whitespace()
                .filter(|scope| !scope.is_empty())
                .map(str::to_string)
                .collect();
            Ok((id, scopes))
        })
        .collect()
}

fn resource_json(resource: &ProtectedResource) -> Value {
    json!({"_id":resource.id,"name":resource.name,"display_name":resource.display_name,"type":resource.resource_type,"owner":resource.owner_id,"uris":resource.uris,"resource_scopes":resource.scopes,"attributes":resource.attributes,"icon_uri":resource.icon_uri})
}
