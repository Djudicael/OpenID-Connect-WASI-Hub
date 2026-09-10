use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use oidc_core::models::{AuthorizationPermission, AuthorizationPolicy, ProtectedResource};
use oidc_core::utils::generate_uuid_v7;
use oidc_repository::repositories::authorization_service_repo::AuthorizationServiceRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{admin_or_forbidden, conflict, connect, internal_error, not_found, realm_or_forbidden};
use crate::middleware::admin_auth::AdminAuth;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ServerQuery {
    pub resource_server_id: Uuid,
}
#[derive(Deserialize)]
pub struct ResourceRequest {
    pub resource_server_id: Uuid,
    pub owner_id: Option<Uuid>,
    pub name: String,
    pub display_name: Option<String>,
    pub resource_type: Option<String>,
    #[serde(default)]
    pub uris: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "object")]
    pub attributes: Value,
    pub icon_uri: Option<String>,
}
#[derive(Deserialize)]
pub struct PolicyRequest {
    pub resource_server_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub policy_type: String,
    #[serde(default = "positive")]
    pub logic: String,
    #[serde(default = "object")]
    pub config: Value,
}
#[derive(Deserialize)]
pub struct PermissionRequest {
    pub resource_server_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub resources: Vec<Uuid>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub policies: Vec<Uuid>,
    #[serde(default = "affirmative")]
    pub decision_strategy: String,
}
fn object() -> Value {
    json!({})
}
fn positive() -> String {
    "positive".into()
}
fn affirmative() -> String {
    "affirmative".into()
}
fn invalid(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":message.into()})),
    )
        .into_response()
}

async fn require_server(
    state: &AppState,
    auth: &AdminAuth,
    id: Uuid,
) -> Result<oidc_core::models::Client, Response> {
    let mut conn = connect(state).await?;
    let client = ClientRepo
        .find_by_id(&mut conn, id)
        .await
        .map_err(|_| internal_error())?
        .ok_or_else(not_found)?;
    if let Some(response) = realm_or_forbidden(auth, client.realm_id) {
        return Err(response);
    }
    Ok(client)
}

async fn permission_references_match_server(
    conn: &mut oidc_repository::Connection,
    server_id: Uuid,
    resources: &[Uuid],
    policies: &[Uuid],
) -> Result<bool, oidc_core::OidcError> {
    for id in resources {
        if !AuthorizationServiceRepo
            .find_resource(conn, *id)
            .await?
            .is_some_and(|item| item.resource_server_id == server_id)
        {
            return Ok(false);
        }
    }
    for id in policies {
        if !AuthorizationServiceRepo
            .find_policy(conn, *id)
            .await?
            .is_some_and(|item| item.resource_server_id == server_id)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn owner_is_in_realm(
    conn: &mut oidc_repository::Connection,
    owner_id: Option<Uuid>,
    realm_id: Uuid,
) -> Result<bool, oidc_core::OidcError> {
    let Some(owner_id) = owner_id else {
        return Ok(true);
    };
    Ok(UserRepo
        .find_by_id(conn, owner_id)
        .await?
        .is_some_and(|user| user.realm_id == realm_id))
}

pub async fn list_resources(
    State(state): State<AppState>,
    auth: AdminAuth,
    Query(q): Query<ServerQuery>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Err(r) = require_server(&state, &auth, q.resource_server_id).await {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match AuthorizationServiceRepo
        .list_resources(&mut c, q.resource_server_id)
        .await
    {
        Ok(v) => Json(json!({"items":v})).into_response(),
        Err(_) => internal_error(),
    }
}
pub async fn create_resource(
    State(state): State<AppState>,
    auth: AdminAuth,
    Json(req): Json<ResourceRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let server = match require_server(&state, &auth, req.resource_server_id).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if req.name.trim().is_empty() {
        return invalid("resource name is required");
    }
    if !req.attributes.is_object() {
        return invalid("resource attributes must be a JSON object");
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if AuthorizationServiceRepo
        .list_resources(&mut c, server.id)
        .await
        .is_ok_and(|v| {
            v.iter()
                .any(|i| i.name.eq_ignore_ascii_case(req.name.trim()))
        })
    {
        return conflict();
    }
    match owner_is_in_realm(&mut c, req.owner_id, server.realm_id).await {
        Ok(true) => {}
        Ok(false) => return invalid("resource owner must belong to this realm"),
        Err(_) => return internal_error(),
    }
    let now = Utc::now();
    let item = ProtectedResource {
        id: generate_uuid_v7(),
        realm_id: server.realm_id,
        resource_server_id: server.id,
        owner_id: req.owner_id,
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
    match AuthorizationServiceRepo
        .create_resource(&mut c, &item)
        .await
    {
        Ok(_) => (StatusCode::CREATED, Json(item)).into_response(),
        Err(_) => internal_error(),
    }
}
pub async fn update_resource(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<ResourceRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut item = match AuthorizationServiceRepo.find_resource(&mut c, id).await {
        Ok(Some(v)) => v,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(r) = realm_or_forbidden(&auth, item.realm_id) {
        return r;
    }
    if req.resource_server_id != item.resource_server_id {
        return invalid("resource server cannot be changed");
    }
    if req.name.trim().is_empty() || !req.attributes.is_object() {
        return invalid("resource name and JSON object attributes are required");
    }
    if AuthorizationServiceRepo
        .list_resources(&mut c, item.resource_server_id)
        .await
        .is_ok_and(|items| {
            items.iter().any(|other| {
                other.id != item.id && other.name.eq_ignore_ascii_case(req.name.trim())
            })
        })
    {
        return conflict();
    }
    match owner_is_in_realm(&mut c, req.owner_id, item.realm_id).await {
        Ok(true) => {}
        Ok(false) => return invalid("resource owner must belong to this realm"),
        Err(_) => return internal_error(),
    }
    item.owner_id = req.owner_id;
    item.name = req.name.trim().into();
    item.display_name = req.display_name;
    item.resource_type = req.resource_type;
    item.uris = req.uris;
    item.scopes = req.scopes;
    item.attributes = req.attributes;
    item.icon_uri = req.icon_uri;
    match AuthorizationServiceRepo
        .update_resource(&mut c, &item)
        .await
    {
        Ok(_) => Json(item).into_response(),
        Err(_) => internal_error(),
    }
}
pub async fn delete_resource(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(id): Path<Uuid>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let item = match AuthorizationServiceRepo.find_resource(&mut c, id).await {
        Ok(Some(v)) => v,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(r) = realm_or_forbidden(&auth, item.realm_id) {
        return r;
    }
    match AuthorizationServiceRepo.delete_resource(&mut c, id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => internal_error(),
    }
}

pub async fn list_policies(
    State(state): State<AppState>,
    auth: AdminAuth,
    Query(q): Query<ServerQuery>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Err(r) = require_server(&state, &auth, q.resource_server_id).await {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match AuthorizationServiceRepo
        .list_policies(&mut c, q.resource_server_id)
        .await
    {
        Ok(v) => Json(json!({"items":v})).into_response(),
        Err(_) => internal_error(),
    }
}
pub async fn create_policy(
    State(state): State<AppState>,
    auth: AdminAuth,
    Json(req): Json<PolicyRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let server = match require_server(&state, &auth, req.resource_server_id).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if AuthorizationServiceRepo
        .list_policies(&mut c, server.id)
        .await
        .is_ok_and(|v| {
            v.iter()
                .any(|i| i.name.eq_ignore_ascii_case(req.name.trim()))
        })
    {
        return conflict();
    }
    let now = Utc::now();
    let item = AuthorizationPolicy {
        id: generate_uuid_v7(),
        realm_id: server.realm_id,
        resource_server_id: server.id,
        name: req.name,
        description: req.description,
        policy_type: req.policy_type,
        logic: req.logic,
        config: req.config,
        created_at: now,
        updated_at: now,
    };
    if let Err(e) = item.validate() {
        return invalid(e);
    }
    match AuthorizationServiceRepo.create_policy(&mut c, &item).await {
        Ok(_) => (StatusCode::CREATED, Json(item)).into_response(),
        Err(_) => internal_error(),
    }
}
pub async fn update_policy(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<PolicyRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut item = match AuthorizationServiceRepo.find_policy(&mut c, id).await {
        Ok(Some(v)) => v,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(r) = realm_or_forbidden(&auth, item.realm_id) {
        return r;
    }
    if req.resource_server_id != item.resource_server_id {
        return invalid("resource server cannot be changed");
    }
    if AuthorizationServiceRepo
        .list_policies(&mut c, item.resource_server_id)
        .await
        .is_ok_and(|items| {
            items.iter().any(|other| {
                other.id != item.id && other.name.eq_ignore_ascii_case(req.name.trim())
            })
        })
    {
        return conflict();
    }
    item.name = req.name;
    item.description = req.description;
    item.policy_type = req.policy_type;
    item.logic = req.logic;
    item.config = req.config;
    if let Err(e) = item.validate() {
        return invalid(e);
    }
    match AuthorizationServiceRepo.update_policy(&mut c, &item).await {
        Ok(_) => Json(item).into_response(),
        Err(_) => internal_error(),
    }
}
pub async fn delete_policy(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(id): Path<Uuid>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let item = match AuthorizationServiceRepo.find_policy(&mut c, id).await {
        Ok(Some(v)) => v,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(r) = realm_or_forbidden(&auth, item.realm_id) {
        return r;
    }
    match AuthorizationServiceRepo.delete_policy(&mut c, id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => internal_error(),
    }
}

pub async fn list_permissions(
    State(state): State<AppState>,
    auth: AdminAuth,
    Query(q): Query<ServerQuery>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Err(r) = require_server(&state, &auth, q.resource_server_id).await {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match AuthorizationServiceRepo
        .list_permissions(&mut c, q.resource_server_id)
        .await
    {
        Ok(v) => Json(json!({"items":v})).into_response(),
        Err(_) => internal_error(),
    }
}
pub async fn create_permission(
    State(state): State<AppState>,
    auth: AdminAuth,
    Json(req): Json<PermissionRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let server = match require_server(&state, &auth, req.resource_server_id).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if AuthorizationServiceRepo
        .list_permissions(&mut c, server.id)
        .await
        .is_ok_and(|v| {
            v.iter()
                .any(|i| i.name.eq_ignore_ascii_case(req.name.trim()))
        })
    {
        return conflict();
    }
    match permission_references_match_server(&mut c, server.id, &req.resources, &req.policies).await
    {
        Ok(true) => {}
        Ok(false) => return invalid("resources and policies must belong to the resource server"),
        Err(_) => return internal_error(),
    }
    let now = Utc::now();
    let item = AuthorizationPermission {
        id: generate_uuid_v7(),
        realm_id: server.realm_id,
        resource_server_id: server.id,
        name: req.name,
        description: req.description,
        resources: req.resources,
        scopes: req.scopes,
        policies: req.policies,
        decision_strategy: req.decision_strategy,
        created_at: now,
        updated_at: now,
    };
    if let Err(e) = item.validate() {
        return invalid(e);
    }
    match AuthorizationServiceRepo
        .create_permission(&mut c, &item)
        .await
    {
        Ok(_) => (StatusCode::CREATED, Json(item)).into_response(),
        Err(_) => internal_error(),
    }
}
pub async fn update_permission(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<PermissionRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut item = match AuthorizationServiceRepo.find_permission(&mut c, id).await {
        Ok(Some(v)) => v,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(r) = realm_or_forbidden(&auth, item.realm_id) {
        return r;
    }
    if req.resource_server_id != item.resource_server_id {
        return invalid("resource server cannot be changed");
    }
    if AuthorizationServiceRepo
        .list_permissions(&mut c, item.resource_server_id)
        .await
        .is_ok_and(|items| {
            items.iter().any(|other| {
                other.id != item.id && other.name.eq_ignore_ascii_case(req.name.trim())
            })
        })
    {
        return conflict();
    }
    match permission_references_match_server(
        &mut c,
        item.resource_server_id,
        &req.resources,
        &req.policies,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return invalid("resources and policies must belong to the resource server"),
        Err(_) => return internal_error(),
    }
    item.name = req.name;
    item.description = req.description;
    item.resources = req.resources;
    item.scopes = req.scopes;
    item.policies = req.policies;
    item.decision_strategy = req.decision_strategy;
    if let Err(e) = item.validate() {
        return invalid(e);
    }
    match AuthorizationServiceRepo
        .update_permission(&mut c, &item)
        .await
    {
        Ok(_) => Json(item).into_response(),
        Err(_) => internal_error(),
    }
}
pub async fn delete_permission(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(id): Path<Uuid>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let item = match AuthorizationServiceRepo.find_permission(&mut c, id).await {
        Ok(Some(v)) => v,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(r) = realm_or_forbidden(&auth, item.realm_id) {
        return r;
    }
    match AuthorizationServiceRepo.delete_permission(&mut c, id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => internal_error(),
    }
}

pub async fn list_tickets(
    State(state): State<AppState>,
    auth: AdminAuth,
    Query(q): Query<ServerQuery>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Err(r) = require_server(&state, &auth, q.resource_server_id).await {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match AuthorizationServiceRepo
        .list_tickets(&mut c, q.resource_server_id)
        .await
    {
        Ok(v) => Json(json!({"items":v})).into_response(),
        Err(_) => internal_error(),
    }
}
pub async fn revoke_ticket(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(id): Path<Uuid>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let ticket = match AuthorizationServiceRepo.find_ticket(&mut c, id).await {
        Ok(Some(v)) => v,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(r) = realm_or_forbidden(&auth, ticket.realm_id) {
        return r;
    }
    match AuthorizationServiceRepo.revoke_ticket(&mut c, id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => internal_error(),
    }
}
pub async fn list_rpts(
    State(state): State<AppState>,
    auth: AdminAuth,
    Query(q): Query<ServerQuery>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Err(r) = require_server(&state, &auth, q.resource_server_id).await {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match AuthorizationServiceRepo
        .list_rpts(&mut c, q.resource_server_id)
        .await
    {
        Ok(v) => Json(json!({"items":v})).into_response(),
        Err(_) => internal_error(),
    }
}
pub async fn revoke_rpt(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(id): Path<Uuid>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let rpt = match AuthorizationServiceRepo.find_rpt(&mut c, id).await {
        Ok(Some(v)) => v,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(r) = realm_or_forbidden(&auth, rpt.realm_id) {
        return r;
    }
    match AuthorizationServiceRepo.revoke_rpt(&mut c, id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => internal_error(),
    }
}
