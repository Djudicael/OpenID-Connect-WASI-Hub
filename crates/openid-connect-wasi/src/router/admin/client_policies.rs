use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use oidc_core::utils::generate_uuid_v7;
use oidc_core::{
    OidcError,
    models::{
        ActorType, AuditEvent, ClientPolicy, ClientPolicyCondition, ClientPolicyExecutor,
        ClientPolicyProfile, ClientRegistrationContext,
    },
};
use oidc_repository::repositories::{
    audit_event_repo::AuditEventRepo, client_policy_repo::ClientPolicyRepo, client_repo::ClientRepo,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::{admin_or_forbidden, connect, internal_error, not_found, realm_or_forbidden};
use crate::{middleware::admin_auth::AdminAuth, state::AppState};

#[derive(Deserialize)]
pub struct ProfileRequest {
    pub name: String,
    pub description: Option<String>,
    pub executors: Vec<ClientPolicyExecutor>,
}
#[derive(Deserialize)]
pub struct PolicyRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "priority")]
    pub priority: i32,
    pub conditions: Vec<ClientPolicyCondition>,
    pub profile_ids: Vec<Uuid>,
}
#[derive(Deserialize)]
pub struct EvaluationRequest {
    pub context: ClientRegistrationContext,
    pub client_id: Uuid,
}
fn yes() -> bool {
    true
}
fn priority() -> i32 {
    100
}
fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({"error":code,"error_description":message.into()})),
    )
        .into_response()
}
fn oidc_error(e: OidcError) -> Response {
    match e {
        OidcError::InvalidInput(m) => error(StatusCode::BAD_REQUEST, "invalid_request", m),
        OidcError::Conflict(m) if m == "profile is assigned to a client policy" => {
            error(StatusCode::CONFLICT, "conflict", m)
        }
        OidcError::Conflict(_) => error(
            StatusCode::CONFLICT,
            "conflict",
            "A client policy or security profile with this name already exists",
        ),
        OidcError::NotFound(m) => error(StatusCode::NOT_FOUND, "not_found", m),
        e => {
            tracing::error!("client policy error: {e}");
            internal_error()
        }
    }
}
async fn audit(
    conn: &mut oidc_repository::Connection,
    auth: &AdminAuth,
    realm: Uuid,
    event: &str,
    target: Uuid,
) {
    let value = AuditEvent {
        id: generate_uuid_v7(),
        realm_id: Some(realm),
        event_type: event.into(),
        actor_id: auth.subject.parse().ok(),
        actor_type: if auth.is_api_key {
            ActorType::ApiKey
        } else {
            ActorType::User
        },
        target_type: Some("client_policy".into()),
        target_id: Some(target),
        details: json!({}),
        ip_address: None,
        user_agent: None,
        created_at: Utc::now(),
    };
    if let Err(e) = AuditEventRepo.create(conn, &value).await {
        tracing::warn!("client policy audit failed: {e}")
    }
}
async fn valid_profiles(
    conn: &mut oidc_repository::Connection,
    realm: Uuid,
    ids: &[Uuid],
) -> Result<(), OidcError> {
    for id in ids {
        if !ClientPolicyRepo
            .find_profile(conn, *id)
            .await?
            .is_some_and(|p| p.realm_id == realm)
        {
            return Err(OidcError::InvalidInput(format!(
                "profile {id} does not exist in this realm"
            )));
        }
    }
    Ok(())
}

pub async fn list_profiles(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(realm): Path<Uuid>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Some(r) = realm_or_forbidden(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match ClientPolicyRepo.list_profiles(&mut c, realm).await {
        Ok(v) => Json(json!({"items":v})).into_response(),
        Err(e) => oidc_error(e),
    }
}
pub async fn create_profile(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(realm): Path<Uuid>,
    Json(req): Json<ProfileRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Some(r) = realm_or_forbidden(&auth, realm) {
        return r;
    }
    let now = Utc::now();
    let v = ClientPolicyProfile {
        id: generate_uuid_v7(),
        realm_id: realm,
        name: req.name.trim().into(),
        description: req.description.filter(|v| !v.trim().is_empty()),
        executors: req.executors,
        created_at: now,
        updated_at: now,
    };
    if let Err(e) = v.validate() {
        return oidc_error(e);
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match ClientPolicyRepo.create_profile(&mut c, &v).await {
        Ok(()) => {
            audit(&mut c, &auth, realm, "client_policy.profile_created", v.id).await;
            (StatusCode::CREATED, Json(v)).into_response()
        }
        Err(e) => oidc_error(e),
    }
}
pub async fn update_profile(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path((realm, id)): Path<(Uuid, Uuid)>,
    Json(req): Json<ProfileRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Some(r) = realm_or_forbidden(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let old = match ClientPolicyRepo.find_profile(&mut c, id).await {
        Ok(Some(value)) => value,
        Ok(None) => return not_found(),
        Err(e) => return oidc_error(e),
    };
    if old.realm_id != realm {
        return not_found();
    }
    let v = ClientPolicyProfile {
        id,
        realm_id: realm,
        name: req.name.trim().into(),
        description: req.description.filter(|v| !v.trim().is_empty()),
        executors: req.executors,
        created_at: old.created_at,
        updated_at: Utc::now(),
    };
    if let Err(e) = v.validate() {
        return oidc_error(e);
    }
    match ClientPolicyRepo.update_profile(&mut c, &v).await {
        Ok(()) => {
            audit(&mut c, &auth, realm, "client_policy.profile_updated", id).await;
            Json(v).into_response()
        }
        Err(e) => oidc_error(e),
    }
}
pub async fn delete_profile(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path((realm, id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Some(r) = realm_or_forbidden(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match ClientPolicyRepo.find_profile(&mut c, id).await {
        Ok(Some(value)) if value.realm_id == realm => {}
        Ok(_) => return not_found(),
        Err(e) => return oidc_error(e),
    }
    match ClientPolicyRepo.delete_profile(&mut c, id).await {
        Ok(()) => {
            audit(&mut c, &auth, realm, "client_policy.profile_deleted", id).await;
            Json(json!({"deleted":true})).into_response()
        }
        Err(e) => oidc_error(e),
    }
}

pub async fn list_policies(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(realm): Path<Uuid>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Some(r) = realm_or_forbidden(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match ClientPolicyRepo.list_policies(&mut c, realm).await {
        Ok(v) => Json(json!({"items":v})).into_response(),
        Err(e) => oidc_error(e),
    }
}
pub async fn create_policy(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(realm): Path<Uuid>,
    Json(req): Json<PolicyRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Some(r) = realm_or_forbidden(&auth, realm) {
        return r;
    }
    let now = Utc::now();
    let v = ClientPolicy {
        id: generate_uuid_v7(),
        realm_id: realm,
        name: req.name.trim().into(),
        description: req.description.filter(|v| !v.trim().is_empty()),
        enabled: req.enabled,
        priority: req.priority,
        conditions: req.conditions,
        profile_ids: req.profile_ids,
        created_at: now,
        updated_at: now,
    };
    if let Err(e) = v.validate() {
        return oidc_error(e);
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(e) = valid_profiles(&mut c, realm, &v.profile_ids).await {
        return oidc_error(e);
    }
    match ClientPolicyRepo.create_policy(&mut c, &v).await {
        Ok(()) => {
            audit(&mut c, &auth, realm, "client_policy.created", v.id).await;
            (StatusCode::CREATED, Json(v)).into_response()
        }
        Err(e) => oidc_error(e),
    }
}
pub async fn update_policy(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path((realm, id)): Path<(Uuid, Uuid)>,
    Json(req): Json<PolicyRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Some(r) = realm_or_forbidden(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let old = match ClientPolicyRepo.find_policy(&mut c, id).await {
        Ok(Some(value)) => value,
        Ok(None) => return not_found(),
        Err(e) => return oidc_error(e),
    };
    if old.realm_id != realm {
        return not_found();
    }
    let v = ClientPolicy {
        id,
        realm_id: realm,
        name: req.name.trim().into(),
        description: req.description.filter(|v| !v.trim().is_empty()),
        enabled: req.enabled,
        priority: req.priority,
        conditions: req.conditions,
        profile_ids: req.profile_ids,
        created_at: old.created_at,
        updated_at: Utc::now(),
    };
    if let Err(e) = v.validate() {
        return oidc_error(e);
    }
    if let Err(e) = valid_profiles(&mut c, realm, &v.profile_ids).await {
        return oidc_error(e);
    }
    match ClientPolicyRepo.update_policy(&mut c, &v).await {
        Ok(()) => {
            audit(&mut c, &auth, realm, "client_policy.updated", id).await;
            Json(v).into_response()
        }
        Err(e) => oidc_error(e),
    }
}
pub async fn delete_policy(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path((realm, id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Some(r) = realm_or_forbidden(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match ClientPolicyRepo.find_policy(&mut c, id).await {
        Ok(Some(value)) if value.realm_id == realm => {}
        Ok(_) => return not_found(),
        Err(e) => return oidc_error(e),
    }
    match ClientPolicyRepo.delete_policy(&mut c, id).await {
        Ok(()) => {
            audit(&mut c, &auth, realm, "client_policy.deleted", id).await;
            Json(json!({"deleted":true})).into_response()
        }
        Err(e) => oidc_error(e),
    }
}
pub async fn evaluate(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(realm): Path<Uuid>,
    Json(req): Json<EvaluationRequest>,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    if let Some(r) = realm_or_forbidden(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let client = match ClientRepo.find_by_id(&mut c, req.client_id).await {
        Ok(Some(v)) => v,
        Ok(None) => return not_found(),
        Err(e) => return oidc_error(e),
    };
    if client.realm_id != realm {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the sample client must belong to the selected realm",
        );
    }
    match oidc_oidc::client_policies::evaluate(&mut c, &client, req.context).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => oidc_error(e),
    }
}
