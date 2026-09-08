use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use oidc_core::{
    OidcError,
    models::{Workflow, WorkflowCondition, WorkflowSchedule, WorkflowStep},
    utils::generate_uuid_v7,
};
use oidc_repository::repositories::workflow_repo::WorkflowRepo;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::{admin_or_forbidden, connect, internal_error, not_found, realm_or_forbidden};
use crate::{middleware::admin_auth::AdminAuth, state::AppState};

#[derive(Deserialize)]
pub struct WorkflowRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub trigger_events: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<WorkflowCondition>,
    pub steps: Vec<WorkflowStep>,
    pub schedule: Option<WorkflowSchedule>,
}
fn enabled() -> bool {
    true
}
#[derive(Deserialize)]
pub struct ActivateRequest {
    pub user_id: Uuid,
}
#[derive(Deserialize)]
pub struct ExecutionQuery {
    pub workflow_id: Option<Uuid>,
    pub limit: Option<i64>,
}
#[derive(Deserialize)]
pub struct RunRequest {
    pub limit: Option<i64>,
}

fn oidc_error(error: OidcError) -> Response {
    match error {
        OidcError::InvalidInput(m) => error_response(StatusCode::BAD_REQUEST, "invalid_request", m),
        OidcError::NotFound(m) => error_response(StatusCode::NOT_FOUND, "not_found", m),
        OidcError::Conflict(_) => error_response(
            StatusCode::CONFLICT,
            "conflict",
            "A workflow with this name already exists",
        ),
        other => {
            tracing::error!("workflow error: {other}");
            internal_error()
        }
    }
}
fn error_response(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({"error":code,"error_description":message.into()})),
    )
        .into_response()
}
fn authorize(auth: &AdminAuth, realm: Uuid) -> Option<Response> {
    admin_or_forbidden(auth).or_else(|| realm_or_forbidden(auth, realm))
}

pub async fn list(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(realm): Path<Uuid>,
) -> Response {
    if let Some(r) = authorize(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match WorkflowRepo.list(&mut c, realm).await {
        Ok(items) => Json(json!({"items":items})).into_response(),
        Err(e) => oidc_error(e),
    }
}
pub async fn create(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(realm): Path<Uuid>,
    Json(req): Json<WorkflowRequest>,
) -> Response {
    if let Some(r) = authorize(&auth, realm) {
        return r;
    }
    let now = Utc::now();
    let value = Workflow {
        id: generate_uuid_v7(),
        realm_id: realm,
        name: req.name.trim().into(),
        description: req
            .description
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
        enabled: req.enabled,
        trigger_events: req
            .trigger_events
            .into_iter()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect(),
        conditions: req.conditions,
        steps: req.steps,
        schedule: req.schedule,
        last_scheduled_at: None,
        created_at: now,
        updated_at: now,
    };
    if let Err(e) = value.validate() {
        return oidc_error(e);
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(e) = WorkflowRepo.validate_references(&mut c, &value).await {
        return oidc_error(e);
    }
    match WorkflowRepo.create(&mut c, &value).await {
        Ok(()) => (StatusCode::CREATED, Json(value)).into_response(),
        Err(e) => oidc_error(e),
    }
}
pub async fn update(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path((realm, id)): Path<(Uuid, Uuid)>,
    Json(req): Json<WorkflowRequest>,
) -> Response {
    if let Some(r) = authorize(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let old = match WorkflowRepo.find(&mut c, id).await {
        Ok(Some(v)) if v.realm_id == realm => v,
        Ok(_) => return not_found(),
        Err(e) => return oidc_error(e),
    };
    let value = Workflow {
        id,
        realm_id: realm,
        name: req.name.trim().into(),
        description: req
            .description
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
        enabled: req.enabled,
        trigger_events: req
            .trigger_events
            .into_iter()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect(),
        conditions: req.conditions,
        steps: req.steps,
        schedule: req.schedule,
        last_scheduled_at: old.last_scheduled_at,
        created_at: old.created_at,
        updated_at: Utc::now(),
    };
    if let Err(e) = value.validate() {
        return oidc_error(e);
    }
    if let Err(e) = WorkflowRepo.validate_references(&mut c, &value).await {
        return oidc_error(e);
    }
    match WorkflowRepo.update(&mut c, &value).await {
        Ok(()) => Json(value).into_response(),
        Err(e) => oidc_error(e),
    }
}
pub async fn delete_workflow(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path((realm, id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Some(r) = authorize(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match WorkflowRepo.find(&mut c, id).await {
        Ok(Some(v)) if v.realm_id == realm => {}
        Ok(_) => return not_found(),
        Err(e) => return oidc_error(e),
    }
    match WorkflowRepo.delete(&mut c, id).await {
        Ok(()) => Json(json!({"deleted":true})).into_response(),
        Err(e) => oidc_error(e),
    }
}
pub async fn activate(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path((realm, id)): Path<(Uuid, Uuid)>,
    Json(req): Json<ActivateRequest>,
) -> Response {
    if let Some(r) = authorize(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let workflow = match WorkflowRepo.find(&mut c, id).await {
        Ok(Some(v)) if v.realm_id == realm => v,
        Ok(_) => return not_found(),
        Err(e) => return oidc_error(e),
    };
    if !workflow.enabled {
        return oidc_error(OidcError::InvalidInput("workflow is disabled".into()));
    }
    match WorkflowRepo.activate(&mut c,&workflow,req.user_id,"manual").await{Ok(Some(execution_id))=>{let _=WorkflowRepo.run_due(&mut c,Some(realm),100,false).await;Json(json!({"execution_id":execution_id,"activated":true})).into_response()},Ok(None)=>Json(json!({"activated":false,"reason":"Conditions did not match or an execution is already active"})).into_response(),Err(e)=>oidc_error(e)}
}
pub async fn executions(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(realm): Path<Uuid>,
    Query(q): Query<ExecutionQuery>,
) -> Response {
    if let Some(r) = authorize(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match WorkflowRepo
        .list_executions(&mut c, realm, q.workflow_id, q.limit.unwrap_or(100))
        .await
    {
        Ok(items) => Json(json!({"items":items})).into_response(),
        Err(e) => oidc_error(e),
    }
}
pub async fn run_due(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(realm): Path<Uuid>,
    Json(req): Json<RunRequest>,
) -> Response {
    if let Some(r) = authorize(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match WorkflowRepo
        .run_due(&mut c, Some(realm), req.limit.unwrap_or(500), true)
        .await
    {
        Ok(report) => Json(report).into_response(),
        Err(e) => oidc_error(e),
    }
}
pub async fn retry(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path((realm, id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Some(r) = authorize(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match WorkflowRepo.retry(&mut c, id, realm).await {
        Ok(()) => {
            let _ = WorkflowRepo.run_due(&mut c, Some(realm), 100, false).await;
            Json(json!({"retried":true})).into_response()
        }
        Err(e) => oidc_error(e),
    }
}
pub async fn cancel(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path((realm, id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Some(r) = authorize(&auth, realm) {
        return r;
    }
    let mut c = match connect(&state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match WorkflowRepo.cancel(&mut c, id, realm).await {
        Ok(()) => Json(json!({"cancelled":true})).into_response(),
        Err(e) => oidc_error(e),
    }
}
