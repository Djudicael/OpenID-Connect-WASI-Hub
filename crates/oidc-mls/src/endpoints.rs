//! MLS HTTP endpoints.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use uuid::Uuid;

use oidc_repository::Connection;

use crate::group_service::GroupService;
use crate::key_package_store::KeyPackageStore;
use crate::models::{
    CreateGroupRequest, JoinGroupRequest, SendCommitRequest, UploadKeyPackageRequest,
};

/// Shared state trait for MLS handlers.
pub trait MlsState: Clone + Send + Sync + 'static {
    /// Database configuration for per-request connections.
    fn db_config(&self) -> &wasi_pg_client::Config;
}

/// Create a new MLS group.
pub async fn create_group<S: MlsState>(
    State(state): State<S>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<Value>, StatusCode> {
    let conn = wasi_pg_client::Connection::connect(state.db_config())
        .await
        .map_err(|e| {
            tracing::error!("db connect: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut conn = Connection::from_pg_client(conn);

    let group = GroupService::create_group(&mut conn, req.realm_id, req.creator_user_id)
        .await
        .map_err(|e| {
            tracing::error!("create group: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(json!({
        "id": group.id,
        "epoch": group.epoch,
    })))
}

/// Join an MLS group (add member).
pub async fn join_group<S: MlsState>(
    State(state): State<S>,
    Path(group_id): Path<Uuid>,
    Json(req): Json<JoinGroupRequest>,
) -> Result<Json<Value>, StatusCode> {
    let conn = wasi_pg_client::Connection::connect(state.db_config())
        .await
        .map_err(|e| {
            tracing::error!("db connect: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut conn = Connection::from_pg_client(conn);

    GroupService::add_member(&mut conn, group_id, req.user_id)
        .await
        .map_err(|e| {
            tracing::error!("add member: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(
        json!({"joined": true, "group_id": group_id, "user_id": req.user_id}),
    ))
}

/// Send a commit to a group.
pub async fn send_commit<S: MlsState>(
    State(state): State<S>,
    Path(group_id): Path<Uuid>,
    Json(req): Json<SendCommitRequest>,
) -> Result<Json<Value>, StatusCode> {
    let conn = wasi_pg_client::Connection::connect(state.db_config())
        .await
        .map_err(|e| {
            tracing::error!("db connect: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut conn = Connection::from_pg_client(conn);

    let mut processor = crate::commit_processor::CommitProcessor::new();
    let commit_data = STANDARD.decode(&req.commit_data).unwrap_or_default();
    processor
        .process_commit(&mut conn, group_id, req.epoch, commit_data)
        .await
        .map_err(|e| {
            tracing::error!("process commit: {e}");
            StatusCode::BAD_REQUEST
        })?;

    Ok(Json(
        json!({"epoch": req.epoch, "accepted": true, "group_id": group_id}),
    ))
}

/// Upload a KeyPackage.
pub async fn upload_key_package<S: MlsState>(
    State(state): State<S>,
    Json(req): Json<UploadKeyPackageRequest>,
) -> Result<Json<Value>, StatusCode> {
    let conn = wasi_pg_client::Connection::connect(state.db_config())
        .await
        .map_err(|e| {
            tracing::error!("db connect: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut conn = Connection::from_pg_client(conn);

    let data = STANDARD.decode(&req.key_package_data).unwrap_or_default();
    let entry = KeyPackageStore::store(&mut conn, req.user_id, data)
        .await
        .map_err(|e| {
            tracing::error!("store key package: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(json!({
        "id": entry.id,
        "key_package_ref": STANDARD.encode(&entry.key_package_ref),
    })))
}

/// Get group welcome/info.
pub async fn welcome<S: MlsState>(
    State(state): State<S>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Value>, StatusCode> {
    let conn = wasi_pg_client::Connection::connect(state.db_config())
        .await
        .map_err(|e| {
            tracing::error!("db connect: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut conn = Connection::from_pg_client(conn);

    let group = GroupService::get_group(&mut conn, group_id)
        .await
        .map_err(|e| {
            tracing::error!("get group: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    match group {
        Some(g) => Ok(Json(json!({
            "id": g.id,
            "realm_id": g.realm_id,
            "epoch": g.epoch,
            "active": !g.group_state_encrypted.is_empty(),
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}
