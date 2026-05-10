//! API key HTTP endpoints.

use axum::Json;
use axum::http::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

use oidc_core::models::audit_event::{ActorType, AuditEvent};
use oidc_repository::Connection;
use oidc_repository::repositories::api_key_repo::ApiKeyRepo;
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;

use crate::auth::{ApiKeyAuth, has_scope};
use crate::models::{CreateKeyRequest, ListKeysQuery, RotateKeyResponse};
use crate::service::ApiKeyService;

/// List API keys for a realm.
pub async fn list_keys(
    db_config: &wasi_pg_client::Config,
    query: ListKeysQuery,
    auth: ApiKeyAuth,
) -> Result<Json<Value>, StatusCode> {
    if !has_scope(&auth.api_key, "admin") && !has_scope(&auth.api_key, "api_keys:read") {
        return Err(StatusCode::FORBIDDEN);
    }

    let conn = wasi_pg_client::Connection::connect(db_config)
        .await
        .map_err(|e| {
            tracing::error!("db connect error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut conn = Connection::from_pg_client(conn);

    let include_revoked = query.include_revoked.unwrap_or(false);
    let keys = ApiKeyRepo
        .find_by_realm(&mut conn, query.realm_id, include_revoked)
        .await
        .map_err(|e| {
            tracing::error!("query error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Gracefully close the connection so the server releases the backend
    // process immediately, rather than waiting for TCP keep-alive timeout.
    let _ = conn.close().await;

    let rows: Vec<Value> = keys
        .into_iter()
        .map(|key| {
            json!({
                "id": key.id.to_string(),
                "realm_id": key.realm_id.to_string(),
                "name": key.name,
                "prefix": key.prefix,
                "scopes": key.scopes,
                "expires_at": key.expires_at.map(|d| d.to_rfc3339()),
                "last_used_at": key.last_used_at.map(|d| d.to_rfc3339()),
                "request_count": key.request_count,
                "revoked": key.revoked,
                "created_at": key.created_at.to_rfc3339(),
                "created_by": key.created_by.map(|u| u.to_string()),
                "rotated_at": key.rotated_at.map(|d| d.to_rfc3339()),
            })
        })
        .collect();

    Ok(Json(json!({"items": rows, "total": rows.len()})))
}

/// Create a new API key.
pub async fn create_key(
    db_config: &wasi_pg_client::Config,
    req: CreateKeyRequest,
    auth: ApiKeyAuth,
) -> Result<Json<Value>, StatusCode> {
    if !has_scope(&auth.api_key, "admin") && !has_scope(&auth.api_key, "api_keys:write") {
        return Err(StatusCode::FORBIDDEN);
    }

    let conn = wasi_pg_client::Connection::connect(db_config)
        .await
        .map_err(|e| {
            tracing::error!("db connect error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut conn = Connection::from_pg_client(conn);

    let created_by = Some(auth.api_key.id);
    let (api_key, raw_key) = ApiKeyService::generate_key(
        &mut conn,
        req.realm_id,
        req.name,
        req.scopes,
        req.expires_in_days,
        created_by,
    )
    .await
    .map_err(|e| {
        tracing::error!("generate key error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Audit event
    let audit = AuditEvent {
        id: Uuid::new_v4(),
        realm_id: Some(api_key.realm_id),
        event_type: "api_key.created".into(),
        actor_id: created_by,
        actor_type: ActorType::ApiKey,
        target_type: Some("api_key".into()),
        target_id: Some(api_key.id),
        details: json!({"name": &api_key.name, "scopes": &api_key.scopes}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    let _ = AuditEventRepo.create(&mut conn, &audit).await;

    // Gracefully close the connection.
    let _ = conn.close().await;

    Ok(Json(json!({
        "id": api_key.id,
        "realm_id": api_key.realm_id,
        "name": api_key.name,
        "prefix": api_key.prefix,
        "scopes": api_key.scopes,
        "raw_key": raw_key,
        "expires_at": api_key.expires_at.map(|d| d.to_rfc3339()),
        "created_at": api_key.created_at.to_rfc3339(),
    })))
}

/// Revoke an API key by ID.
pub async fn revoke_key(
    db_config: &wasi_pg_client::Config,
    id: Uuid,
    auth: ApiKeyAuth,
) -> Result<Json<Value>, StatusCode> {
    if !has_scope(&auth.api_key, "admin") && !has_scope(&auth.api_key, "api_keys:write") {
        return Err(StatusCode::FORBIDDEN);
    }

    let conn = wasi_pg_client::Connection::connect(db_config)
        .await
        .map_err(|e| {
            tracing::error!("db connect error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut conn = Connection::from_pg_client(conn);

    ApiKeyService::revoke_key(&mut conn, id)
        .await
        .map_err(|e| {
            tracing::error!("revoke key error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Audit event
    let audit = AuditEvent {
        id: Uuid::new_v4(),
        realm_id: None,
        event_type: "api_key.revoked".into(),
        actor_id: Some(auth.api_key.id),
        actor_type: ActorType::ApiKey,
        target_type: Some("api_key".into()),
        target_id: Some(id),
        details: json!({}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    let _ = AuditEventRepo.create(&mut conn, &audit).await;

    // Gracefully close the connection.
    let _ = conn.close().await;

    Ok(Json(json!({"revoked": true})))
}

/// Rotate an API key by ID.
pub async fn rotate_key(
    db_config: &wasi_pg_client::Config,
    id: Uuid,
    auth: ApiKeyAuth,
) -> Result<Json<Value>, StatusCode> {
    if !has_scope(&auth.api_key, "admin") && !has_scope(&auth.api_key, "api_keys:write") {
        return Err(StatusCode::FORBIDDEN);
    }

    let conn = wasi_pg_client::Connection::connect(db_config)
        .await
        .map_err(|e| {
            tracing::error!("db connect error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut conn = Connection::from_pg_client(conn);

    let (new_key, raw_key) = ApiKeyService::rotate_key(&mut conn, id, None)
        .await
        .map_err(|e| {
            tracing::error!("rotate key error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Audit event
    let audit = AuditEvent {
        id: Uuid::new_v4(),
        realm_id: Some(new_key.realm_id),
        event_type: "api_key.rotated".into(),
        actor_id: Some(auth.api_key.id),
        actor_type: ActorType::ApiKey,
        target_type: Some("api_key".into()),
        target_id: Some(new_key.id),
        details: json!({"previous_id": id.to_string()}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    let _ = AuditEventRepo.create(&mut conn, &audit).await;

    // Gracefully close the connection.
    let _ = conn.close().await;

    let response = RotateKeyResponse {
        id: new_key.id,
        raw_key,
        expires_at: new_key.expires_at,
    };

    Ok(Json(serde_json::to_value(response).unwrap()))
}
