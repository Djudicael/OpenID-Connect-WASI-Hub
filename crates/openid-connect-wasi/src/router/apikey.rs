//! API key routes.

use axum::Router;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde_json::Value;
use uuid::Uuid;

use oidc_apikey::service::ApiKeyService;
use oidc_core::models::audit_event::{ActorType, AuditEvent};
use oidc_repository::Connection;
use oidc_repository::repositories::api_key_repo::ApiKeyRepo;
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;

use crate::state::AppState;

/// Build the API key sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/keys", get(list_keys))
        .route("/api/keys", post(create_key))
        .route("/api/keys/{id}", delete(revoke_key))
        .route("/api/keys/{id}/rotate", post(rotate_key))
}

async fn list_keys(
    State(state): State<AppState>,
    Query(query): Query<oidc_apikey::models::ListKeysQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let auth = match verify_request_api_key(&headers, &state.db_config).await {
        Ok(a) => a,
        Err(status) => {
            return (
                status,
                axum::Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    };
    if !oidc_apikey::auth::has_scope(&auth.api_key, "admin")
        && !oidc_apikey::auth::has_scope(&auth.api_key, "api_keys:read")
    {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }

    let mut conn = match wasi_pg_client::Connection::connect(&state.db_config).await {
        Ok(c) => Connection::from_pg_client(c),
        Err(e) => {
            tracing::error!("db connect error: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    let include_revoked = query.include_revoked.unwrap_or(false);
    let keys = match ApiKeyRepo
        .find_by_realm(&mut conn, query.realm_id, include_revoked)
        .await
    {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("query error: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    let rows: Vec<Value> = keys
        .into_iter()
        .map(|key| {
            serde_json::json!({
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

    axum::Json(serde_json::json!({"items": rows, "total": rows.len()})).into_response()
}

async fn create_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let req: oidc_apikey::models::CreateKeyRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "bad_request"})),
            )
                .into_response();
        }
    };

    let auth = match verify_request_api_key(&headers, &state.db_config).await {
        Ok(a) => a,
        Err(status) => {
            return (
                status,
                axum::Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    };
    if !oidc_apikey::auth::has_scope(&auth.api_key, "admin")
        && !oidc_apikey::auth::has_scope(&auth.api_key, "api_keys:write")
    {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }

    let mut conn = match wasi_pg_client::Connection::connect(&state.db_config).await {
        Ok(c) => Connection::from_pg_client(c),
        Err(e) => {
            tracing::error!("db connect error: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    let created_by = Some(auth.api_key.id);
    let (api_key, raw_key) = match ApiKeyService::generate_key(
        &mut conn,
        req.realm_id,
        req.name,
        req.scopes,
        req.expires_in_days,
        created_by,
    )
    .await
    {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("generate key error: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    // Audit event
    let audit = AuditEvent {
        id: Uuid::new_v4(),
        realm_id: Some(api_key.realm_id),
        event_type: "api_key.created".into(),
        actor_id: created_by,
        actor_type: ActorType::ApiKey,
        target_type: Some("api_key".into()),
        target_id: Some(api_key.id),
        details: serde_json::json!({"name": &api_key.name, "scopes": &api_key.scopes}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    let _ = AuditEventRepo.create(&mut conn, &audit).await;

    axum::Json(serde_json::json!({
        "id": api_key.id,
        "realm_id": api_key.realm_id,
        "name": api_key.name,
        "prefix": api_key.prefix,
        "scopes": api_key.scopes,
        "raw_key": raw_key,
        "expires_at": api_key.expires_at.map(|d| d.to_rfc3339()),
        "created_at": api_key.created_at.to_rfc3339(),
    }))
    .into_response()
}

async fn revoke_key(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> Response {
    let auth = match verify_request_api_key(&headers, &state.db_config).await {
        Ok(a) => a,
        Err(status) => {
            return (
                status,
                axum::Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    };
    if !oidc_apikey::auth::has_scope(&auth.api_key, "admin")
        && !oidc_apikey::auth::has_scope(&auth.api_key, "api_keys:write")
    {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }

    let mut conn = match wasi_pg_client::Connection::connect(&state.db_config).await {
        Ok(c) => Connection::from_pg_client(c),
        Err(e) => {
            tracing::error!("db connect error: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    if let Err(e) = ApiKeyService::revoke_key(&mut conn, id).await {
        tracing::error!("revoke key error: {e}");
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": "internal"})),
        )
            .into_response();
    }

    // Audit event
    let audit = AuditEvent {
        id: Uuid::new_v4(),
        realm_id: None,
        event_type: "api_key.revoked".into(),
        actor_id: Some(auth.api_key.id),
        actor_type: ActorType::ApiKey,
        target_type: Some("api_key".into()),
        target_id: Some(id),
        details: serde_json::json!({}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    let _ = AuditEventRepo.create(&mut conn, &audit).await;

    axum::Json(serde_json::json!({"revoked": true})).into_response()
}

async fn rotate_key(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> Response {
    let auth = match verify_request_api_key(&headers, &state.db_config).await {
        Ok(a) => a,
        Err(status) => {
            return (
                status,
                axum::Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    };
    if !oidc_apikey::auth::has_scope(&auth.api_key, "admin")
        && !oidc_apikey::auth::has_scope(&auth.api_key, "api_keys:write")
    {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }

    let mut conn = match wasi_pg_client::Connection::connect(&state.db_config).await {
        Ok(c) => Connection::from_pg_client(c),
        Err(e) => {
            tracing::error!("db connect error: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    let (new_key, raw_key) = match ApiKeyService::rotate_key(&mut conn, id, None).await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("rotate key error: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    // Audit event
    let audit = AuditEvent {
        id: Uuid::new_v4(),
        realm_id: Some(new_key.realm_id),
        event_type: "api_key.rotated".into(),
        actor_id: Some(auth.api_key.id),
        actor_type: ActorType::ApiKey,
        target_type: Some("api_key".into()),
        target_id: Some(new_key.id),
        details: serde_json::json!({"previous_id": id.to_string()}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    let _ = AuditEventRepo.create(&mut conn, &audit).await;

    axum::Json(serde_json::json!({
        "id": new_key.id,
        "raw_key": raw_key,
        "expires_at": new_key.expires_at.map(|d| d.to_rfc3339()),
    }))
    .into_response()
}

/// Extract raw API key from headers and verify it.
async fn verify_request_api_key(
    headers: &axum::http::HeaderMap,
    db_config: &wasi_pg_client::Config,
) -> Result<oidc_apikey::auth::ApiKeyAuth, axum::http::StatusCode> {
    let raw_key = extract_raw_key(headers).ok_or(axum::http::StatusCode::UNAUTHORIZED)?;

    let conn = wasi_pg_client::Connection::connect(db_config)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut conn = Connection::from_pg_client(conn);

    let api_key = ApiKeyService::verify_key(&mut conn, &raw_key)
        .await
        .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;

    // Best-effort usage tracking
    let _ = ApiKeyService::increment_usage(&mut conn, api_key.id).await;

    Ok(oidc_apikey::auth::ApiKeyAuth { api_key })
}

/// Extract raw key from X-API-Key or Authorization header.
fn extract_raw_key(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(header) = headers.get("X-API-Key") {
        if let Ok(val) = header.to_str() {
            return Some(val.trim().to_string());
        }
    }
    if let Some(header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.trim().to_string());
            }
            if let Some(token) = auth_str.strip_prefix("bearer ") {
                return Some(token.trim().to_string());
            }
        }
    }
    None
}
