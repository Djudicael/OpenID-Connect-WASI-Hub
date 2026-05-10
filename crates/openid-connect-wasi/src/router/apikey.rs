//! API key routes.

use axum::Router;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::Value;
use uuid::Uuid;

use oidc_apikey::auth::{ApiRouteAuth, verify_request_auth};
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
        .route("/api/keys/{id}", get(get_key).delete(revoke_key))
        .route("/api/keys/{id}/rotate", post(rotate_key))
}

/// Check if the auth has admin access or the required scope.
///
/// JWT Bearer tokens from the admin login are treated as having admin access.
/// API keys must have either the `admin` scope or the specific required scope.
fn has_admin_or_scope(auth: &ApiRouteAuth, scope: &str) -> bool {
    match auth {
        ApiRouteAuth::ApiKey(api_key_auth) => {
            oidc_apikey::auth::has_scope(&api_key_auth.api_key, "admin")
                || oidc_apikey::auth::has_scope(&api_key_auth.api_key, scope)
        }
        ApiRouteAuth::JwtBearer { .. } => true, // JWT tokens from admin login have admin access
    }
}

/// Extract the actor ID and type from the auth result.
fn auth_actor(auth: &ApiRouteAuth) -> (Option<Uuid>, ActorType) {
    match auth {
        ApiRouteAuth::ApiKey(api_key_auth) => (Some(api_key_auth.api_key.id), ActorType::ApiKey),
        ApiRouteAuth::JwtBearer { subject } => (subject.parse::<Uuid>().ok(), ActorType::User),
    }
}

async fn list_keys(
    State(state): State<AppState>,
    Query(query): Query<oidc_apikey::models::ListKeysQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let auth = match verify_request_auth_local(&headers, &state).await {
        Ok(a) => a,
        Err(status) => {
            return (
                status,
                axum::Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    };
    if !has_admin_or_scope(&auth, "api_keys:read") {
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

    // Gracefully close the connection.
    let _ = conn.close().await;

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

    let auth = match verify_request_auth_local(&headers, &state).await {
        Ok(a) => a,
        Err(status) => {
            return (
                status,
                axum::Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    };
    if !has_admin_or_scope(&auth, "api_keys:write") {
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

    let (actor_id, actor_type) = auth_actor(&auth);
    let created_by = match &auth {
        ApiRouteAuth::ApiKey(api_key_auth) => Some(api_key_auth.api_key.id),
        ApiRouteAuth::JwtBearer { subject } => subject.parse::<Uuid>().ok(),
    };
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
        actor_id,
        actor_type,
        target_type: Some("api_key".into()),
        target_id: Some(api_key.id),
        details: serde_json::json!({"name": &api_key.name, "scopes": &api_key.scopes}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    let _ = AuditEventRepo.create(&mut conn, &audit).await;

    // Gracefully close the connection.
    let _ = conn.close().await;

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

async fn get_key(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> Response {
    let auth = match verify_request_auth_local(&headers, &state).await {
        Ok(a) => a,
        Err(status) => {
            return (
                status,
                axum::Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    };
    if !has_admin_or_scope(&auth, "api_keys:read") {
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

    let result = ApiKeyRepo.find_by_id(&mut conn, id).await;
    // Gracefully close the connection.
    let _ = conn.close().await;

    match result {
        Ok(Some(key)) => axum::Json(serde_json::json!({
            "id": key.id.to_string(),
            "realm_id": key.realm_id.to_string(),
            "name": key.name,
            "prefix": key.prefix,
            "scopes": key.scopes,
            "revoked": key.revoked,
            "request_count": key.request_count,
            "expires_at": key.expires_at.map(|d| d.to_rfc3339()),
            "last_used_at": key.last_used_at.map(|d| d.to_rfc3339()),
            "created_at": key.created_at.to_rfc3339(),
            "created_by": key.created_by.map(|u| u.to_string()),
            "rotated_at": key.rotated_at.map(|d| d.to_rfc3339()),
        }))
        .into_response(),
        Ok(None) => (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error": "not_found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("query error: {e}");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "internal"})),
            )
                .into_response()
        }
    }
}

async fn revoke_key(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> Response {
    let auth = match verify_request_auth_local(&headers, &state).await {
        Ok(a) => a,
        Err(status) => {
            return (
                status,
                axum::Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    };
    if !has_admin_or_scope(&auth, "api_keys:write") {
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
    let (actor_id, actor_type) = auth_actor(&auth);
    let audit = AuditEvent {
        id: Uuid::new_v4(),
        realm_id: None,
        event_type: "api_key.revoked".into(),
        actor_id,
        actor_type,
        target_type: Some("api_key".into()),
        target_id: Some(id),
        details: serde_json::json!({}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    let _ = AuditEventRepo.create(&mut conn, &audit).await;

    // Gracefully close the connection.
    let _ = conn.close().await;

    axum::Json(serde_json::json!({"revoked": true})).into_response()
}

async fn rotate_key(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> Response {
    let auth = match verify_request_auth_local(&headers, &state).await {
        Ok(a) => a,
        Err(status) => {
            return (
                status,
                axum::Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    };
    if !has_admin_or_scope(&auth, "api_keys:write") {
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
    let (actor_id, actor_type) = auth_actor(&auth);
    let audit = AuditEvent {
        id: Uuid::new_v4(),
        realm_id: Some(new_key.realm_id),
        event_type: "api_key.rotated".into(),
        actor_id,
        actor_type,
        target_type: Some("api_key".into()),
        target_id: Some(new_key.id),
        details: serde_json::json!({"previous_id": id.to_string()}),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };
    let _ = AuditEventRepo.create(&mut conn, &audit).await;

    // Gracefully close the connection.
    let _ = conn.close().await;

    axum::Json(serde_json::json!({
        "id": new_key.id,
        "raw_key": raw_key,
        "expires_at": new_key.expires_at.map(|d| d.to_rfc3339()),
    }))
    .into_response()
}

/// Extract raw API key from headers and verify it, or fall back to JWT Bearer token.
///
/// Delegates to the shared `verify_request_auth` from `oidc-apikey`.
async fn verify_request_auth_local(
    headers: &axum::http::HeaderMap,
    state: &AppState,
) -> Result<ApiRouteAuth, axum::http::StatusCode> {
    verify_request_auth(headers, &state.db_config, &*state.token_service).await
}
