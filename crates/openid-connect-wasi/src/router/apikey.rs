//! API key routes.

use axum::Router;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::Value;
use uuid::Uuid;

use oidc_apikey::service::ApiKeyService;
use oidc_core::models::audit_event::{ActorType, AuditEvent};
use oidc_repository::Connection;
use oidc_repository::repositories::api_key_repo::ApiKeyRepo;
use oidc_repository::repositories::audit_event_repo::AuditEventRepo;

use crate::middleware::admin_auth::AdminAuth;
use crate::state::AppState;

/// Build the API key sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/keys", get(list_keys))
        .route("/api/keys", post(create_key))
        .route("/api/keys/{id}", get(get_key).delete(revoke_key))
        .route("/api/keys/{id}/rotate", post(rotate_key))
        .layer(axum::middleware::from_fn(
            crate::middleware::csrf::csrf_middleware,
        ))
}

/// Extract the actor ID and type from the auth result.
fn auth_actor(auth: &AdminAuth) -> (Option<Uuid>, ActorType) {
    (
        auth.subject.parse::<Uuid>().ok(),
        if auth.is_api_key {
            ActorType::ApiKey
        } else {
            ActorType::User
        },
    )
}

/// API keys and delegated users are confined to their own realm. A JWT with
/// the broad `admin` permission retains the existing cross-realm access.
fn ensure_realm_access(auth: &AdminAuth, realm_id: Uuid) -> Option<Response> {
    if !auth.is_global_admin() && auth.realm_id != Some(realm_id) {
        Some(
            (
                axum::http::StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({"error": "forbidden"})),
            )
                .into_response(),
        )
    } else {
        None
    }
}

async fn list_keys(
    State(state): State<AppState>,
    Query(query): Query<oidc_apikey::models::ListKeysQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = ensure_realm_access(&auth, query.realm_id) {
        return response;
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

async fn create_key(State(state): State<AppState>, auth: AdminAuth, body: String) -> Response {
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

    if let Some(response) = ensure_realm_access(&auth, req.realm_id) {
        return response;
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
    // Only set created_by when the actor is a user (JWT), not an API key.
    // The api_keys.created_by column has a FK to users(id), so API key UUIDs
    // would violate the constraint.
    let created_by = (!auth.is_api_key)
        .then(|| auth.subject.parse::<Uuid>().ok())
        .flatten();
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
    auth: AdminAuth,
) -> Response {
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

    match result {
        Ok(Some(key)) => {
            if let Some(response) = ensure_realm_access(&auth, key.realm_id) {
                let _ = conn.close().await;
                return response;
            }

            // Gracefully close the connection.
            let _ = conn.close().await;

            axum::Json(serde_json::json!({
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
            .into_response()
        }
        Ok(None) => {
            let _ = conn.close().await;
            (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({"error": "not_found"})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("query error: {e}");
            let _ = conn.close().await;
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
    auth: AdminAuth,
) -> Response {
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

    let existing_key = match ApiKeyRepo.find_by_id(&mut conn, id).await {
        Ok(Some(key)) => key,
        Ok(None) => {
            let _ = conn.close().await;
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({"error": "not_found"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("query error: {e}");
            let _ = conn.close().await;
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    if let Some(response) = ensure_realm_access(&auth, existing_key.realm_id) {
        let _ = conn.close().await;
        return response;
    }

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
    auth: AdminAuth,
) -> Response {
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

    let existing_key = match ApiKeyRepo.find_by_id(&mut conn, id).await {
        Ok(Some(key)) => key,
        Ok(None) => {
            let _ = conn.close().await;
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({"error": "not_found"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("query error: {e}");
            let _ = conn.close().await;
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "internal"})),
            )
                .into_response();
        }
    };

    if let Some(response) = ensure_realm_access(&auth, existing_key.realm_id) {
        let _ = conn.close().await;
        return response;
    }

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
