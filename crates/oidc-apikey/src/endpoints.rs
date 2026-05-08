//! API key HTTP endpoints.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

use oidc_repository::Connection;

use crate::models::{CreateKeyRequest, ListKeysQuery};
use crate::service::ApiKeyService;

/// Shared state trait bound used by the apikey router.
///
/// The concrete `AppState` in `openid-connect-wasi` implements this.
pub trait ApiKeyState: Clone + Send + Sync + 'static {
    /// Obtain a database configuration so we can open a per-request connection.
    fn db_config(&self) -> &wasi_pg_client::Config;
}

/// List API keys for a realm.
pub async fn list_keys<S: ApiKeyState>(
    State(state): State<S>,
    Query(query): Query<ListKeysQuery>,
) -> Result<Json<Value>, StatusCode> {
    let conn = wasi_pg_client::Connection::connect(state.db_config())
        .await
        .map_err(|e| {
            tracing::error!("db connect error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut conn = Connection::from_pg_client(conn);

    // Simple query; in production this should use a repository method with pagination.
    let sql = r#"
        SELECT id, realm_id, name, prefix, hashed_secret,
               scopes, revoked, request_count
        FROM api_keys
        WHERE realm_id = $1 AND NOT revoked
    "#;

    let result = conn
        .query_params(sql, &[&query.realm_id])
        .await
        .map_err(|e| {
            tracing::error!("query error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let rows: Vec<Value> = result
        .into_rows()
        .into_iter()
        .map(|row| {
            json!({
                "id": row.get::<Uuid>(0).ok().map(|v| v.to_string()),
                "realm_id": row.get::<Uuid>(1).ok().map(|v| v.to_string()),
                "name": row.get::<String>(2).ok(),
                "prefix": row.get::<String>(3).ok(),
                "scopes": row.get::<serde_json::Value>(5).ok(),
                "revoked": row.get::<bool>(6).ok(),
                "request_count": row.get::<i64>(7).ok(),
            })
        })
        .collect();

    Ok(Json(json!({"items": rows, "total": rows.len()})))
}

/// Create a new API key.
pub async fn create_key<S: ApiKeyState>(
    State(state): State<S>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<Json<Value>, StatusCode> {
    let conn = wasi_pg_client::Connection::connect(state.db_config())
        .await
        .map_err(|e| {
            tracing::error!("db connect error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut conn = Connection::from_pg_client(conn);

    let (api_key, raw_key) =
        ApiKeyService::generate_key(&mut conn, req.realm_id, req.name, req.scopes)
            .await
            .map_err(|e| {
                tracing::error!("generate key error: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    Ok(Json(json!({
        "id": api_key.id,
        "realm_id": api_key.realm_id,
        "name": api_key.name,
        "prefix": api_key.prefix,
        "scopes": api_key.scopes,
        "raw_key": raw_key,
        "revoked": api_key.revoked,
        "request_count": api_key.request_count,
    })))
}

/// Revoke an API key by ID.
pub async fn revoke_key<S: ApiKeyState>(
    State(state): State<S>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<Value>, StatusCode> {
    let conn = wasi_pg_client::Connection::connect(state.db_config())
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

    Ok(Json(json!({"revoked": true})))
}
