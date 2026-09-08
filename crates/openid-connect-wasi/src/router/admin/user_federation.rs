use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use oidc_core::models::{UserFederationProvider, UserFederationType};
use oidc_core::utils::generate_uuid_v7;
use oidc_repository::repositories::user_federation_repo::UserFederationRepo;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::middleware::admin_auth::AdminAuth;
use crate::router::admin::{
    admin_or_forbidden, conflict, connect, internal_error, not_found, realm_or_forbidden,
};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct RealmQuery {
    realm_id: Uuid,
}

#[derive(Deserialize)]
pub struct ProviderRequest {
    realm_id: Uuid,
    name: String,
    provider_type: UserFederationType,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    priority: i32,
    gateway_url: String,
    gateway_secret: Option<String>,
    #[serde(default = "empty_object")]
    config: Value,
    #[serde(default = "yes")]
    import_users: bool,
    #[serde(default = "yes")]
    sync_groups: bool,
}

fn yes() -> bool {
    true
}
fn empty_object() -> Value {
    json!({})
}

fn config_contains_secret(value: &Value) -> bool {
    match value {
        Value::Object(values) => values.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            ["password", "secret", "keytab", "credential", "private_key"]
                .iter()
                .any(|part| key.contains(part))
                || config_contains_secret(value)
        }),
        Value::Array(values) => values.iter().any(config_contains_secret),
        _ => false,
    }
}

fn validate_public_config(config: &Value) -> Result<(), Response> {
    if config_contains_secret(config) {
        return Err(invalid(
            "store directory passwords, credentials, and keytabs in the federation gateway",
        ));
    }
    Ok(())
}

fn provider_json(provider: &UserFederationProvider, count: Option<i64>) -> Value {
    json!({
        "id": provider.id, "realm_id": provider.realm_id, "name": provider.name,
        "provider_type": provider.provider_type, "enabled": provider.enabled,
        "priority": provider.priority, "gateway_url": provider.gateway_url,
        "gateway_secret_configured": !provider.gateway_secret.is_empty(), "config": provider.config,
        "import_users": provider.import_users, "sync_groups": provider.sync_groups,
        "last_sync_at": provider.last_sync_at, "last_sync_status": provider.last_sync_status,
        "last_sync_error": provider.last_sync_error, "linked_users": count,
    })
}

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<RealmQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    if let Some(response) = realm_or_forbidden(&auth, query.realm_id) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match UserFederationRepo
        .list_providers(&mut conn, query.realm_id)
        .await
    {
        Ok(providers) => {
            let mut items = Vec::with_capacity(providers.len());
            for provider in providers {
                let count = UserFederationRepo
                    .count_links(&mut conn, provider.id)
                    .await
                    .unwrap_or(0);
                items.push(provider_json(&provider, Some(count)));
            }
            Json(json!({"items": items})).into_response()
        }
        Err(error) => {
            tracing::error!("list user federation providers failed: {error}");
            internal_error()
        }
    }
}

pub async fn create(
    State(state): State<AppState>,
    auth: AdminAuth,
    Json(request): Json<ProviderRequest>,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    if let Some(response) = realm_or_forbidden(&auth, request.realm_id) {
        return response;
    }
    if let Err(response) = validate_public_config(&request.config) {
        return response;
    }
    let secret = match request.gateway_secret.filter(|value| !value.is_empty()) {
        Some(value) => match state.encrypt_sensitive_value(value.as_bytes()) {
            Ok(value) => value,
            Err(_) => return internal_error(),
        },
        None => return invalid("gateway_secret is required"),
    };
    let now = Utc::now();
    let provider = UserFederationProvider {
        id: generate_uuid_v7(),
        realm_id: request.realm_id,
        name: request.name,
        provider_type: request.provider_type,
        enabled: request.enabled,
        priority: request.priority,
        gateway_url: request.gateway_url,
        gateway_secret: secret,
        config: request.config,
        import_users: request.import_users,
        sync_groups: request.sync_groups,
        last_sync_at: None,
        last_sync_status: None,
        last_sync_error: None,
        created_at: now,
        updated_at: now,
    };
    if let Err(error) = provider.validate() {
        return invalid(&error.to_string());
    }
    let mut conn = match connect(&state).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match UserFederationRepo
        .list_providers(&mut conn, provider.realm_id)
        .await
    {
        Ok(items)
            if items
                .iter()
                .any(|item| item.name.eq_ignore_ascii_case(&provider.name)) =>
        {
            return conflict();
        }
        Ok(_) => {}
        Err(error) => {
            tracing::error!("check user federation provider name failed: {error}");
            return internal_error();
        }
    }
    match UserFederationRepo
        .create_provider(&mut conn, &provider)
        .await
    {
        Ok(()) => (StatusCode::CREATED, Json(provider_json(&provider, Some(0)))).into_response(),
        Err(error) => {
            tracing::error!("create user federation provider failed: {error}");
            internal_error()
        }
    }
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
    Json(request): Json<ProviderRequest>,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut provider = match UserFederationRepo.find_provider(&mut conn, id).await {
        Ok(Some(value)) => value,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(response) = realm_or_forbidden(&auth, provider.realm_id) {
        return response;
    }
    if request.realm_id != provider.realm_id {
        return invalid("realm cannot be changed");
    }
    if let Err(response) = validate_public_config(&request.config) {
        return response;
    }
    provider.name = request.name;
    provider.provider_type = request.provider_type;
    provider.enabled = request.enabled;
    provider.priority = request.priority;
    provider.gateway_url = request.gateway_url;
    provider.config = request.config;
    provider.import_users = request.import_users;
    provider.sync_groups = request.sync_groups;
    if let Some(secret) = request.gateway_secret.filter(|value| !value.is_empty()) {
        provider.gateway_secret = match state.encrypt_sensitive_value(secret.as_bytes()) {
            Ok(value) => value,
            Err(_) => return internal_error(),
        };
    }
    if let Err(error) = provider.validate() {
        return invalid(&error.to_string());
    }
    match UserFederationRepo
        .update_provider(&mut conn, &provider)
        .await
    {
        Ok(()) => Json(provider_json(
            &provider,
            UserFederationRepo.count_links(&mut conn, id).await.ok(),
        ))
        .into_response(),
        Err(error) => {
            tracing::error!("update user federation provider failed: {error}");
            internal_error()
        }
    }
}

pub async fn delete_provider(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let provider = match UserFederationRepo.find_provider(&mut conn, id).await {
        Ok(Some(value)) => value,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(response) = realm_or_forbidden(&auth, provider.realm_id) {
        return response;
    }
    match UserFederationRepo.delete_provider(&mut conn, id).await {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(_) => internal_error(),
    }
}

pub async fn test_connection(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let provider = match UserFederationRepo.find_provider(&mut conn, id).await {
        Ok(Some(value)) => value,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(response) = realm_or_forbidden(&auth, provider.realm_id) {
        return response;
    }
    match oidc_oidc::federation::test_provider(&state.oidc_state(), &provider).await {
        Ok(result) if result.ok => {
            Json(json!({"ok": true, "message": result.message})).into_response()
        }
        Ok(result) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"ok": false, "error": result.message})),
        )
            .into_response(),
        Err(error) => {
            tracing::warn!("user federation connection test failed: {error}");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"ok": false, "error": "connection failed"})),
            )
                .into_response()
        }
    }
}

pub async fn sync(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(response) = admin_or_forbidden(&auth) {
        return response;
    }
    let mut conn = match connect(&state).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let provider = match UserFederationRepo.find_provider(&mut conn, id).await {
        Ok(Some(value)) => value,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    if let Some(response) = realm_or_forbidden(&auth, provider.realm_id) {
        return response;
    }
    if !provider.import_users {
        return invalid("user import is disabled for this provider");
    }
    let oidc_state = state.oidc_state();
    let mut cursor = None;
    let mut imported = 0usize;
    for _ in 0..100 {
        let page = match oidc_oidc::federation::list_gateway_users(
            &oidc_state,
            &provider,
            cursor.as_deref(),
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                let safe = "gateway synchronization failed";
                let _ = UserFederationRepo
                    .record_sync(&mut conn, id, "failed", Some(safe))
                    .await;
                tracing::warn!("user federation synchronization failed: {error}");
                return (StatusCode::BAD_GATEWAY, Json(json!({"error": safe}))).into_response();
            }
        };
        for user in page.users {
            if let Err(error) =
                oidc_oidc::federation::import_user(&mut conn, &provider, &user, false).await
            {
                let safe = "directory returned a user that could not be imported";
                let _ = UserFederationRepo
                    .record_sync(&mut conn, id, "failed", Some(safe))
                    .await;
                tracing::warn!("user federation import failed: {error}");
                return (StatusCode::BAD_GATEWAY, Json(json!({"error": safe}))).into_response();
            }
            imported += 1;
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    if cursor.is_some() {
        let _ = UserFederationRepo
            .record_sync(
                &mut conn,
                id,
                "failed",
                Some("gateway pagination limit exceeded"),
            )
            .await;
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "gateway pagination limit exceeded"})),
        )
            .into_response();
    }
    if UserFederationRepo
        .record_sync(&mut conn, id, "success", None)
        .await
        .is_err()
    {
        return internal_error();
    }
    Json(json!({"synced": imported})).into_response()
}

fn invalid(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": message}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_config_rejects_nested_secrets() {
        assert!(validate_public_config(&json!({"search": {"bind_password": "unsafe"}})).is_err());
        assert!(validate_public_config(&json!({"base_dn": "dc=example,dc=com"})).is_ok());
    }
}
