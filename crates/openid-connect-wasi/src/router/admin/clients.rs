use axum::Json;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use oidc_core::models::ClientType;
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7};
use oidc_repository::repositories::client_repo::ClientRepo;

use crate::middleware::admin_auth::AdminAuth;
use crate::router::admin::{
    admin_or_forbidden, bad_request, conflict, connect, internal_error, not_found,
};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ListQuery {
    realm_id: Option<Uuid>,
    search: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_offset")]
    offset: i64,
}

fn default_limit() -> i64 {
    20
}
fn default_offset() -> i64 {
    0
}

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let clients = match ClientRepo
        .list(
            &mut conn,
            query.realm_id,
            query.search.as_deref(),
            query.limit,
            query.offset,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("list clients error: {e}");
            return internal_error();
        }
    };
    let total = ClientRepo
        .count(&mut conn, query.realm_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to count clients: {e}");
            0
        });
    let rows: Vec<Value> = clients.into_iter().map(|c| json!({
        "id": c.id.to_string(),
        "realm_id": c.realm_id.to_string(),
        "client_id": c.client_id,
        "client_type": match c.client_type { ClientType::Confidential => "confidential", ClientType::Public => "public" },
        "name": c.name,
        "redirect_uris": c.redirect_uris,
        "allowed_scopes": c.allowed_scopes,
        "allowed_grant_types": c.allowed_grant_types,
        "pkce_required": c.pkce_required,
        "enabled": c.enabled,
        "subject_type": c.subject_type,
        "sector_identifier_uri": c.sector_identifier_uri,
        "token_endpoint_auth_method": c.token_endpoint_auth_method,
        "jwks_uri": c.jwks_uri,
        "request_uris": c.request_uris,
        "frontchannel_logout_uri": c.frontchannel_logout_uri,
        "frontchannel_logout_session_required": c.frontchannel_logout_session_required,
        "backchannel_logout_uri": c.backchannel_logout_uri,
        "backchannel_logout_session_required": c.backchannel_logout_session_required,
        "post_logout_redirect_uris": c.post_logout_redirect_uris,
        "response_modes": c.response_modes,
        "id_token_encrypted_response_alg": c.id_token_encrypted_response_alg,
        "id_token_encrypted_response_enc": c.id_token_encrypted_response_enc,
        "request_object_encryption_alg": c.request_object_encryption_alg,
        "request_object_encryption_enc": c.request_object_encryption_enc,
    })).collect();
    Json(json!({"items": rows, "total": total})).into_response()
}

pub async fn get(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match ClientRepo.find_by_id(&mut conn, id).await {
        Ok(Some(c)) => Json(json!({
            "id": c.id.to_string(),
            "realm_id": c.realm_id.to_string(),
            "client_id": c.client_id,
            "client_type": match c.client_type { ClientType::Confidential => "confidential", ClientType::Public => "public" },
            "name": c.name,
            "redirect_uris": c.redirect_uris,
            "allowed_scopes": c.allowed_scopes,
            "allowed_grant_types": c.allowed_grant_types,
            "pkce_required": c.pkce_required,
            "enabled": c.enabled,
            "subject_type": c.subject_type,
            "sector_identifier_uri": c.sector_identifier_uri,
            "token_endpoint_auth_method": c.token_endpoint_auth_method,
            "jwks_uri": c.jwks_uri,
            "request_uris": c.request_uris,
            "frontchannel_logout_uri": c.frontchannel_logout_uri,
            "frontchannel_logout_session_required": c.frontchannel_logout_session_required,
            "backchannel_logout_uri": c.backchannel_logout_uri,
            "backchannel_logout_session_required": c.backchannel_logout_session_required,
            "post_logout_redirect_uris": c.post_logout_redirect_uris,
            "response_modes": c.response_modes,
            "id_token_encrypted_response_alg": c.id_token_encrypted_response_alg,
            "id_token_encrypted_response_enc": c.id_token_encrypted_response_enc,
            "request_object_encryption_alg": c.request_object_encryption_alg,
            "request_object_encryption_enc": c.request_object_encryption_enc,
        })).into_response(),
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!("get client error: {e}");
            internal_error()
        }
    }
}

#[derive(Deserialize)]
pub struct CreateRequest {
    realm_id: Uuid,
    client_id: String,
    client_type: Option<String>,
    client_secret: Option<String>,
    name: String,
    redirect_uris: Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
    allowed_grant_types: Option<Vec<String>>,
    pkce_required: Option<bool>,
    enabled: Option<bool>,
    subject_type: Option<String>,
    sector_identifier_uri: Option<String>,
    token_endpoint_auth_method: Option<String>,
    jwks_uri: Option<String>,
    jwks: Option<Value>,
    request_uris: Option<Vec<String>>,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: Option<bool>,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: Option<bool>,
    post_logout_redirect_uris: Option<Vec<String>>,
    response_modes: Option<Vec<String>>,
    id_token_encrypted_response_alg: Option<String>,
    id_token_encrypted_response_enc: Option<String>,
    id_token_encryption_key_pem: Option<String>,
    request_object_encryption_alg: Option<String>,
    request_object_encryption_enc: Option<String>,
    request_object_encryption_key_pem: Option<String>,
}

pub async fn create(State(state): State<AppState>, auth: AdminAuth, body: String) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: CreateRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match ClientRepo
        .find_by_client_id(&mut conn, &req.client_id)
        .await
    {
        Ok(Some(_)) => return conflict(),
        Ok(None) => {}
        Err(e) => {
            tracing::error!("create client duplicate check error: {e}");
            return internal_error();
        }
    }
    let client_type = match req.client_type.as_deref() {
        Some("public") => ClientType::Public,
        _ => ClientType::Confidential,
    };
    let (client_secret_hash, plain_secret) = match client_type {
        ClientType::Confidential => {
            let plain = req
                .client_secret
                .unwrap_or_else(|| generate_opaque_token().unwrap_or_default());
            let hash = match state.hasher.hash(&plain) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("create client hash error: {e}");
                    return internal_error();
                }
            };
            (Some(hash), Some(plain))
        }
        ClientType::Public => (None, None),
    };
    let id = generate_uuid_v7();
    let redirect_uris = req.redirect_uris.unwrap_or_default();
    let allowed_scopes = req
        .allowed_scopes
        .unwrap_or_else(|| vec!["openid".to_string()]);
    let allowed_grant_types = req
        .allowed_grant_types
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);
    let pkce_required = req.pkce_required.unwrap_or(true);
    let enabled = req.enabled.unwrap_or(true);
    let client = oidc_core::models::Client {
        id,
        realm_id: req.realm_id,
        client_id: req.client_id,
        client_type,
        client_secret_hash,
        name: req.name,
        redirect_uris,
        allowed_scopes,
        allowed_grant_types,
        pkce_required,
        enabled,
        deleted_at: None,
        token_endpoint_auth_method: req.token_endpoint_auth_method.unwrap_or_else(|| {
            match client_type {
                ClientType::Confidential => "client_secret_basic".into(),
                ClientType::Public => "none".into(),
            }
        }),
        jwks_uri: req.jwks_uri,
        jwks: req.jwks,
        request_uris: req.request_uris.unwrap_or_default(),
        client_secret_encrypted: None,
        frontchannel_logout_uri: req.frontchannel_logout_uri,
        frontchannel_logout_session_required: req
            .frontchannel_logout_session_required
            .unwrap_or(false),
        backchannel_logout_uri: req.backchannel_logout_uri,
        backchannel_logout_session_required: req
            .backchannel_logout_session_required
            .unwrap_or(false),
        post_logout_redirect_uris: req.post_logout_redirect_uris.unwrap_or_default(),
        subject_type: req.subject_type.unwrap_or_else(|| "public".into()),
        sector_identifier_uri: req.sector_identifier_uri,
        response_modes: req
            .response_modes
            .unwrap_or_else(|| vec!["query".to_string(), "fragment".to_string()]),
        id_token_encrypted_response_alg: req.id_token_encrypted_response_alg,
        id_token_encrypted_response_enc: req.id_token_encrypted_response_enc,
        id_token_encryption_key_encrypted: None,
        id_token_encryption_key_pem: req.id_token_encryption_key_pem,
        request_object_encryption_alg: req.request_object_encryption_alg,
        request_object_encryption_enc: req.request_object_encryption_enc,
        request_object_encryption_key_encrypted: None,
        request_object_encryption_key_pem: req.request_object_encryption_key_pem,
    };
    match ClientRepo.create(&mut conn, &client).await {
        Ok(()) => {}
        Err(e) => {
            tracing::error!("create client error: {e}");
            return internal_error();
        }
    }
    let mut resp = json!({
        "id": client.id.to_string(),
        "realm_id": client.realm_id.to_string(),
        "client_id": client.client_id,
        "client_type": match client.client_type { ClientType::Confidential => "confidential", ClientType::Public => "public" },
        "name": client.name,
        "redirect_uris": client.redirect_uris,
        "allowed_scopes": client.allowed_scopes,
        "allowed_grant_types": client.allowed_grant_types,
        "pkce_required": client.pkce_required,
        "enabled": client.enabled,
        "subject_type": client.subject_type,
        "sector_identifier_uri": client.sector_identifier_uri,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "jwks_uri": client.jwks_uri,
        "request_uris": client.request_uris,
        "frontchannel_logout_uri": client.frontchannel_logout_uri,
        "frontchannel_logout_session_required": client.frontchannel_logout_session_required,
        "backchannel_logout_uri": client.backchannel_logout_uri,
        "backchannel_logout_session_required": client.backchannel_logout_session_required,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "response_modes": client.response_modes,
        "id_token_encrypted_response_alg": client.id_token_encrypted_response_alg,
        "id_token_encrypted_response_enc": client.id_token_encrypted_response_enc,
        "request_object_encryption_alg": client.request_object_encryption_alg,
        "request_object_encryption_enc": client.request_object_encryption_enc,
    });
    if let Some(secret) = plain_secret {
        resp["client_secret"] = json!(secret);
    }
    Json(resp).into_response()
}

#[derive(Deserialize)]
pub struct UpdateRequest {
    name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
    allowed_grant_types: Option<Vec<String>>,
    pkce_required: Option<bool>,
    enabled: Option<bool>,
    subject_type: Option<String>,
    sector_identifier_uri: Option<String>,
    token_endpoint_auth_method: Option<String>,
    jwks_uri: Option<String>,
    jwks: Option<Value>,
    request_uris: Option<Vec<String>>,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: Option<bool>,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: Option<bool>,
    post_logout_redirect_uris: Option<Vec<String>>,
    response_modes: Option<Vec<String>>,
    id_token_encrypted_response_alg: Option<String>,
    id_token_encrypted_response_enc: Option<String>,
    id_token_encryption_key_pem: Option<String>,
    request_object_encryption_alg: Option<String>,
    request_object_encryption_enc: Option<String>,
    request_object_encryption_key_pem: Option<String>,
}

pub async fn update(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
    body: String,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let req: UpdateRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return bad_request(),
    };
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut client = match ClientRepo.find_by_id(&mut conn, id).await {
        Ok(Some(c)) => c,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("update client fetch error: {e}");
            return internal_error();
        }
    };
    if let Some(v) = req.name {
        client.name = v;
    }
    if let Some(v) = req.redirect_uris {
        client.redirect_uris = v;
    }
    if let Some(v) = req.allowed_scopes {
        client.allowed_scopes = v;
    }
    if let Some(v) = req.allowed_grant_types {
        client.allowed_grant_types = v;
    }
    if let Some(v) = req.pkce_required {
        client.pkce_required = v;
    }
    if let Some(v) = req.enabled {
        client.enabled = v;
    }
    if let Some(v) = req.subject_type {
        client.subject_type = v;
    }
    if let Some(v) = req.sector_identifier_uri {
        client.sector_identifier_uri = Some(v);
    }
    if let Some(v) = req.token_endpoint_auth_method {
        client.token_endpoint_auth_method = v;
    }
    if let Some(v) = req.jwks_uri {
        client.jwks_uri = Some(v);
    }
    if let Some(v) = req.jwks {
        client.jwks = Some(v);
    }
    if let Some(v) = req.request_uris {
        client.request_uris = v;
    }
    if let Some(v) = req.frontchannel_logout_uri {
        client.frontchannel_logout_uri = Some(v);
    }
    if let Some(v) = req.frontchannel_logout_session_required {
        client.frontchannel_logout_session_required = v;
    }
    if let Some(v) = req.backchannel_logout_uri {
        client.backchannel_logout_uri = Some(v);
    }
    if let Some(v) = req.backchannel_logout_session_required {
        client.backchannel_logout_session_required = v;
    }
    if let Some(v) = req.post_logout_redirect_uris {
        client.post_logout_redirect_uris = v;
    }
    if let Some(v) = req.response_modes {
        client.response_modes = v;
    }
    if let Some(v) = req.id_token_encrypted_response_alg {
        client.id_token_encrypted_response_alg = Some(v);
    }
    if let Some(v) = req.id_token_encrypted_response_enc {
        client.id_token_encrypted_response_enc = Some(v);
    }
    if let Some(v) = req.id_token_encryption_key_pem {
        client.id_token_encryption_key_pem = Some(v);
    }
    if let Some(v) = req.request_object_encryption_alg {
        client.request_object_encryption_alg = Some(v);
    }
    if let Some(v) = req.request_object_encryption_enc {
        client.request_object_encryption_enc = Some(v);
    }
    if let Some(v) = req.request_object_encryption_key_pem {
        client.request_object_encryption_key_pem = Some(v);
    }
    match ClientRepo.update(&mut conn, &client).await {
        Ok(()) => Json(json!({"updated": true})).into_response(),
        Err(e) => {
            tracing::error!("update client error: {e}");
            internal_error()
        }
    }
}

pub async fn delete(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    auth: AdminAuth,
) -> Response {
    if let Some(r) = admin_or_forbidden(&auth) {
        return r;
    }
    let mut conn = match connect(&state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match ClientRepo.delete(&mut conn, id).await {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => {
            tracing::error!("delete client error: {e}");
            internal_error()
        }
    }
}
