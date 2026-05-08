use axum::Json;
use base64::Engine;
use serde_json::{Value, json};
use uuid::Uuid;

use oidc_core::OidcError;
use oidc_core::models::{Client, ClientType};
use oidc_repository::repositories::client_repo::ClientRepo;

use crate::state::OidcState;

/// Request body for dynamic client registration.
#[derive(Debug, serde::Deserialize)]
pub struct RegisterClientRequest {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scope: String,
    pub token_endpoint_auth_method: String,
}

/// Register a new OAuth2/OIDC client.
pub async fn register_handler(
    state: OidcState,
    Json(req): Json<RegisterClientRequest>,
) -> Result<Json<Value>, OidcError> {
    let client_id = format!("client_{}", Uuid::new_v4().to_string().replace("-", ""));

    let (client_type, client_secret, client_secret_hash) =
        match req.token_endpoint_auth_method.as_str() {
            "client_secret_basic" | "client_secret_post" => {
                let mut secret_bytes = [0u8; 32];
                getrandom::fill(&mut secret_bytes)
                    .map_err(|e| OidcError::Internal(e.to_string()))?;
                let secret = base64::engine::general_purpose::STANDARD.encode(&secret_bytes);
                let hash = state.hasher.hash(&secret)?;
                (ClientType::Confidential, Some(secret), Some(hash))
            }
            _ => (ClientType::Public, None, None),
        };

    let mut conn = state.connect().await?;
    let client = Client {
        id: Uuid::new_v4(),
        realm_id: Uuid::nil(),
        client_id: client_id.clone(),
        client_type,
        client_secret_hash,
        name: req.client_name,
        redirect_uris: req.redirect_uris,
        allowed_scopes: req
            .scope
            .split_whitespace()
            .map(|s| s.to_string())
            .collect(),
        allowed_grant_types: req.grant_types,
        pkce_required: true,
        enabled: true,
    };

    ClientRepo.create(&mut conn, &client).await?;

    let mut response = json!({
        "client_id": client_id,
        "client_name": client.name,
        "redirect_uris": client.redirect_uris,
        "grant_types": client.allowed_grant_types,
        "scope": client.allowed_scopes.join(" "),
        "token_endpoint_auth_method": req.token_endpoint_auth_method,
    });

    if let Some(secret) = client_secret {
        response["client_secret"] = json!(secret);
    }

    Ok(Json(response))
}
