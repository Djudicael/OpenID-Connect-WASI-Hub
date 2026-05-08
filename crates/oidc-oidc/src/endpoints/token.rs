use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use oidc_core::models::Session;
use oidc_core::traits::token_service::TokenService;
use oidc_core::utils::{generate_uuid_v7, verify_s256};
use oidc_core::OidcError;
use oidc_repository::repositories::auth_code_repo::AuthCodeRepo;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;

use crate::state::OidcState;

/// Token endpoint handler.
pub async fn token_handler(
    state: OidcState,
    params: HashMap<String, String>,
) -> Result<Json<Value>, OidcError> {
    let grant_type = params
        .get("grant_type")
        .ok_or(OidcError::InvalidRequest)?
        .as_str();

    match grant_type {
        "authorization_code" => handle_authorization_code(state, params).await,
        "client_credentials" => handle_client_credentials(state, params).await,
        _ => Err(OidcError::UnsupportedGrantType),
    }
}

async fn handle_authorization_code(
    state: OidcState,
    params: HashMap<String, String>,
) -> Result<Json<Value>, OidcError> {
    let code = params.get("code").ok_or(OidcError::InvalidRequest)?;
    let redirect_uri = params.get("redirect_uri").ok_or(OidcError::InvalidRequest)?;
    let client_id = params.get("client_id").ok_or(OidcError::InvalidClient)?;
    let code_verifier = params.get("code_verifier").ok_or(OidcError::InvalidRequest)?;

    let mut conn = state.connect().await?;

    // --- Look up and validate the authorization code ---
    let auth_code = AuthCodeRepo
        .find_by_code(&mut conn, code)
        .await?
        .ok_or(OidcError::InvalidRequest)?;

    if auth_code.used {
        return Err(OidcError::InvalidRequest);
    }

    if auth_code.redirect_uri != *redirect_uri {
        return Err(OidcError::InvalidRequest);
    }

    // --- Validate client ---
    let client = ClientRepo
        .find_by_client_id(&mut conn, client_id)
        .await?
        .ok_or(OidcError::InvalidClient)?;

    if client.id != auth_code.client_id {
        return Err(OidcError::InvalidClient);
    }

    if !client.enabled {
        return Err(OidcError::InvalidClient);
    }

    // --- PKCE verification ---
    if auth_code.code_challenge_method == "S256" {
        if !verify_s256(code_verifier, &auth_code.code_challenge) {
            return Err(OidcError::InvalidRequest);
        }
    } else {
        // plain: direct comparison
        if auth_code.code_challenge != *code_verifier {
            return Err(OidcError::InvalidRequest);
        }
    }

    // --- Mark code as used ---
    AuthCodeRepo.mark_used(&mut conn, auth_code.id).await?;

    // --- Issue tokens ---
    let subject = auth_code.user_id.to_string();
    let audience = client.client_id.clone();
    let scopes = auth_code.scope.clone();

    let access_token = state
        .token_service
        .issue_access_token(&subject, &audience, &scopes)
        .await?;
    let id_token = state
        .token_service
        .issue_id_token(&subject, &audience, None)
        .await?;

    // --- Store session ---
    let access_hash = sha2_256_hex(&access_token);
    let refresh_hash = Some(sha2_256_hex(&format!("{}refresh", access_token)));

    let session = Session {
        id: generate_uuid_v7(),
        user_id: auth_code.user_id,
        realm_id: auth_code.realm_id,
        client_id: client.id,
        grant_type: "authorization_code".to_string(),
        access_token_hash: access_hash,
        refresh_token_hash: refresh_hash,
        id_token_jti: None,
        scope: scopes.clone(),
        revoked: false,
    };

    SessionRepo.create(&mut conn, &session).await?;

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 900,
        "refresh_token": format!("{}refresh", access_token),
        "id_token": id_token,
        "scope": scopes.join(" "),
    })))
}

async fn handle_client_credentials(
    state: OidcState,
    params: HashMap<String, String>,
) -> Result<Json<Value>, OidcError> {
    let client_id = params.get("client_id").ok_or(OidcError::InvalidClient)?;
    let client_secret = params.get("client_secret").ok_or(OidcError::InvalidClient)?;

    let mut conn = state.connect().await?;
    let client = ClientRepo
        .find_by_client_id(&mut conn, client_id)
        .await?
        .ok_or(OidcError::InvalidClient)?;

    if !client.enabled {
        return Err(OidcError::InvalidClient);
    }

    match client.client_secret_hash {
        Some(ref hash) => {
            if !state.hasher.verify(client_secret, hash)? {
                return Err(OidcError::InvalidClient);
            }
        }
        None => return Err(OidcError::InvalidClient),
    }

    let access_token = state
        .token_service
        .issue_access_token(&client.client_id, &client.client_id, &client.allowed_scopes)
        .await?;

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 900,
        "scope": client.allowed_scopes.join(" "),
    })))
}

fn sha2_256_hex(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
