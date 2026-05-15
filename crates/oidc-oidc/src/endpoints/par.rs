//! Pushed Authorization Requests (PAR) endpoint handler.
//!
//! Implements RFC 9126 — pushes authorization request parameters to the
//! authorization server, which stores them and returns a `request_uri`.
//! The client later presents the `request_uri` at the authorize endpoint.

use axum::Json;
use serde_json::{Value, json};
use std::collections::HashMap;

use oidc_core::OidcError;
use oidc_core::models::PushedAuthorizationRequest;
use oidc_core::utils::{generate_opaque_token, generate_uuid_v7};
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::par_repo::ParRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;

use crate::state::OidcState;
use crate::tokens::JwtTokenService;

/// PAR endpoint handler.
///
/// RFC 9126 allows any OAuth2/OIDC authorization request parameter to be
/// pushed. We accept them as a flat form-urlencoded HashMap.
/// Client authentication supports `client_secret_basic` (Authorization
/// header), `client_secret_post` (form body), `private_key_jwt`
/// (client_assertion JWT), and `client_secret_jwt` (client_assertion JWT
/// signed with HMAC) per RFC 7523.
pub async fn par_handler(
    state: OidcState,
    headers: axum::http::HeaderMap,
    mut params: HashMap<String, String>,
) -> Result<Json<Value>, OidcError> {
    // Extract client_secret_basic from Authorization header if present
    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(credentials) = auth_str.strip_prefix("Basic ") {
                use base64::{Engine, engine::general_purpose::STANDARD};
                if let Ok(decoded) = STANDARD.decode(credentials) {
                    if let Ok(cred_str) = String::from_utf8(decoded) {
                        if let Some((client_id, client_secret)) = cred_str.split_once(':') {
                            params
                                .entry("client_id".to_string())
                                .or_insert_with(|| client_id.to_string());
                            params
                                .entry("client_secret".to_string())
                                .or_insert_with(|| client_secret.to_string());
                        }
                    }
                }
            }
        }
    }

    // ── Client authentication ──────────────────────────────────────────
    let client = authenticate_client_par(&state, &params).await?;

    // Resolve realm (needed for the PAR record)
    let realm_id = if client.realm_id.is_nil() {
        // Fallback: try to infer from a realm parameter if present
        if let Some(realm_name) = params.get("realm") {
            let mut conn = state.connect().await?;
            RealmRepo
                .find_by_name(&mut conn, realm_name)
                .await?
                .map(|r| r.id)
                .unwrap_or_else(uuid::Uuid::nil)
        } else {
            uuid::Uuid::nil()
        }
    } else {
        client.realm_id
    };

    // Store all pushed parameters as JSON (excluding client_secret / client_assertion for security)
    let mut stored_params = params.clone();
    stored_params.remove("client_secret");
    stored_params.remove("client_assertion");
    stored_params.remove("client_assertion_type");

    let request_uri_token = generate_opaque_token()?;
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(90);

    let par = PushedAuthorizationRequest {
        id: generate_uuid_v7(),
        client_id: client.id,
        realm_id,
        request_uri_token: request_uri_token.clone(),
        request_params: serde_json::to_value(&stored_params)
            .map_err(|e| OidcError::Internal(format!("JSON serialization failed: {e}")))?,
        expires_at,
        used: false,
        created_at: chrono::Utc::now(),
    };

    let mut conn = state.connect().await?;
    ParRepo.create(&mut conn, &par).await?;

    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", request_uri_token);

    Ok(Json(json!({
        "request_uri": request_uri,
        "expires_in": 90,
    })))
}

/// Authenticate the client at the PAR endpoint.
async fn authenticate_client_par(
    state: &OidcState,
    params: &HashMap<String, String>,
) -> Result<oidc_core::models::Client, OidcError> {
    if let Some(assertion) = params.get("client_assertion") {
        let assertion_type = params
            .get("client_assertion_type")
            .ok_or(OidcError::InvalidClient)?;
        if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            return Err(OidcError::InvalidClient);
        }

        let (_, claims, _, _) = JwtTokenService::parse_client_assertion_unverified(assertion)?;
        let client_id = claims.iss;

        let mut conn = state.connect().await?;
        let client = ClientRepo
            .find_by_client_id(&mut conn, &client_id)
            .await?
            .ok_or(OidcError::InvalidClient)?;

        if !client.enabled {
            return Err(OidcError::InvalidClient);
        }

        match client.token_endpoint_auth_method.as_str() {
            "private_key_jwt" => {
                let jwks = client.jwks.as_ref().ok_or_else(|| {
                    OidcError::InvalidClientAssertion("client has no jwks".into())
                })?;

                let token_endpoint = format!("{}/oidc/par", state.issuer);
                let now = chrono::Utc::now().timestamp();
                JwtTokenService::verify_client_assertion(
                    assertion,
                    jwks,
                    &token_endpoint,
                    &client_id,
                    now,
                )?;
            }
            "client_secret_jwt" => {
                let encrypted_secret =
                    client.client_secret_encrypted.as_ref().ok_or_else(|| {
                        OidcError::InvalidClientAssertion(
                            "client has no encrypted secret for client_secret_jwt".into(),
                        )
                    })?;

                let client_secret_bytes = state
                    .decrypt_client_encryption_key(encrypted_secret)
                    .map_err(|_| {
                        OidcError::InvalidClientAssertion("failed to decrypt client secret".into())
                    })?;
                let client_secret = String::from_utf8(client_secret_bytes).map_err(|_| {
                    OidcError::InvalidClientAssertion("invalid client secret encoding".into())
                })?;

                let token_endpoint = format!("{}/oidc/par", state.issuer);
                let now = chrono::Utc::now().timestamp();
                crate::tokens::jwt_service::verify_client_secret_jwt(
                    assertion,
                    &client_secret,
                    &token_endpoint,
                    &client_id,
                    now,
                )?;
            }
            _ => {
                return Err(OidcError::InvalidClient);
            }
        }

        return Ok(client);
    }

    // --- client_secret_basic / client_secret_post ---
    let client_id = params
        .get("client_id")
        .ok_or(OidcError::InvalidClient)?
        .clone();
    let client_secret = params.get("client_secret").cloned();

    let mut conn = state.connect().await?;
    let client = ClientRepo
        .find_by_client_id(&mut conn, &client_id)
        .await?
        .ok_or(OidcError::InvalidClient)?;

    if !client.enabled {
        return Err(OidcError::InvalidClient);
    }

    if let Some(ref hash) = client.client_secret_hash {
        let secret = client_secret.as_ref().ok_or(OidcError::InvalidClient)?;
        if !state.hasher.verify(secret, hash)? {
            return Err(OidcError::InvalidClient);
        }
    }

    Ok(client)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_request_uri_format() {
        let token = oidc_core::utils::generate_opaque_token().unwrap();
        let uri = format!("urn:ietf:params:oauth:request_uri:{}", token);
        assert!(uri.starts_with("urn:ietf:params:oauth:request_uri:"));
        assert!(!token.is_empty());
    }
}
