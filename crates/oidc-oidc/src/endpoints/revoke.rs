use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};
use std::collections::HashMap;

use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::with_transaction;

use crate::errors::OidcErrorResponse;
use crate::state::OidcState;
use crate::tokens::JwtTokenService;

/// Token revocation endpoint handler.
/// Requires client authentication. Supports both access tokens and refresh tokens.
pub async fn revoke_handler(
    State(state): State<OidcState>,
    axum::extract::Form(mut params): axum::extract::Form<HashMap<String, String>>,
) -> Result<Json<Value>, OidcErrorResponse> {
    // --- Extract client_secret_basic from Authorization header if present ---
    if let Some(auth_header) = params.get("Authorization") {
        if let Some(credentials) = auth_header.strip_prefix("Basic ") {
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

    let token = params
        .get("token")
        .ok_or_else(|| OidcErrorResponse::invalid_request("Missing token"))?;

    let token_type_hint = params.get("token_type_hint").map(|s| s.as_str());

    let mut conn = state
        .connect()
        .await
        .map_err(|e| OidcErrorResponse::from_internal(e))?;

    with_transaction!(conn, |e| OidcErrorResponse::from_internal(e), {
        // --- Client authentication ---
        let _client = authenticate_client_revoke(&state, &params, &mut conn).await?;

        let token_hash = oidc_core::utils::sha2_256_hex(token);

        // Try refresh token first if hinted, otherwise try access token
        if token_type_hint == Some("refresh_token") {
            if let Ok(Some(session)) = SessionRepo
                .find_by_refresh_token_hash(&mut conn, &token_hash)
                .await
            {
                let _ = SessionRepo.revoke(&mut conn, session.id).await;
                return Ok(Json(json!({})));
            }
        }

        // Try as access token
        if let Ok(Some(session)) = SessionRepo
            .find_by_access_token_hash(&mut conn, &token_hash)
            .await
        {
            let _ = SessionRepo.revoke(&mut conn, session.id).await;
            return Ok(Json(json!({})));
        }

        // Also try as refresh token if not already tried
        if token_type_hint != Some("refresh_token") {
            if let Ok(Some(session)) = SessionRepo
                .find_by_refresh_token_hash(&mut conn, &token_hash)
                .await
            {
                let _ = SessionRepo.revoke(&mut conn, session.id).await;
                return Ok(Json(json!({})));
            }
        }

        // Per RFC 7009, return 200 even if token not found
        Ok(Json(json!({})))
    })
}

/// Authenticate the client at the revocation endpoint.
async fn authenticate_client_revoke(
    state: &OidcState,
    params: &HashMap<String, String>,
    conn: &mut oidc_repository::Connection,
) -> Result<oidc_core::models::Client, OidcErrorResponse> {
    if let Some(assertion) = params.get("client_assertion") {
        let assertion_type = params
            .get("client_assertion_type")
            .ok_or_else(|| OidcErrorResponse::invalid_client("Missing client_assertion_type"))?;
        if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            return Err(OidcErrorResponse::invalid_client(
                "Unsupported client_assertion_type",
            ));
        }

        let (_, claims, _, _) = JwtTokenService::parse_client_assertion_unverified(assertion)
            .map_err(|e| {
                OidcErrorResponse::invalid_client(format!("Invalid client assertion: {e}"))
            })?;
        let client_id = claims.iss;

        let client = match ClientRepo.find_by_client_id(conn, &client_id).await {
            Ok(Some(c)) if c.enabled => c,
            Ok(Some(_)) => {
                return Err(OidcErrorResponse::invalid_client("Client is disabled"));
            }
            Ok(None) => return Err(OidcErrorResponse::invalid_client("Client not found")),
            Err(e) => return Err(OidcErrorResponse::from_internal(e)),
        };

        match client.token_endpoint_auth_method.as_str() {
            "private_key_jwt" => {
                let jwks = client.jwks.as_ref().ok_or_else(|| {
                    OidcErrorResponse::invalid_client("Client has no JWKS for private_key_jwt")
                })?;

                let token_endpoint = format!("{}/oidc/revoke", state.issuer);
                let now = chrono::Utc::now().timestamp();
                JwtTokenService::verify_client_assertion(
                    assertion,
                    jwks,
                    &token_endpoint,
                    &client_id,
                    now,
                )
                .map_err(|e| {
                    OidcErrorResponse::invalid_client(format!("JWT verification failed: {e}"))
                })?;
            }
            "client_secret_jwt" => {
                let encrypted_secret =
                    client.client_secret_encrypted.as_ref().ok_or_else(|| {
                        OidcErrorResponse::invalid_client(
                            "Client has no encrypted secret for client_secret_jwt",
                        )
                    })?;

                let client_secret_bytes = state
                    .decrypt_client_encryption_key(encrypted_secret)
                    .map_err(|_| {
                        OidcErrorResponse::invalid_client("Failed to decrypt client secret")
                    })?;
                let client_secret = String::from_utf8(client_secret_bytes).map_err(|_| {
                    OidcErrorResponse::invalid_client("Invalid client secret encoding")
                })?;

                let token_endpoint = format!("{}/oidc/revoke", state.issuer);
                let now = chrono::Utc::now().timestamp();
                crate::tokens::jwt_service::verify_client_secret_jwt(
                    assertion,
                    &client_secret,
                    &token_endpoint,
                    &client_id,
                    now,
                )
                .map_err(|e| {
                    OidcErrorResponse::invalid_client(format!("JWT verification failed: {e}"))
                })?;
            }
            _ => {
                return Err(OidcErrorResponse::invalid_client(
                    "Client not configured for JWT assertion authentication",
                ));
            }
        }

        return Ok(client);
    }

    // --- client_secret_basic / client_secret_post ---
    let client_id = params
        .get("client_id")
        .ok_or_else(|| OidcErrorResponse::invalid_client("Missing client_id"))?;

    let _client_secret = params
        .get("client_secret")
        .ok_or_else(|| OidcErrorResponse::invalid_client("Missing client_secret"))?;

    let client = match ClientRepo.find_by_client_id(conn, client_id).await {
        Ok(Some(c)) if c.enabled => c,
        Ok(Some(_)) => {
            return Err(OidcErrorResponse::invalid_client("Client is disabled"));
        }
        Ok(None) => return Err(OidcErrorResponse::invalid_client("Client not found")),
        Err(e) => return Err(OidcErrorResponse::from_internal(e)),
    };

    if let Some(ref hash) = client.client_secret_hash {
        if !state.hasher.verify(_client_secret, hash).unwrap_or(false) {
            return Err(OidcErrorResponse::invalid_client(
                "Invalid client credentials",
            ));
        }
    } else {
        return Err(OidcErrorResponse::invalid_client(
            "Public clients cannot revoke tokens",
        ));
    }

    Ok(client)
}
