use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};
use std::collections::HashMap;

use oidc_core::traits::TokenService;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;
use oidc_repository::with_transaction;

use crate::errors::OidcErrorResponse;
use crate::state::OidcState;

/// Token introspection endpoint handler.
/// Requires client authentication (client_secret_basic or client_secret_post).
/// Per RFC 7662, returns `active`, `sub`, `client_id`, `scope`, `token_type`,
/// `exp`, and `iat` from the verified JWT claims.
pub async fn introspect_handler(
    State(state): State<OidcState>,
    axum::extract::Form(params): axum::extract::Form<HashMap<String, String>>,
) -> Result<Json<Value>, OidcErrorResponse> {
    // --- Client authentication (required per RFC 7662 §2.1) ---
    let client_id = params
        .get("client_id")
        .ok_or_else(|| OidcErrorResponse::invalid_client("Missing client_id"))?;

    let _client_secret = params
        .get("client_secret")
        .ok_or_else(|| OidcErrorResponse::invalid_client("Missing client_secret"))?;

    let token = params
        .get("token")
        .ok_or_else(|| OidcErrorResponse::invalid_request("Missing token"))?;

    let mut conn = state
        .connect()
        .await
        .map_err(|e| OidcErrorResponse::from_internal(e))?;

    let result = with_transaction!(conn, |e| OidcErrorResponse::from_internal(e), {
        // Verify client credentials
        let client = match ClientRepo.find_by_client_id(&mut conn, client_id).await {
            Ok(Some(c)) if c.enabled => c,
            Ok(Some(_)) => {
                return Err(OidcErrorResponse::invalid_client("Client is disabled"));
            }
            Ok(None) => {
                return Err(OidcErrorResponse::invalid_client("Client not found"));
            }
            Err(e) => return Err(OidcErrorResponse::from_internal(e)),
        };

        // Verify client secret for confidential clients
        if let Some(ref hash) = client.client_secret_hash {
            if !state.hasher.verify(_client_secret, hash).unwrap_or(false) {
                return Err(OidcErrorResponse::invalid_client(
                    "Invalid client credentials",
                ));
            }
        } else {
            return Err(OidcErrorResponse::invalid_client(
                "Public clients cannot introspect",
            ));
        }

        // Verify the token signature, expiry, and extract full claims
        let claims = match state
            .token_service
            .verify_access_token_with_claims(token)
            .await
        {
            Ok(c) => c,
            Err(_) => return Ok(Json(json!({"active": false}))),
        };

        // Look up the session by access token hash to confirm it is not revoked
        let access_hash = oidc_core::utils::sha2_256_hex(token);
        let _session = match SessionRepo
            .find_by_access_token_hash(&mut conn, &access_hash)
            .await
        {
            Ok(Some(s)) if !s.revoked => s,
            Ok(Some(_)) => return Ok(Json(json!({"active": false}))),
            Ok(None) => return Ok(Json(json!({"active": false}))),
            Err(e) => return Err(OidcErrorResponse::from_internal(e)),
        };

        // Look up the user by sub to get the email for the `username` field
        let username = match uuid::Uuid::parse_str(&claims.sub) {
            Ok(user_id) => UserRepo
                .find_by_id(&mut conn, user_id)
                .await
                .ok()
                .flatten()
                .and_then(|u| u.username.clone().or(Some(u.email.clone()))),
            Err(_) => None,
        };

        Ok(Json(json!({
            "active": true,
            "sub": claims.sub,
            "client_id": claims.aud,
            "aud": claims.aud,
            "scope": claims.scope,
            "token_type": "Bearer",
            "exp": claims.exp,
            "iat": claims.iat,
            "username": username,
        })))
    });

    result
}
