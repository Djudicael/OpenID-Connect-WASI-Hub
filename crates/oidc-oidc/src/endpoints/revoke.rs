use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};
use std::collections::HashMap;

use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;

use crate::errors::OidcErrorResponse;
use crate::state::OidcState;

/// Token revocation endpoint handler.
/// Requires client authentication. Supports both access tokens and refresh tokens.
pub async fn revoke_handler(
    State(state): State<OidcState>,
    axum::extract::Form(params): axum::extract::Form<HashMap<String, String>>,
) -> Result<Json<Value>, OidcErrorResponse> {
    // --- Client authentication (required per RFC 7009 §2.1) ---
    let client_id = params
        .get("client_id")
        .ok_or_else(|| OidcErrorResponse::invalid_client("Missing client_id"))?;

    let _client_secret = params
        .get("client_secret")
        .ok_or_else(|| OidcErrorResponse::invalid_client("Missing client_secret"))?;

    let token = params
        .get("token")
        .ok_or_else(|| OidcErrorResponse::invalid_request("Missing token"))?;

    let token_type_hint = params.get("token_type_hint").map(|s| s.as_str());

    let mut conn = state
        .connect()
        .await
        .map_err(|e| OidcErrorResponse::from_internal(e))?;

    // Verify client credentials
    let client = match ClientRepo.find_by_client_id(&mut conn, client_id).await {
        Ok(Some(c)) if c.enabled => c,
        Ok(Some(_)) => return Err(OidcErrorResponse::invalid_client("Client is disabled")),
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
}
