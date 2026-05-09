use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};
use std::collections::HashMap;

use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;

use crate::state::OidcState;

/// Token revocation endpoint handler.
/// Requires client authentication. Supports both access tokens and refresh tokens.
pub async fn revoke_handler(
    State(state): State<OidcState>,
    axum::extract::Form(params): axum::extract::Form<HashMap<String, String>>,
) -> Json<Value> {
    // --- Client authentication ---
    let client_id = match params.get("client_id") {
        Some(id) => id,
        None => return Json(json!({})),
    };

    let client_secret = match params.get("client_secret") {
        Some(s) => s,
        None => return Json(json!({})),
    };

    let token = match params.get("token") {
        Some(t) => t,
        None => return Json(json!({})),
    };

    let token_type_hint = params.get("token_type_hint").map(|s| s.as_str());

    let mut conn = match state.connect().await {
        Ok(c) => c,
        Err(_) => return Json(json!({})),
    };

    // Verify client credentials
    let client = match ClientRepo.find_by_client_id(&mut conn, client_id).await {
        Ok(Some(c)) if c.enabled => c,
        _ => return Json(json!({})),
    };

    if let Some(ref hash) = client.client_secret_hash {
        if !state.hasher.verify(client_secret, hash).unwrap_or(false) {
            return Json(json!({}));
        }
    } else {
        return Json(json!({}));
    }

    let token_hash = oidc_core::utils::sha2_256_hex(token);

    // Try refresh token first if hinted, otherwise try access token
    if token_type_hint == Some("refresh_token") {
        if let Ok(Some(session)) = SessionRepo
            .find_by_refresh_token_hash(&mut conn, &token_hash)
            .await
        {
            let _ = SessionRepo.revoke(&mut conn, session.id).await;
            return Json(json!({}));
        }
    }

    // Try as access token
    if let Ok(Some(session)) = SessionRepo
        .find_by_access_token_hash(&mut conn, &token_hash)
        .await
    {
        let _ = SessionRepo.revoke(&mut conn, session.id).await;
        return Json(json!({}));
    }

    // Also try as refresh token if not already tried
    if token_type_hint != Some("refresh_token") {
        if let Ok(Some(session)) = SessionRepo
            .find_by_refresh_token_hash(&mut conn, &token_hash)
            .await
        {
            let _ = SessionRepo.revoke(&mut conn, session.id).await;
            return Json(json!({}));
        }
    }

    // Per RFC 7009, return 200 even if token not found
    Json(json!({}))
}
