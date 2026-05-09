use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};
use std::collections::HashMap;

use oidc_core::traits::TokenService;

use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;

use crate::state::OidcState;

/// Token introspection endpoint handler.
/// Requires client authentication (client_secret_basic or client_secret_post).
/// Per RFC 7662, returns `active`, `sub`, `client_id`, `scope`, `token_type`,
/// `exp`, and `iat` from the verified JWT claims.
pub async fn introspect_handler(
    State(state): State<OidcState>,
    axum::extract::Form(params): axum::extract::Form<HashMap<String, String>>,
) -> Json<Value> {
    // --- Client authentication ---
    let client_id = match params.get("client_id") {
        Some(id) => id,
        None => return Json(json!({"active": false})),
    };

    let client_secret = match params.get("client_secret") {
        Some(s) => s,
        None => return Json(json!({"active": false})),
    };

    let token = match params.get("token") {
        Some(t) => t,
        None => return Json(json!({"active": false})),
    };

    let mut conn = match state.connect().await {
        Ok(c) => c,
        Err(_) => return Json(json!({"active": false})),
    };

    // Verify client credentials
    let client = match ClientRepo.find_by_client_id(&mut conn, client_id).await {
        Ok(Some(c)) if c.enabled => c,
        _ => return Json(json!({"active": false})),
    };

    // Verify client secret for confidential clients
    if let Some(ref hash) = client.client_secret_hash {
        if !state.hasher.verify(client_secret, hash).unwrap_or(false) {
            return Json(json!({"active": false}));
        }
    } else {
        return Json(json!({"active": false}));
    }

    // Verify the token signature, expiry, and extract full claims
    let claims = match state
        .token_service
        .verify_access_token_with_claims(token)
        .await
    {
        Ok(c) => c,
        Err(_) => return Json(json!({"active": false})),
    };

    // Look up the session by access token hash to confirm it is not revoked
    let access_hash = oidc_core::utils::sha2_256_hex(token);
    let _session = match SessionRepo
        .find_by_access_token_hash(&mut conn, &access_hash)
        .await
    {
        Ok(Some(s)) if !s.revoked => s,
        _ => return Json(json!({"active": false})),
    };

    Json(json!({
        "active": true,
        "sub": claims.sub,
        "client_id": claims.aud,
        "scope": claims.scope,
        "token_type": "Bearer",
        "exp": claims.exp,
        "iat": claims.iat,
    }))
}
