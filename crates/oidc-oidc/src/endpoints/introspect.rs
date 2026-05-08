use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};
use std::collections::HashMap;

use oidc_core::traits::TokenService;
use oidc_repository::repositories::session_repo::SessionRepo;

use crate::state::OidcState;

/// Token introspection endpoint handler.
pub async fn introspect_handler(
    State(state): State<OidcState>,
    axum::extract::Form(params): axum::extract::Form<HashMap<String, String>>,
) -> Json<Value> {
    let token = match params.get("token") {
        Some(t) => t,
        None => return Json(json!({"active": false})),
    };

    // Verify the token signature and expiry
    let subject = match state.token_service.verify_access_token(token).await {
        Ok(sub) => sub,
        Err(_) => return Json(json!({"active": false})),
    };

    // Look up the session by access token hash
    let access_hash = sha2_256_hex(token);
    let mut conn = match state.connect().await {
        Ok(c) => c,
        Err(_) => return Json(json!({"active": false})),
    };

    let session = match SessionRepo.find_by_access_token_hash(&mut conn, &access_hash).await {
        Ok(Some(s)) if !s.revoked => s,
        _ => return Json(json!({"active": false})),
    };

    Json(json!({
        "active": true,
        "sub": subject,
        "client_id": session.client_id.to_string(),
        "scope": session.scope.join(" "),
        "token_type": "Bearer",
    }))
}

fn sha2_256_hex(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
