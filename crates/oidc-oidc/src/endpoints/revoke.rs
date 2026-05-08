use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};
use std::collections::HashMap;

use oidc_repository::repositories::session_repo::SessionRepo;

use crate::state::OidcState;

/// Token revocation endpoint handler.
pub async fn revoke_handler(
    State(state): State<OidcState>,
    axum::extract::Form(params): axum::extract::Form<HashMap<String, String>>,
) -> Json<Value> {
    let token = match params.get("token") {
        Some(t) => t,
        None => return Json(json!({})),
    };

    let access_hash = sha2_256_hex(token);
    let mut conn = match state.connect().await {
        Ok(c) => c,
        Err(_) => return Json(json!({})),
    };

    // Find session by access token hash and revoke it
    if let Ok(Some(session)) = SessionRepo.find_by_access_token_hash(&mut conn, &access_hash).await {
        let _ = SessionRepo.revoke(&mut conn, session.id).await;
    }

    Json(json!({}))
}

fn sha2_256_hex(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
