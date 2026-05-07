use axum::Json;
use serde_json::{json, Value};

/// Token endpoint handler.
pub async fn token_handler() -> Json<Value> {
    // TODO: implement token issuance
    Json(json!({
        "error": "unsupported_grant_type"
    }))
}
