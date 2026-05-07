use axum::Json;
use serde_json::{json, Value};

/// Token revocation endpoint handler.
pub async fn revoke_handler() -> Json<Value> {
    // TODO: implement revocation
    Json(json!({}))
}
