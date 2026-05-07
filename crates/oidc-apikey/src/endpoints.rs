//! API key HTTP endpoints.

use axum::Json;
use serde_json::{json, Value};

/// List API keys.
pub async fn list_keys() -> Json<Value> {
    Json(json!({"items": [], "total": 0}))
}

/// Create a new API key.
pub async fn create_key() -> Json<Value> {
    // TODO: implement creation
    Json(json!({"id": null, "raw_key": null}))
}

/// Revoke an API key.
pub async fn revoke_key() -> Json<Value> {
    Json(json!({}))
}
