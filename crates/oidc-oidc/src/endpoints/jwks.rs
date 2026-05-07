use axum::Json;
use serde_json::{json, Value};

/// JWKS endpoint handler.
pub async fn jwks_handler() -> Json<Value> {
    Json(json!({
        "keys": []
    }))
}
