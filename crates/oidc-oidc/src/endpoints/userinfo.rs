use axum::Json;
use serde_json::{json, Value};

/// UserInfo endpoint handler.
pub async fn userinfo_handler() -> Json<Value> {
    // TODO: implement userinfo
    Json(json!({
        "error": "invalid_token"
    }))
}
