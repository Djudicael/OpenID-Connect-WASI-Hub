use axum::Json;
use serde_json::{json, Value};

/// Token introspection endpoint handler.
pub async fn introspect_handler() -> Json<Value> {
    // TODO: implement introspection
    Json(json!({
        "active": false
    }))
}
