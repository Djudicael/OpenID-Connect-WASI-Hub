//! MLS HTTP endpoints.

use axum::Json;
use serde_json::{json, Value};

/// Create a new MLS group.
pub async fn create_group() -> Json<Value> {
    Json(json!({"id": null, "epoch": 0}))
}

/// Upload a KeyPackage.
pub async fn upload_key_package() -> Json<Value> {
    Json(json!({"id": null}))
}

/// Send a commit to a group.
pub async fn send_commit() -> Json<Value> {
    Json(json!({"epoch": 0, "accepted": true}))
}
