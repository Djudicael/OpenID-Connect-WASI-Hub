//! MLS routes.

use axum::routing::{get, post};
use axum::Router;
use axum::extract::State;

use crate::state::AppState;

/// Build the MLS sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/mls/groups", post(|State(state): State<AppState>, json| async move {
            oidc_mls::endpoints::create_group(State(state), json).await
        }))
        .route("/api/mls/groups/{id}/join", post(|State(state): State<AppState>, path, json| async move {
            oidc_mls::endpoints::join_group(State(state), path, json).await
        }))
        .route("/api/mls/groups/{id}/commits", post(|State(state): State<AppState>, path, json| async move {
            oidc_mls::endpoints::send_commit(State(state), path, json).await
        }))
        .route("/api/mls/groups/{id}", get(|State(state): State<AppState>, path| async move {
            oidc_mls::endpoints::welcome(State(state), path).await
        }))
        .route("/api/mls/key-packages", post(|State(state): State<AppState>, json| async move {
            oidc_mls::endpoints::upload_key_package(State(state), json).await
        }))
}
