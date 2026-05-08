//! API key routes.

use axum::Router;
use axum::extract::State;
use axum::routing::{delete, get, post};

use crate::state::AppState;

/// Build the API key sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/keys",
            get(|State(state): State<AppState>, query| async move {
                oidc_apikey::endpoints::list_keys(State(state), query).await
            }),
        )
        .route(
            "/api/keys",
            post(|State(state): State<AppState>, json| async move {
                oidc_apikey::endpoints::create_key(State(state), json).await
            }),
        )
        .route(
            "/api/keys/{id}",
            delete(|State(state): State<AppState>, path| async move {
                oidc_apikey::endpoints::revoke_key(State(state), path).await
            }),
        )
}
