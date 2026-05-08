//! OIDC protocol routes.

use axum::extract::{Form, Query, State};
use axum::routing::{get, post};
use axum::Router;
use std::collections::HashMap;

use crate::state::AppState;

/// Build the OIDC sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(|State(state): State<AppState>| async move {
            oidc_oidc::discovery_handler(state.oidc_state()).await
        }))
        .route("/oidc/jwks", get(|State(state): State<AppState>| async move {
            oidc_oidc::endpoints::jwks::jwks_handler(state.oidc_state())
                .await
                .unwrap()
        }))
        .route("/oidc/authorize", get(|State(state): State<AppState>, Query(params): Query<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::authorize::authorize_handler(state.oidc_state(), Query(params)).await
        }))
        .route("/oidc/token", post(|State(state): State<AppState>, Form(params): Form<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::token::token_handler(state.oidc_state(), params)
                .await
                .unwrap_or_else(|e| axum::Json(serde_json::json!({"error": e.to_string() })))
        }))
        .route("/oidc/userinfo", get(|| async move {
            oidc_oidc::endpoints::userinfo::userinfo_handler().await
        }))
        .route("/oidc/introspect", post(|| async move {
            oidc_oidc::endpoints::introspect::introspect_handler().await
        }))
        .route("/oidc/revoke", post(|| async move {
            oidc_oidc::endpoints::revoke::revoke_handler().await
        }))
}
