//! OIDC protocol routes.

use axum::Json;
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::routing::{get, post};
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
        .route("/oidc/token", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, Form(params): Form<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::token::token_handler(state.oidc_state(), headers, params)
                .await
                .unwrap_or_else(|e| axum::Json(serde_json::json!({"error": e.to_string() })))
        }))
        .route("/oidc/userinfo", get(|State(state): State<AppState>, headers: axum::http::HeaderMap| async move {
            let auth = headers.get(axum::http::header::AUTHORIZATION).cloned();
            oidc_oidc::endpoints::userinfo::userinfo_handler(State(state.oidc_state()), auth).await
                .unwrap_or_else(|_| axum::Json(serde_json::json!({"error": "invalid_token"})))
        }))
        .route("/oidc/introspect", post(|State(state): State<AppState>, form: Form<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::introspect::introspect_handler(State(state.oidc_state()), form).await
        }))
        .route("/oidc/revoke", post(|State(state): State<AppState>, form: Form<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::revoke::revoke_handler(State(state.oidc_state()), form).await
        }))
        .route("/oidc/logout", get(|State(state): State<AppState>, Query(params): Query<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::logout::logout_handler(state.oidc_state(), Query(params)).await
        }))
        .route("/oidc/register", post(|State(state): State<AppState>, Json(req): Json<oidc_oidc::endpoints::registration::RegisterClientRequest>| async move {
            oidc_oidc::endpoints::registration::register_handler(state.oidc_state(), Json(req)).await
                .unwrap_or_else(|e| axum::Json(serde_json::json!({"error": e.to_string()})))
        }))
}
