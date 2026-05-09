//! OIDC protocol routes.

use axum::Json;
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::response::Html;
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
        .route("/oidc/login", post(|State(state): State<AppState>, json: Json<oidc_oidc::endpoints::login::LoginRequest>| async move {
            oidc_oidc::endpoints::login::login_handler(State(state.oidc_state()), json).await
        }))
        .route("/oidc/error", get(error_handler))
}

/// Simple error page for OIDC authorization failures.
async fn error_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let error = params
        .get("error")
        .cloned()
        .unwrap_or_else(|| "server_error".to_string());
    let description = params
        .get("error_description")
        .cloned()
        .unwrap_or_else(|| "An error occurred during authentication.".to_string());

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Error</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }}
        .error-box {{
            background: white;
            padding: 2.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            max-width: 28rem;
            text-align: center;
        }}
        .error-icon {{
            font-size: 3rem;
            margin-bottom: 1rem;
        }}
        h1 {{
            font-size: 1.25rem;
            color: #dc2626;
            margin: 0 0 0.5rem 0;
        }}
        .error-code {{
            font-family: monospace;
            background: #fef2f2;
            color: #dc2626;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.875rem;
        }}
        p {{
            color: #6b7280;
            margin: 1rem 0 0 0;
            line-height: 1.5;
        }}
        a {{
            color: #2563eb;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="error-box">
        <div class="error-icon">&#x26A0;&#xFE0F;</div>
        <h1>Authentication Error</h1>
        <div class="error-code">{}</div>
        <p>{}</p>
        <p><a href="/">&larr; Back to Home</a></p>
    </div>
</body>
</html>"#,
        html_escape(&error),
        html_escape(&description)
    );

    Html(html)
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
