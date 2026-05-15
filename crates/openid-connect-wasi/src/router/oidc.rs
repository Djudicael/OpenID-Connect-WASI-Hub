//! OIDC protocol routes.

use axum::Json;
use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use std::collections::HashMap;

use crate::middleware::admin_auth::AdminAuth;
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
        .route("/oidc/authorize", get(|State(state): State<AppState>, headers: axum::http::HeaderMap, Query(params): Query<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::authorize::authorize_handler(state.oidc_state(), headers, Query(params)).await
        }))
        .route("/oidc/token", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, Form(params): Form<HashMap<String, String>>| async move {
            let oidc_state = state.oidc_state();
            match oidc_oidc::endpoints::token::token_handler(oidc_state, headers, params).await {
                Ok(json) => (axum::http::StatusCode::OK, json).into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        .route("/oidc/userinfo", get(|State(state): State<AppState>, headers: axum::http::HeaderMap| async move {
            let auth = headers.get(axum::http::header::AUTHORIZATION).cloned();
            let dpop = headers.get("DPoP").cloned();
            oidc_oidc::endpoints::userinfo::userinfo_handler(State(state.oidc_state()), auth, dpop).await
        }))
        .route("/oidc/introspect", post(|State(state): State<AppState>, form: Form<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::introspect::introspect_handler(State(state.oidc_state()), form).await
        }))
        .route("/oidc/revoke", post(|State(state): State<AppState>, form: Form<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::revoke::revoke_handler(State(state.oidc_state()), form).await
        }))
        .route("/oidc/par", post(|State(state): State<AppState>, headers: axum::http::HeaderMap, Form(params): Form<HashMap<String, String>>| async move {
            let oidc_state = state.oidc_state();
            match oidc_oidc::endpoints::par::par_handler(oidc_state, headers, params).await {
                Ok(json) => (axum::http::StatusCode::CREATED, json).into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        .route("/oidc/logout", get(|State(state): State<AppState>, headers: axum::http::HeaderMap, Query(params): Query<HashMap<String, String>>| async move {
            oidc_oidc::endpoints::logout::logout_handler(state.oidc_state(), headers, Query(params)).await
        }))
        .route("/oidc/session/check", get(|State(state): State<AppState>, Query(params): Query<oidc_oidc::endpoints::session::check_session::CheckSessionParams>| async move {
            oidc_oidc::endpoints::session::check_session::check_session_handler(state.oidc_state(), Query(params)).await
        }))
        .route("/oidc/register", post(|State(state): State<AppState>, auth: AdminAuth, Json(req): Json<oidc_oidc::endpoints::registration::RegisterClientRequest>| async move {
            match oidc_oidc::endpoints::registration::register_handler(state.oidc_state(), auth.realm_id, Json(req)).await {
                Ok(json) => (axum::http::StatusCode::OK, json).into_response(),
                Err(e) => oidc_oidc::errors::from_oidc_error(&e).into_response(),
            }
        }))
        // Backward-compatible admin login
        .route("/oidc/login", post(|State(state): State<AppState>, json: Json<oidc_oidc::endpoints::login::LoginRequest>| async move {
            oidc_oidc::endpoints::login::login_handler(State(state.oidc_state()), json).await
        }))
        // Per-realm login endpoint (Keycloak-compatible path)
        .route("/realms/{realm}/protocol/openid-connect/token", post(per_realm_token_handler))
        .route("/realms/{realm}/protocol/openid-connect/auth", get(per_realm_authorize_handler))
        .route("/realms/{realm}/.well-known/openid-configuration", get(per_realm_discovery_handler))
        .route("/realms/{realm}/protocol/openid-connect/certs", get(per_realm_certs_handler))
        .route("/realms/{realm}/login", get(per_realm_login_page_handler))
        .route("/realms/{realm}/login", post(per_realm_login_handler))
        .route("/oidc/error", get(error_handler))
}

/// Per-realm token endpoint (Keycloak-compatible).
///
/// Accepts `email` + `password` as JSON, uses the realm from the URL path.
async fn per_realm_token_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Json(req): Json<oidc_oidc::endpoints::login::LoginRequest>,
) -> axum::response::Response {
    // Override any realm field in the body with the URL path realm
    let mut request = req;
    request.realm = Some(realm);

    match oidc_oidc::endpoints::login::login_handler(State(state.oidc_state()), Json(request)).await
    {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

/// Per-realm login endpoint (convenience path).
///
/// Accepts `email` + `password` as JSON, uses the realm from the URL path.
async fn per_realm_login_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Json(req): Json<oidc_oidc::endpoints::login::LoginRequest>,
) -> axum::response::Response {
    let mut request = req;
    request.realm = Some(realm);

    match oidc_oidc::endpoints::login::login_handler(State(state.oidc_state()), Json(request)).await
    {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

/// Per-realm authorize handler (Keycloak-compatible).
async fn per_realm_authorize_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Redirect {
    oidc_oidc::endpoints::authorize::realm_authorize_handler(
        state.oidc_state(),
        realm,
        headers,
        Query(params),
    )
    .await
}

/// Per-realm discovery handler (Keycloak-compatible).
async fn per_realm_discovery_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> Json<serde_json::Value> {
    oidc_oidc::realm_discovery_handler(state.oidc_state(), realm).await
}

/// Per-realm JWKS (certs) handler.
async fn per_realm_certs_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> axum::response::Response {
    match oidc_oidc::endpoints::jwks::realm_jwks_handler(state.oidc_state(), realm).await {
        Ok(json) => json.into_response(),
        Err(e) => {
            let status = match e {
                oidc_core::OidcError::NotFound(_) => axum::http::StatusCode::NOT_FOUND,
                _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            };
            let body = serde_json::json!({"error": e.to_string()});
            (status, axum::Json(body)).into_response()
        }
    }
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

/// Serve a branded HTML login page for a realm.
///
/// Reads theme configuration from `realm.config.theme` and renders
/// a self-contained login form that POSTs JSON to the token endpoint.
async fn per_realm_login_page_handler(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let mut conn = match wasi_pg_client::Connection::connect(&state.db_config).await {
        Ok(c) => oidc_repository::Connection::from_pg_client(c),
        Err(e) => {
            tracing::error!("DB connection failed for login page: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
                .into_response();
        }
    };

    let realm_entity = match oidc_repository::repositories::realm_repo::RealmRepo
        .find_by_name(&mut conn, &realm)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                "Realm not found".to_string(),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("DB error fetching realm for login page: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
                .into_response();
        }
    };

    if !realm_entity.enabled {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Realm is disabled".to_string(),
        )
            .into_response();
    }

    // Extract theme from config JSONB
    let theme = realm_entity.config.get("theme");
    let login_title = theme
        .and_then(|t| t.get("login_title"))
        .and_then(|v| v.as_str())
        .unwrap_or(&realm_entity.display_name);
    let logo_url = theme
        .and_then(|t| t.get("logo_url"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let primary_color = theme
        .and_then(|t| t.get("primary_color"))
        .and_then(|v| v.as_str())
        .unwrap_or("#2563eb");
    let bg_color = theme
        .and_then(|t| t.get("bg_color"))
        .and_then(|v| v.as_str())
        .unwrap_or("#f8fafc");

    let return_to = params.get("return_to").cloned().unwrap_or_default();
    let state_param = params.get("state").cloned().unwrap_or_default();

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Sign In</title>
    <style>
        :root {{ --primary: {}; --bg: {}; }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex; align-items: center; justify-content: center;
            min-height: 100vh; margin: 0; background: var(--bg);
        }}
        .login-box {{
            background: #fff; padding: 2.5rem; border-radius: 12px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.08); width: 100%; max-width: 24rem;
            text-align: center;
        }}
        .logo {{ max-height: 3rem; margin-bottom: 1rem; }}
        h1 {{ font-size: 1.5rem; font-weight: 600; margin: 0 0 0.25rem 0; color: #111; }}
        .subtitle {{ color: #6b7280; margin-bottom: 1.5rem; font-size: 0.875rem; }}
        .form {{ display: flex; flex-direction: column; gap: 1rem; text-align: left; }}
        label {{ display: block; font-size: 0.875rem; font-weight: 500; margin-bottom: 0.25rem; color: #374151; }}
        input {{
            width: 100%; padding: 0.625rem; border: 1px solid #d1d5db;
            border-radius: 6px; font-size: 0.875rem; background: #fff; color: #111;
        }}
        input:focus {{ outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }}
        .pw-wrap {{ position: relative; }}
        .pw-wrap input {{ padding-right: 2.5rem; }}
        .toggle-pw {{
            position: absolute; right: 0.5rem; top: 50%; transform: translateY(-50%);
            background: none; border: none; cursor: pointer; font-size: 1rem; color: #9ca3af;
        }}
        button[type="submit"] {{
            width: 100%; padding: 0.75rem; font-size: 1rem; font-weight: 500;
            background: var(--primary); color: #fff; border: none; border-radius: 6px;
            cursor: pointer; margin-top: 0.5rem;
        }}
        button[type="submit"]:hover {{ opacity: 0.92; }}
        button[type="submit"]:disabled {{ opacity: 0.6; cursor: not-allowed; }}
        .error {{
            color: #dc2626; font-size: 0.875rem; margin-top: 0.75rem;
            padding: 0.75rem; background: #fef2f2; border-radius: 6px; display: none;
        }}
        .footer {{ margin-top: 1.25rem; font-size: 0.75rem; color: #9ca3af; }}
    </style>
</head>
<body>
    <div class="login-box">
        {}
        <h1>{}</h1>
        <p class="subtitle">Sign in to continue</p>
        <form class="form" id="loginForm">
            <div>
                <label for="email">Email</label>
                <input id="email" type="email" placeholder="you@example.com" required autofocus />
            </div>
            <div>
                <label for="password">Password</label>
                <div class="pw-wrap">
                    <input id="password" type="password" placeholder="••••••••" required />
                    <button type="button" class="toggle-pw" id="togglePw" aria-label="Toggle password visibility">&#128065;</button>
                </div>
            </div>
            <button type="submit" id="submitBtn">Sign In</button>
            <div class="error" id="errorBox"></div>
        </form>
        <div class="footer">Powered by OpenID Connect Hub</div>
    </div>
    <script>
        (function() {{
            const form = document.getElementById('loginForm');
            const btn = document.getElementById('submitBtn');
            const errorBox = document.getElementById('errorBox');
            const togglePw = document.getElementById('togglePw');
            const pwInput = document.getElementById('password');
            const returnTo = {};
            const stateParam = {};

            togglePw.addEventListener('click', function() {{
                const isPw = pwInput.type === 'password';
                pwInput.type = isPw ? 'text' : 'password';
                togglePw.textContent = isPw ? String.fromCodePoint(0x1F576) : String.fromCodePoint(0x1F441);
            }});

            form.addEventListener('submit', async function(e) {{
                e.preventDefault();
                btn.disabled = true;
                btn.textContent = 'Signing in...';
                errorBox.style.display = 'none';

                try {{
                    const res = await fetch('/realms/{}/protocol/openid-connect/token', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            email: document.getElementById('email').value,
                            password: pwInput.value,
                            realm: '{}'
                        }})
                    }});
                    const data = await res.json();
                    if (!res.ok) {{
                        throw new Error(data.error_description || data.error || 'Login failed');
                    }}
                    // Store tokens in sessionStorage for SPA usage
                    sessionStorage.setItem('access_token', data.access_token);
                    sessionStorage.setItem('refresh_token', data.refresh_token);
                    if (returnTo) {{
                        let url = decodeURIComponent(returnTo);
                        if (stateParam) url += (url.includes('?') ? '&' : '?') + 'state=' + encodeURIComponent(stateParam);
                        window.location.href = url;
                    }} else {{
                        window.location.href = '/';
                    }}
                }} catch (err) {{
                    errorBox.textContent = err.message;
                    errorBox.style.display = 'block';
                    btn.disabled = false;
                    btn.textContent = 'Sign In';
                }}
            }});
        }})();
    </script>
</body>
</html>"##,
        html_escape(login_title),
        primary_color,
        bg_color,
        if logo_url.is_empty() {
            String::new()
        } else {
            format!(
                r#"<img src="{}" alt="Logo" class="logo" />"#,
                html_escape(logo_url)
            )
        },
        html_escape(login_title),
        if return_to.is_empty() {
            "null".to_string()
        } else {
            format!("'{}'", html_escape(&return_to))
        },
        if state_param.is_empty() {
            "null".to_string()
        } else {
            format!("'{}'", html_escape(&state_param))
        },
        html_escape(&realm),
        html_escape(&realm)
    );

    Html(html).into_response()
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
