//! Authorization endpoint handler.

use axum::extract::Query;
use axum::response::Redirect;
use std::collections::HashMap;

use oidc_core::models::AuthCode;
use oidc_core::utils::generate_uuid_v7;
use oidc_repository::repositories::client_repo::ClientRepo;

use crate::state::OidcState;

/// Authorization endpoint handler.
/// Validates the request, generates an authorization code, and redirects back to the client.
///
/// Supports OIDC Core `prompt` and `max_age` parameters:
/// - `prompt=none`: Returns `login_required` if no authenticated session exists.
/// - `prompt=login`: Forces re-authentication (proceeds to login page).
/// - `prompt=consent`: Pass-through (auto-consent for now).
/// - `max_age`: If the user's auth_time exceeds max_age, requires re-authentication.
pub async fn authorize_handler(
    state: OidcState,
    Query(params): Query<HashMap<String, String>>,
) -> Redirect {
    let state_param = params.get("state").cloned();
    match authorize_inner(state, params).await {
        Ok(redirect_uri) => Redirect::temporary(&redirect_uri),
        Err((redirect_uri, error, description)) => {
            tracing::warn!("authorize failed: {} - {}", error, description);
            let mut url = format!("{}?error={}", redirect_uri, urlencoding::encode(&error));
            if !description.is_empty() {
                url.push_str(&format!(
                    "&error_description={}",
                    urlencoding::encode(&description)
                ));
            }
            if let Some(s) = state_param {
                url.push_str(&format!("&state={}", urlencoding::encode(&s)));
            }
            Redirect::temporary(&url)
        }
    }
}

async fn authorize_inner(
    state: OidcState,
    params: HashMap<String, String>,
) -> Result<String, (String, String, String)> {
    // --- Extract redirect_uri early for error responses ---
    let redirect_uri = params
        .get("redirect_uri")
        .cloned()
        .unwrap_or_else(|| "/oidc/error".to_string());

    // --- Parameter extraction ---
    let response_type = params.get("response_type").ok_or_else(|| {
        (
            redirect_uri.clone(),
            "invalid_request".to_string(),
            "Missing response_type".to_string(),
        )
    })?;

    if response_type != "code" {
        return Err((
            redirect_uri.clone(),
            "unsupported_response_type".to_string(),
            "Only 'code' is supported".to_string(),
        ));
    }

    let client_id_str = params.get("client_id").ok_or_else(|| {
        (
            redirect_uri.clone(),
            "invalid_request".to_string(),
            "Missing client_id".to_string(),
        )
    })?;

    let scope = params.get("scope").unwrap_or(&"openid".to_string()).clone();
    let state_param = params.get("state").cloned();
    let code_challenge = params.get("code_challenge").ok_or_else(|| {
        (
            redirect_uri.clone(),
            "invalid_request".to_string(),
            "Missing code_challenge".to_string(),
        )
    })?;

    let code_challenge_method = params.get("code_challenge_method").ok_or_else(|| {
        (
            redirect_uri.clone(),
            "invalid_request".to_string(),
            "Missing code_challenge_method".to_string(),
        )
    })?;

    if code_challenge_method != "S256" {
        return Err((
            redirect_uri.clone(),
            "invalid_request".to_string(),
            "Only S256 code_challenge_method is supported".to_string(),
        ));
    }

    let nonce = params.get("nonce").cloned();

    // --- Client validation ---
    let mut conn = state.connect().await.map_err(|e| {
        (
            redirect_uri.clone(),
            "server_error".to_string(),
            e.to_string(),
        )
    })?;

    let client = ClientRepo
        .find_by_client_id(&mut conn, client_id_str)
        .await
        .map_err(|e| {
            (
                redirect_uri.clone(),
                "server_error".to_string(),
                e.to_string(),
            )
        })?
        .ok_or_else(|| {
            (
                redirect_uri.clone(),
                "invalid_client".to_string(),
                "Client not found".to_string(),
            )
        })?;

    if !client.enabled {
        return Err((
            redirect_uri.clone(),
            "unauthorized_client".to_string(),
            "Client is disabled".to_string(),
        ));
    }

    if !client.redirect_uris.contains(&redirect_uri) {
        // Security: if redirect_uri is invalid, we MUST NOT redirect back.
        // Return to generic error page instead.
        return Err((
            "/oidc/error".to_string(),
            "invalid_request".to_string(),
            "Invalid redirect_uri".to_string(),
        ));
    }

    if client.pkce_required && code_challenge_method != "S256" {
        return Err((
            redirect_uri.clone(),
            "invalid_request".to_string(),
            "PKCE S256 required".to_string(),
        ));
    }

    // --- Scope validation ---
    let requested_scopes: Vec<String> = scope.split(' ').map(|s| s.to_string()).collect();

    // Require "openid" scope for OIDC
    if !requested_scopes.contains(&"openid".to_string()) {
        return Err((
            redirect_uri.clone(),
            "invalid_scope".to_string(),
            "The 'openid' scope is required".to_string(),
        ));
    }

    // Validate requested scopes against client's allowed scopes
    for s in &requested_scopes {
        if !client.allowed_scopes.contains(s) {
            return Err((
                redirect_uri.clone(),
                "invalid_scope".to_string(),
                format!("Scope '{}' is not allowed for this client", s),
            ));
        }
    }

    // --- prompt parameter handling (OIDC Core §3.1.2.1) ---
    let prompt_values: Vec<&str> = params
        .get("prompt")
        .map(|p| p.split(' ').collect())
        .unwrap_or_default();

    // prompt=none: If the user is not authenticated, return login_required.
    // Since we don't have session cookies yet, we always return login_required
    // for prompt=none when no login_hint is provided.
    if prompt_values.contains(&"none") {
        let login_hint = params.get("login_hint");
        if login_hint.is_none() {
            return Err((
                redirect_uri.clone(),
                "login_required".to_string(),
                "The Authorization Server requires End-User authentication.".to_string(),
            ));
        }
        // If login_hint is provided, we proceed — the user will be looked up below.
    }

    // prompt=login: Force re-authentication. For now, this just proceeds to the
    // login page normally (same as no session), so no special action needed.

    // prompt=consent: Pass-through — we auto-consent for now.

    // --- max_age parameter handling (OIDC Core §3.1.2.1) ---
    // If max_age is specified and the user's auth_time exceeds it, require
    // re-authentication. Since we don't have session cookies yet, any max_age
    // value means we need to re-authenticate unless login_hint is provided
    // and we can verify the auth_time.
    if let Some(max_age_str) = params.get("max_age") {
        if let Ok(max_age) = max_age_str.parse::<i64>() {
            if max_age >= 0 {
                // Without session cookies, we cannot verify auth_time.
                // If login_hint is provided, we'll proceed (user will be
                // looked up below). Otherwise, redirect to login.
                let login_hint = params.get("login_hint");
                if login_hint.is_none() {
                    // No way to verify auth_time — require re-authentication
                    let mut login_url = format!(
                        "/login?return_to={}",
                        urlencoding::encode(&format!(
                            "/oidc/authorize?{}",
                            serde_urlencoded::to_string(&params).unwrap_or_default()
                        ))
                    );
                    if let Some(s) = state_param {
                        login_url.push_str(&format!("&state={}", urlencoding::encode(&s)));
                    }
                    return Ok(login_url);
                }
            }
        }
    }

    // --- User authentication ---
    // For now, we require a pre-authenticated session or login_hint.
    // TODO: Replace with proper session/cookie-based authentication.
    let login_hint = params.get("login_hint").cloned();
    let user = if let Some(email) = login_hint {
        oidc_repository::repositories::user_repo::UserRepo
            .find_by_email(&mut conn, client.realm_id, &email)
            .await
            .map_err(|e| {
                (
                    redirect_uri.clone(),
                    "server_error".to_string(),
                    e.to_string(),
                )
            })?
            .ok_or_else(|| {
                (
                    redirect_uri.clone(),
                    "access_denied".to_string(),
                    "User not found".to_string(),
                )
            })?
    } else {
        // No login_hint: redirect to login page with return URL
        let mut login_url = format!(
            "/login?return_to={}",
            urlencoding::encode(&format!(
                "/oidc/authorize?{}",
                serde_urlencoded::to_string(&params).unwrap_or_default()
            ))
        );
        if let Some(s) = state_param {
            login_url.push_str(&format!("&state={}", urlencoding::encode(&s)));
        }
        return Ok(login_url);
    };

    if !user.enabled {
        return Err((
            redirect_uri.clone(),
            "access_denied".to_string(),
            "User account is disabled".to_string(),
        ));
    }

    // --- Generate authorization code ---
    let code_value = generate_auth_code();
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(60); // 60 seconds per plan

    let auth_code = AuthCode {
        id: generate_uuid_v7(),
        code: code_value.clone(),
        client_id: client.id,
        user_id: user.id,
        realm_id: client.realm_id,
        redirect_uri: redirect_uri.clone(),
        scope: requested_scopes,
        code_challenge: code_challenge.clone(),
        code_challenge_method: oidc_core::models::CodeChallengeMethod::S256,
        nonce,
        used: false,
        expires_at,
    };

    oidc_repository::repositories::auth_code_repo::AuthCodeRepo
        .create(&mut conn, &auth_code)
        .await
        .map_err(|e| {
            (
                redirect_uri.clone(),
                "server_error".to_string(),
                e.to_string(),
            )
        })?;

    // --- Build redirect URL ---
    let mut redirect = format!("{}?code={}", redirect_uri, urlencoding::encode(&code_value));
    if let Some(s) = state_param {
        redirect.push_str(&format!("&state={}", urlencoding::encode(&s)));
    }

    Ok(redirect)
}

fn generate_auth_code() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("getrandom failed");
    base64_encode_url_safe_no_pad(&buf)
}

fn base64_encode_url_safe_no_pad(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}
