//! Authorization endpoint handler.

use axum::extract::Query;
use axum::http::HeaderMap;
use axum::response::Redirect;
use std::collections::HashMap;

use oidc_core::models::AuthCode;
use oidc_core::utils::generate_uuid_v7;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;

use crate::session_cookie;
use crate::state::OidcState;

/// Authorization endpoint handler.
/// Validates the request, generates an authorization code, and redirects back to the client.
///
/// Supports OIDC Core `prompt` and `max_age` parameters:
/// - `prompt=none`: Returns `login_required` if no authenticated session exists.
///   If a valid session cookie is present, the user is authenticated silently (SSO).
/// - `prompt=login`: Forces re-authentication (ignores session cookie, proceeds to login page).
/// - `prompt=consent`: Pass-through (auto-consent for now).
/// - `max_age`: If the user's auth_time exceeds max_age, requires re-authentication.
pub async fn authorize_handler(
    state: OidcState,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Redirect {
    let state_param = params.get("state").cloned();
    match authorize_inner(state, &headers, params).await {
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
    headers: &HeaderMap,
    params: HashMap<String, String>,
) -> Result<String, (String, String, String)> {
    // --- Extract redirect_uri early for error responses ---
    let redirect_uri_param = params.get("redirect_uri").cloned();
    let redirect_uri = match redirect_uri_param.as_deref() {
        Some(uri) if !uri.is_empty() => {
            // Validate URI format before using it for error redirects
            if url::Url::parse(uri).is_err() {
                return Err((
                    "/oidc/error".to_string(),
                    "invalid_request".to_string(),
                    "Invalid redirect_uri format".to_string(),
                ));
            }
            uri.to_string()
        }
        _ => "/oidc/error".to_string(),
    };

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
    let mut conn = match state.connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB connection failed in authorize: {e}");
            return Err((
                "/oidc/error".to_string(),
                "server_error".to_string(),
                "An internal error occurred".to_string(),
            ));
        }
    };

    let client = match ClientRepo.find_by_client_id(&mut conn, client_id_str).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Err((
                redirect_uri.clone(),
                "invalid_client".to_string(),
                "Client not found".to_string(),
            ));
        }
        Err(e) => {
            tracing::error!("DB error finding client in authorize: {e}");
            return Err((
                redirect_uri.clone(),
                "server_error".to_string(),
                "An internal error occurred".to_string(),
            ));
        }
    };

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

    // prompt=login forces re-authentication — skip session cookie lookup.
    let force_login = prompt_values.contains(&"login");

    // Try to resolve the user from the session cookie.
    let cookie_session_id = if !force_login {
        match state.decode_encryption_key() {
            Ok(key) => session_cookie::extract_session_id_from_headers(headers, &key),
            Err(e) => {
                tracing::warn!("Failed to decode encryption key: {e}");
                None
            }
        }
    } else {
        None
    };

    // Look up the session and user from the cookie.
    let cookie_user = if let Some(ref session_id_str) = cookie_session_id {
        if let Ok(sid) = uuid::Uuid::parse_str(session_id_str) {
            match SessionRepo.find_by_id(&mut conn, sid).await {
                Ok(Some(session))
                    if !session.revoked && session.expires_at > chrono::Utc::now() =>
                {
                    // Session is valid — look up the user if one is attached.
                    if let Some(user_id) = session.user_id {
                        match UserRepo.find_by_id(&mut conn, user_id).await {
                            Ok(Some(u)) if u.enabled => Some(u),
                            Ok(Some(_)) => {
                                tracing::warn!(
                                    "User {} is disabled, ignoring session cookie",
                                    user_id
                                );
                                None
                            }
                            Ok(None) => {
                                tracing::warn!(
                                    "User {} not found, ignoring session cookie",
                                    user_id
                                );
                                None
                            }
                            Err(e) => {
                                tracing::error!("DB error finding user from session cookie: {e}");
                                None
                            }
                        }
                    } else {
                        tracing::debug!(
                            "Session {} has no user (client_credentials grant), ignoring",
                            session.id
                        );
                        None
                    }
                }
                Ok(Some(_)) => {
                    tracing::debug!("Session {} is revoked or expired, ignoring", sid);
                    None
                }
                Ok(None) => {
                    tracing::debug!("Session {} not found, ignoring", sid);
                    None
                }
                Err(e) => {
                    tracing::error!("DB error finding session from cookie: {e}");
                    None
                }
            }
        } else {
            tracing::debug!("Invalid UUID in session cookie: {session_id_str}");
            None
        }
    } else {
        None
    };

    // prompt=none: If the user is not authenticated, return login_required.
    if prompt_values.contains(&"none") {
        if cookie_user.is_none() && params.get("login_hint").is_none() {
            return Err((
                redirect_uri.clone(),
                "login_required".to_string(),
                "The Authorization Server requires End-User authentication.".to_string(),
            ));
        }
        // If a valid session cookie or login_hint exists, we proceed.
    }

    // prompt=consent: Pass-through — we auto-consent for now.

    // --- max_age parameter handling (OIDC Core §3.1.2.1) ---
    // If max_age is specified and the user's auth_time exceeds it, require
    // re-authentication.
    if let Some(max_age_str) = params.get("max_age") {
        if let Ok(max_age) = max_age_str.parse::<i64>() {
            if max_age >= 0 {
                // If we have a session cookie, check auth_time via session creation time.
                if cookie_user.is_some() {
                    // The session's created_at serves as a proxy for auth_time.
                    // We look up the session again to check the time.
                    if let Some(ref session_id_str) = cookie_session_id {
                        if let Ok(sid) = uuid::Uuid::parse_str(session_id_str) {
                            if let Ok(Some(session)) = SessionRepo.find_by_id(&mut conn, sid).await
                            {
                                let auth_age =
                                    (chrono::Utc::now() - session.created_at).num_seconds();
                                if auth_age > max_age {
                                    // Session is too old — require re-authentication.
                                    let mut login_url = format!(
                                        "/login?return_to={}",
                                        urlencoding::encode(&format!(
                                            "/oidc/authorize?{}",
                                            serde_urlencoded::to_string(&params)
                                                .unwrap_or_default()
                                        ))
                                    );
                                    if let Some(s) = state_param {
                                        login_url.push_str(&format!(
                                            "&state={}",
                                            urlencoding::encode(&s)
                                        ));
                                    }
                                    return Ok(login_url);
                                }
                            }
                        }
                    }
                } else {
                    // No session cookie — if login_hint is provided, proceed.
                    // Otherwise, redirect to login.
                    let login_hint = params.get("login_hint");
                    if login_hint.is_none() {
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
    }

    // --- User authentication ---
    // Priority: 1) session cookie  2) login_hint  3) redirect to login
    let login_hint = params.get("login_hint").cloned();
    let user = if let Some(u) = cookie_user {
        u
    } else if let Some(email) = login_hint {
        match UserRepo
            .find_by_email(&mut conn, client.realm_id, &email)
            .await
        {
            Ok(Some(u)) => u,
            Ok(None) => {
                return Err((
                    redirect_uri.clone(),
                    "access_denied".to_string(),
                    "User not found".to_string(),
                ));
            }
            Err(e) => {
                tracing::error!("DB error finding user in authorize: {e}");
                return Err((
                    redirect_uri.clone(),
                    "server_error".to_string(),
                    "An internal error occurred".to_string(),
                ));
            }
        }
    } else {
        // No session cookie or login_hint: redirect to login page with return URL
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

    match oidc_repository::repositories::auth_code_repo::AuthCodeRepo
        .create(&mut conn, &auth_code)
        .await
    {
        Ok(()) => {}
        Err(e) => {
            tracing::error!("DB error creating auth code in authorize: {e}");
            return Err((
                redirect_uri.clone(),
                "server_error".to_string(),
                "An internal error occurred".to_string(),
            ));
        }
    };

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
