//! Authorization endpoint handler.
//!
//! Supports RFC 9101 JARM (JWT-Secured Authorization Response Mode) in addition
//! to the standard OIDC response modes (query, fragment, form_post).

use axum::extract::Query;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::collections::HashMap;

use oidc_core::models::{AuthCode, ResponseType};
use oidc_core::traits::TokenService;
use oidc_core::utils::generate_uuid_v7;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::session_repo::SessionRepo;
use oidc_repository::repositories::user_repo::UserRepo;

use crate::session_cookie;
use crate::state::OidcState;

// ---------------------------------------------------------------------------
// Response mode types (RFC 9101 JARM)
// ---------------------------------------------------------------------------

/// The effective delivery mode for an authorization response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseMode {
    /// Parameters in the query string (default for `code` flow)
    Query,
    /// Parameters in the URI fragment (default for implicit/hybrid)
    Fragment,
    /// Auto-submitting HTML form POST (OIDC Core §3.1.5.3)
    FormPost,
}

/// Parsed `response_mode` parameter from the authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedResponseMode {
    Query,
    Fragment,
    FormPost,
    Jwt,
    QueryJwt,
    FragmentJwt,
    FormPostJwt,
}

impl ParsedResponseMode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "query" => Some(Self::Query),
            "fragment" => Some(Self::Fragment),
            "form_post" => Some(Self::FormPost),
            "jwt" => Some(Self::Jwt),
            "query.jwt" => Some(Self::QueryJwt),
            "fragment.jwt" => Some(Self::FragmentJwt),
            "form_post.jwt" => Some(Self::FormPostJwt),
            _ => None,
        }
    }

    /// Returns true if this is a JARM mode (ends with `.jwt`).
    fn is_jarm(&self) -> bool {
        matches!(
            self,
            Self::Jwt | Self::QueryJwt | Self::FragmentJwt | Self::FormPostJwt
        )
    }

    /// Returns the base delivery mode for a JARM response.
    /// For non-JARM modes, returns `None`.
    fn jarm_base_mode(&self) -> Option<ResponseMode> {
        match self {
            Self::Jwt => None, // resolved later based on response_type
            Self::QueryJwt => Some(ResponseMode::Query),
            Self::FragmentJwt => Some(ResponseMode::Fragment),
            Self::FormPostJwt => Some(ResponseMode::FormPost),
            _ => None,
        }
    }

    /// Returns the base delivery mode for a non-JARM response.
    fn base_mode(&self) -> ResponseMode {
        match self {
            Self::Query => ResponseMode::Query,
            Self::Fragment => ResponseMode::Fragment,
            Self::FormPost => ResponseMode::FormPost,
            _ => unreachable!("base_mode called on JARM mode"),
        }
    }
}

/// The result of `authorize_inner`: either a redirect URL or an HTML form page.
#[derive(Debug)]
enum AuthorizeResult {
    /// Standard HTTP redirect (query or fragment mode).
    Redirect(String),
    /// HTML auto-submitting form (form_post mode).
    FormPost { html: String },
}

impl IntoResponse for AuthorizeResult {
    fn into_response(self) -> Response {
        match self {
            Self::Redirect(url) => Redirect::temporary(&url).into_response(),
            Self::FormPost { html, .. } => Html(html).into_response(),
        }
    }
}

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
) -> Response {
    let state_param = params.get("state").cloned();
    match authorize_inner(state, &headers, params, None).await {
        Ok(result) => result.into_response(),
        Err((redirect_uri, error, description)) => {
            tracing::warn!("authorize failed: {} - {}", error, description);
            let url = build_error_url(
                &redirect_uri,
                &error,
                &description,
                state_param.as_deref(),
                ResponseMode::Query,
            );
            Redirect::temporary(&url).into_response()
        }
    }
}

/// Per-realm authorization endpoint handler (Keycloak-compatible).
///
/// Resolves the realm by name, then delegates to authorize_inner.
/// Path: /realms/{realm}/protocol/openid-connect/auth
pub async fn realm_authorize_handler(
    state: OidcState,
    realm: String,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let state_param = params.get("state").cloned();
    match authorize_inner(state, &headers, params, Some(&realm)).await {
        Ok(result) => result.into_response(),
        Err((redirect_uri, error, description)) => {
            tracing::warn!(
                "authorize failed for realm {}: {} - {}",
                realm,
                error,
                description
            );
            let url = build_error_url(
                &redirect_uri,
                &error,
                &description,
                state_param.as_deref(),
                ResponseMode::Query,
            );
            Redirect::temporary(&url).into_response()
        }
    }
}

async fn authorize_inner(
    state: OidcState,
    headers: &HeaderMap,
    params: HashMap<String, String>,
    realm_name: Option<&str>,
) -> Result<AuthorizeResult, (String, String, String)> {
    // Helper to build the correct login URL based on whether a realm is present
    let build_login_url = |return_to: &str, state: Option<&String>| {
        let mut url = if let Some(name) = realm_name {
            format!(
                "/realms/{}/login?return_to={}",
                name,
                urlencoding::encode(return_to)
            )
        } else {
            format!("/login?return_to={}", urlencoding::encode(return_to))
        };
        if let Some(s) = state {
            url.push_str(&format!("&state={}", urlencoding::encode(s)));
        }
        url
    };

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

    // --- Pushed Authorization Request (PAR) resolution ---
    let mut params = params;
    if let Some(request_uri) = params.get("request_uri").cloned() {
        if let Some(token) = request_uri.strip_prefix("urn:ietf:params:oauth:request_uri:") {
            let mut conn = match state.connect().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("DB connection failed in authorize PAR lookup: {e}");
                    return Err((
                        redirect_uri.clone(),
                        "server_error".to_string(),
                        "An internal error occurred".to_string(),
                    ));
                }
            };

            match oidc_repository::repositories::par_repo::ParRepo
                .find_by_request_uri_token(&mut conn, token)
                .await
            {
                Ok(Some(par)) if !par.used && par.expires_at > chrono::Utc::now() => {
                    if let Some(stored) = par.request_params.as_object() {
                        for (k, v) in stored {
                            if let Some(s) = v.as_str() {
                                params.entry(k.clone()).or_insert_with(|| s.to_string());
                            }
                        }
                    }
                    let _ = oidc_repository::repositories::par_repo::ParRepo
                        .mark_used(&mut conn, par.id)
                        .await;
                }
                Ok(Some(_)) => {
                    return Err((
                        redirect_uri.clone(),
                        "invalid_request".to_string(),
                        "The request_uri is expired or has already been used".to_string(),
                    ));
                }
                Ok(None) => {
                    return Err((
                        redirect_uri.clone(),
                        "invalid_request".to_string(),
                        "The request_uri was not found".to_string(),
                    ));
                }
                Err(e) => {
                    tracing::error!("DB error looking up PAR: {e}");
                    return Err((
                        redirect_uri.clone(),
                        "server_error".to_string(),
                        "An internal error occurred".to_string(),
                    ));
                }
            }
        } else {
            return Err((
                redirect_uri.clone(),
                "invalid_request".to_string(),
                "Invalid request_uri format".to_string(),
            ));
        }
    }

    // --- Signed Request Object resolution (OIDC Core §6) ---
    if let Some(request_jwt) = params.get("request").cloned() {
        // Per OIDC Core §6.1: If both request and request_uri are present, return an error.
        // Since request_uri was already resolved above, if we reach here with both,
        // it means request_uri was present and resolved — reject.
        if params.contains_key("request_uri") {
            return Err((
                redirect_uri.clone(),
                "invalid_request".to_string(),
                "request and request_uri MUST NOT be used together".to_string(),
            ));
        }

        // The client_id must be present either in params or in the JWT
        let request_client_id = params.get("client_id").cloned();

        // Parse the request object header/claims without verification to get client_id if missing
        let (_header, unverified_claims, _signing_input, _signature) =
            crate::tokens::jwt_service::JwtTokenService::parse_client_assertion_unverified(
                &request_jwt,
            )
            .map_err(|e| {
                (
                    redirect_uri.clone(),
                    "invalid_request_object".to_string(),
                    format!("Request object parse error: {e}"),
                )
            })?;

        // Determine client_id: from params first, then from JWT iss
        let effective_client_id = request_client_id
            .as_deref()
            .or(Some(unverified_claims.iss.as_str()))
            .ok_or_else(|| {
                (
                    redirect_uri.clone(),
                    "invalid_request".to_string(),
                    "Missing client_id".to_string(),
                )
            })?;

        // Look up the client to get its JWKS
        let mut conn_for_jwks = match state.connect().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("DB connection failed in authorize request object lookup: {e}");
                return Err((
                    redirect_uri.clone(),
                    "server_error".to_string(),
                    "An internal error occurred".to_string(),
                ));
            }
        };

        let client_for_jwks = ClientRepo
            .find_by_client_id(&mut conn_for_jwks, effective_client_id)
            .await
            .map_err(|_| {
                (
                    redirect_uri.clone(),
                    "invalid_client".to_string(),
                    "Client not found".to_string(),
                )
            })?
            .ok_or_else(|| {
                (
                    redirect_uri.clone(),
                    "invalid_client".to_string(),
                    "Client not found".to_string(),
                )
            })?;

        let client_jwks = client_for_jwks.jwks.as_ref().ok_or_else(|| {
            (
                redirect_uri.clone(),
                "invalid_request".to_string(),
                "Client has no JWKS for request object verification".to_string(),
            )
        })?;

        // Verify and extract claims from the request object
        let request_claims = crate::tokens::request_object::verify_request_object(
            &request_jwt,
            client_jwks,
            &state.issuer,
            effective_client_id,
            chrono::Utc::now().timestamp(),
        )
        .map_err(|e| {
            (
                redirect_uri.clone(),
                "invalid_request_object".to_string(),
                format!("Request object verification failed: {e}"),
            )
        })?;

        // Merge: request object claims override query params per OIDC Core §6.2
        // But certain parameters (client_id, redirect_uri) must match between query and JWT
        for (k, v) in request_claims {
            params.entry(k).or_insert(v);
        }
    }

    // --- Parameter extraction ---
    let response_type_raw = params.get("response_type").ok_or_else(|| {
        (
            redirect_uri.clone(),
            "invalid_request".to_string(),
            "Missing response_type".to_string(),
        )
    })?;

    let response_type = match ResponseType::parse(response_type_raw) {
        Ok(rt) => rt,
        Err(_) => {
            return Err((
                redirect_uri.clone(),
                "unsupported_response_type".to_string(),
                "Invalid or unsupported response_type".to_string(),
            ));
        }
    };

    // --- response_mode parameter (RFC 9101 JARM) ---
    let response_mode_param = params.get("response_mode").cloned();
    let parsed_response_mode = match response_mode_param.as_deref() {
        Some(rm) => match ParsedResponseMode::parse(rm) {
            Some(prm) => Some(prm),
            None => {
                return Err((
                    redirect_uri.clone(),
                    "invalid_request".to_string(),
                    format!("Unsupported response_mode: {}", rm),
                ));
            }
        },
        None => None,
    };

    // Determine whether this is a JARM request
    let is_jarm = parsed_response_mode
        .as_ref()
        .map_or(false, |prm| prm.is_jarm());

    // Determine the effective delivery mode
    let effective_mode = match &parsed_response_mode {
        Some(prm) if prm.is_jarm() => {
            // For JARM, resolve the base delivery mode
            match prm.jarm_base_mode() {
                Some(mode) => mode,
                None => {
                    // `jwt` without prefix: use default based on response_type
                    if response_type.is_implicit_or_hybrid() {
                        ResponseMode::Fragment
                    } else {
                        ResponseMode::Query
                    }
                }
            }
        }
        Some(prm) => prm.base_mode(),
        None => {
            // No response_mode specified: use default based on response_type
            if response_type.is_implicit_or_hybrid() {
                ResponseMode::Fragment
            } else {
                ResponseMode::Query
            }
        }
    };

    let client_id_str = params.get("client_id").ok_or_else(|| {
        (
            redirect_uri.clone(),
            "invalid_request".to_string(),
            "Missing client_id".to_string(),
        )
    })?;

    let scope = params.get("scope").unwrap_or(&"openid".to_string()).clone();
    let state_param = params.get("state").cloned();
    // PKCE is required for authorization-code and hybrid flows (with code).
    // It is optional for pure implicit flows (no code), but we require it
    // for all flows that issue a code.
    let code_challenge = params.get("code_challenge").cloned();
    let code_challenge_method = params.get("code_challenge_method").cloned();

    if response_type.has_code() {
        let _cc = code_challenge.as_ref().ok_or_else(|| {
            (
                redirect_uri.clone(),
                "invalid_request".to_string(),
                "Missing code_challenge".to_string(),
            )
        })?;
        let ccm = code_challenge_method.as_ref().ok_or_else(|| {
            (
                redirect_uri.clone(),
                "invalid_request".to_string(),
                "Missing code_challenge_method".to_string(),
            )
        })?;
        if ccm != "S256" {
            return Err((
                redirect_uri.clone(),
                "invalid_request".to_string(),
                "Only S256 code_challenge_method is supported".to_string(),
            ));
        }
    }

    let nonce = params.get("nonce").cloned();

    // --- display parameter handling (OIDC Core §3.1.2.1) ---
    let display = params.get("display").cloned();

    // --- claims parameter handling (OIDC Core §5.5) ---
    let claims_request: Option<serde_json::Value> = params
        .get("claims")
        .and_then(|c| serde_json::from_str(c).ok());

    // --- acr_values parameter handling (OIDC Core §3.1.2.1) ---
    let acr_values: Vec<String> = params
        .get("acr_values")
        .map(|v| v.split(' ').map(|s| s.to_string()).collect())
        .unwrap_or_default();

    // --- claims_locales parameter handling (OIDC Core §3.1.2.1 / §5.2) ---
    let claims_locales: Vec<String> = params
        .get("claims_locales")
        .map(|v| v.split(' ').map(|s| s.to_string()).collect())
        .unwrap_or_default();

    // --- id_token_hint parameter handling (OIDC Core §3.1.2.1) ---
    // Per OIDC Core §3.1.2.1: "id_token_hint" is a hint about the identity
    // of the end-user the RP wants to authenticate. If present, the OP
    // should check if the authenticated user matches the hint.
    let id_token_hint_subject: Option<String> = if let Some(hint) =
        params.get("id_token_hint").cloned()
    {
        // Best-effort verification: extract the `sub` claim from the hint.
        // Per OIDC Core §3.1.2.1, the OP MAY verify the signature.
        match state.token_service.verify_id_token(&hint).await {
            Ok(subject) => Some(subject),
            Err(e) => {
                tracing::warn!("id_token_hint verification failed (proceeding without hint): {e}");
                // If verification fails, try to extract sub from the JWT payload
                // without verification (the hint is advisory per spec)
                extract_sub_from_jwt_payload(&hint)
            }
        }
    } else {
        None
    };

    // --- authorization_details parameter handling (RFC 9396 RAR) ---
    let authorization_details: Option<serde_json::Value> = params
        .get("authorization_details")
        .and_then(|v| serde_json::from_str(v).ok())
        .filter(|v: &serde_json::Value| v.is_array());
    if let Some(ref details) = authorization_details {
        // Validate each element has a "type" field per RFC 9396 §2
        if let Some(arr) = details.as_array() {
            for item in arr {
                if !item.is_object()
                    || !item.get("type").map_or(false, |t| {
                        t.is_string() && !t.as_str().unwrap_or_default().is_empty()
                    })
                {
                    return Err((
                        redirect_uri.clone(),
                        "invalid_request".to_string(),
                        "Each authorization_detail must have a non-empty 'type' field".to_string(),
                    ));
                }
            }
        }
    }

    // --- resource parameter handling (RFC 8707 Resource Indicators) ---
    // The `resource` parameter can appear multiple times.
    // Each value must be an absolute URI per RFC 8707 §2.
    let resource_params: Vec<String> = params
        .iter()
        .filter(|(k, _)| k.as_str() == "resource")
        .map(|(_, v)| v.clone())
        .collect();
    for res in &resource_params {
        if url::Url::parse(res).is_err() || !res.contains(':') {
            return Err((
                redirect_uri.clone(),
                "invalid_target".to_string(),
                "Each resource must be an absolute URI".to_string(),
            ));
        }
        if res.len() > 512 {
            return Err((
                redirect_uri.clone(),
                "invalid_target".to_string(),
                "Resource URI must not exceed 512 characters".to_string(),
            ));
        }
    }

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

    // Resolve realm if provided, then look up client within that realm
    let realm_id = if let Some(name) = realm_name {
        let realm = match RealmRepo.find_by_name(&mut conn, name).await {
            Ok(Some(r)) => r,
            _ => {
                return Err((
                    redirect_uri.clone(),
                    "invalid_request".to_string(),
                    "Realm not found".to_string(),
                ));
            }
        };
        if !realm.enabled {
            return Err((
                redirect_uri.clone(),
                "access_denied".to_string(),
                "Realm is disabled".to_string(),
            ));
        }
        realm.id
    } else {
        uuid::Uuid::nil()
    };
    let client = if realm_id != uuid::Uuid::nil() {
        match ClientRepo
            .find_by_client_id_in_realm(&mut conn, client_id_str, realm_id)
            .await
        {
            Ok(Some(c)) => c,
            Ok(None) => {
                return Err((
                    redirect_uri.clone(),
                    "invalid_client".to_string(),
                    "Client not found in realm".to_string(),
                ));
            }
            Err(e) => {
                tracing::error!("DB error finding client in authorize: {}", e);
                return Err((
                    redirect_uri.clone(),
                    "server_error".to_string(),
                    "An internal error occurred".to_string(),
                ));
            }
        }
    } else {
        match ClientRepo.find_by_client_id(&mut conn, client_id_str).await {
            Ok(Some(c)) => c,
            Ok(None) => {
                return Err((
                    redirect_uri.clone(),
                    "invalid_client".to_string(),
                    "Client not found".to_string(),
                ));
            }
            Err(e) => {
                tracing::error!("DB error finding client in authorize: {}", e);
                return Err((
                    redirect_uri.clone(),
                    "server_error".to_string(),
                    "An internal error occurred".to_string(),
                ));
            }
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

    if client.pkce_required {
        let ccm = code_challenge_method.as_deref().unwrap_or("");
        if ccm != "S256" {
            return Err((
                redirect_uri.clone(),
                "invalid_request".to_string(),
                "PKCE S256 required".to_string(),
            ));
        }
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
        if cookie_user.is_none()
            && params.get("login_hint").is_none()
            && id_token_hint_subject.is_none()
        {
            return Err((
                redirect_uri.clone(),
                "login_required".to_string(),
                "The Authorization Server requires End-User authentication.".to_string(),
            ));
        }
        // If a valid session cookie, login_hint, or id_token_hint exists, we proceed.
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
                                    let login_url = build_login_url(
                                        &format!(
                                            "/oidc/authorize?{}",
                                            serde_urlencoded::to_string(&params)
                                                .unwrap_or_default()
                                        ),
                                        state_param.as_ref(),
                                    );
                                    return Ok(AuthorizeResult::Redirect(login_url));
                                }
                            }
                        }
                    }
                } else {
                    // No session cookie — if login_hint is provided, proceed.
                    // Otherwise, redirect to login.
                    let login_hint = params.get("login_hint");
                    if login_hint.is_none() {
                        let login_url = build_login_url(
                            &format!(
                                "/oidc/authorize?{}",
                                serde_urlencoded::to_string(&params).unwrap_or_default()
                            ),
                            state_param.as_ref(),
                        );
                        return Ok(AuthorizeResult::Redirect(login_url));
                    }
                }
            }
        }
    }

    // --- User authentication ---
    // Priority: 1) session cookie  2) login_hint  3) id_token_hint  4) redirect to login
    let login_hint = params.get("login_hint").cloned();
    let user = if let Some(ref u) = cookie_user {
        u.clone()
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
    } else if let Some(ref hint_subject) = id_token_hint_subject {
        // Try to look up the user by the subject from id_token_hint
        match uuid::Uuid::parse_str(hint_subject) {
            Ok(user_id) => match UserRepo.find_by_id(&mut conn, user_id).await {
                Ok(Some(u)) if u.enabled => u,
                Ok(Some(_)) => {
                    return Err((
                        redirect_uri.clone(),
                        "access_denied".to_string(),
                        "User account is disabled".to_string(),
                    ));
                }
                Ok(None) => {
                    return Err((
                        redirect_uri.clone(),
                        "access_denied".to_string(),
                        "User not found for id_token_hint subject".to_string(),
                    ));
                }
                Err(e) => {
                    tracing::error!("DB error finding user from id_token_hint: {e}");
                    return Err((
                        redirect_uri.clone(),
                        "server_error".to_string(),
                        "An internal error occurred".to_string(),
                    ));
                }
            },
            Err(_) => {
                // Subject is not a UUID — try email lookup as fallback
                match UserRepo
                    .find_by_email(&mut conn, client.realm_id, hint_subject)
                    .await
                {
                    Ok(Some(u)) => u,
                    Ok(None) | Err(_) => {
                        return Err((
                            redirect_uri.clone(),
                            "access_denied".to_string(),
                            "User not found for id_token_hint subject".to_string(),
                        ));
                    }
                }
            }
        }
    } else {
        // No session cookie or login_hint: redirect to login page with return URL
        let login_url = build_login_url(
            &format!(
                "/oidc/authorize?{}",
                serde_urlencoded::to_string(&params).unwrap_or_default()
            ),
            state_param.as_ref(),
        );
        return Ok(AuthorizeResult::Redirect(login_url));
    };

    if !user.enabled {
        return Err((
            redirect_uri.clone(),
            "access_denied".to_string(),
            "User account is disabled".to_string(),
        ));
    }

    // --- id_token_hint validation (OIDC Core §3.1.2.1) ---
    // If id_token_hint was provided, check if the authenticated user matches the hint.
    // Per OIDC Core §3.1.2.2: If the end-user identified by the hint is not already
    // logged in or is logged in with a different account, the OP SHOULD return
    // login_required or account_selection_required.
    if let Some(ref hint_subject) = id_token_hint_subject {
        let user_subject = user.id.to_string();
        if hint_subject != &user_subject {
            tracing::warn!(
                "id_token_hint subject ({}) does not match authenticated user ({})",
                hint_subject,
                user_subject
            );
            if prompt_values.contains(&"none") {
                return Err((
                    redirect_uri.clone(),
                    "account_selection_required".to_string(),
                    "The end-user identified by the id_token_hint is not the currently authenticated user.".to_string(),
                ));
            }
            // Without prompt=none, redirect to login so the user can select the correct account
            let login_url = build_login_url(
                &format!(
                    "/oidc/authorize?{}",
                    serde_urlencoded::to_string(&params).unwrap_or_default()
                ),
                state_param.as_ref(),
            );
            return Ok(AuthorizeResult::Redirect(login_url));
        }
    }

    // --- acr_values validation and resolution (OIDC Core §3.1.2.1 / §3.1.2.2) ---
    // Determine the authentication method used. For the authorize endpoint,
    // the user authenticated via session cookie or login_hint (password-based).
    let auth_method = "pwd";
    let resolved_acr_amr = match oidc_core::utils::resolve_acr_amr(auth_method, &acr_values) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("ACR resolution failed: {e}");
            // Per OIDC Core §3.1.2.2, if the requested ACR cannot be satisfied,
            // the OP MUST return login_required.
            return Err((
                redirect_uri.clone(),
                "login_required".to_string(),
                format!("Cannot satisfy requested ACR values: {e}"),
            ));
        }
    };

    // --- claims_locales resolution (OIDC Core §5.2) ---
    // Select the best matching locale for the user's claims.
    let resolved_locale = oidc_core::utils::resolve_locale(&user.locale, &claims_locales);

    // --- Generate authorization code ---
    let code_value = generate_auth_code();
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(60); // 60 seconds per plan

    // --- For implicit/hybrid flows, issue tokens directly ---
    // For pure authorization code flow, persist a code.
    let mut redirect_fragments: Vec<String> = Vec::new();

    if response_type.has_code() {
        let auth_code = AuthCode {
            id: generate_uuid_v7(),
            code: code_value.clone(),
            client_id: client.id,
            user_id: user.id,
            realm_id: client.realm_id,
            redirect_uri: redirect_uri.clone(),
            scope: requested_scopes.clone(),
            code_challenge: code_challenge.clone().unwrap_or_default(),
            code_challenge_method: oidc_core::models::CodeChallengeMethod::S256,
            nonce: nonce.clone(),
            used: false,
            claims_request,
            display,
            response_type,
            acr_values,
            claims_locales,
            expires_at,
            response_mode: response_mode_param.clone(),
            authorization_details: authorization_details.clone(),
            resource: resource_params.clone(),
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

        redirect_fragments.push(format!("code={}", urlencoding::encode(&code_value)));
    }

    // Generate sid for session management (used in both implicit/hybrid ID tokens and session_state)
    let implicit_sid = oidc_core::utils::generate_sid().unwrap_or_default();

    if response_type.is_implicit_or_hybrid() {
        let token_svc = match state.token_service_for_realm(client.realm_id).await {
            Ok(svc) => svc,
            Err(e) => {
                tracing::error!("Token service error in authorize: {e}");
                return Err((
                    redirect_uri.clone(),
                    "server_error".to_string(),
                    "An internal error occurred".to_string(),
                ));
            }
        };

        let subject = if client.subject_type == "pairwise" {
            let sector = oidc_core::utils::extract_sector_identifier(
                client.sector_identifier_uri.as_deref(),
                &client.redirect_uris,
            )
            .unwrap_or_default();
            oidc_core::utils::compute_pairwise_sub(
                &user.id.to_string(),
                &sector,
                &state.pairwise_salt,
            )
        } else {
            user.id.to_string()
        };
        let audience = client.client_id.clone();

        if response_type.has_token() {
            let access_token = match token_svc
                .issue_access_token(
                    &subject,
                    &audience,
                    &requested_scopes,
                    None,
                    authorization_details.as_ref(),
                    Some(resource_params.as_slice()),
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("Failed to issue access token in authorize: {e}");
                    return Err((
                        redirect_uri.clone(),
                        "server_error".to_string(),
                        "An internal error occurred".to_string(),
                    ));
                }
            };

            let access_hash = oidc_core::utils::sha2_256_hex(&access_token);
            let session = oidc_core::models::Session {
                id: oidc_core::utils::generate_uuid_v7(),
                sid: implicit_sid.clone(),
                user_id: Some(user.id),
                realm_id: client.realm_id,
                client_id: client.id,
                grant_type: "implicit".to_string(),
                access_token_hash: access_hash,
                refresh_token_hash: None,
                id_token_jti: None,
                scope: requested_scopes.clone(),
                revoked: false,
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(15),
                refresh_expires_at: None,
                created_at: chrono::Utc::now(),
                last_used_at: None,
                token_family_id: None,
                previous_session_id: None,
                rotated_at: None,
                reused_at: None,
                family_revoked: false,
                authorization_details: authorization_details.clone(),
                resource: resource_params.clone(),
            };

            if let Err(e) = oidc_repository::repositories::session_repo::SessionRepo
                .create(&mut conn, &session)
                .await
            {
                tracing::error!("DB error creating implicit session: {e}");
                return Err((
                    redirect_uri.clone(),
                    "server_error".to_string(),
                    "An internal error occurred".to_string(),
                ));
            }

            redirect_fragments.push(format!(
                "access_token={}&token_type=Bearer&expires_in=900",
                urlencoding::encode(&access_token)
            ));
        }

        if response_type.has_id_token() {
            let at_hash = if response_type.has_token() && !redirect_fragments.is_empty() {
                redirect_fragments.iter().find_map(|frag| {
                    frag.strip_prefix("access_token=").map(|at| {
                        oidc_core::utils::compute_at_hash(
                            &urlencoding::decode(at).unwrap_or_default(),
                        )
                    })
                })
            } else {
                None
            };

            let id_token_extra = oidc_core::traits::token_service::IdTokenExtraClaims {
                nonce: nonce.clone(),
                at_hash,
                c_hash: None,
                auth_time: Some(chrono::Utc::now().timestamp()),
                sid: Some(implicit_sid.clone()),
                email: Some(user.email.clone()),
                email_verified: Some(user.email_verified),
                name: user.username.clone(),
                given_name: user.given_name.clone(),
                family_name: user.family_name.clone(),
                middle_name: user.middle_name.clone(),
                nickname: user.nickname.clone(),
                preferred_username: user.preferred_username.clone(),
                profile: user.profile.clone(),
                picture: user.picture.clone(),
                website: user.website.clone(),
                gender: user.gender.clone(),
                birthdate: user.birthdate.clone(),
                zoneinfo: user.zoneinfo.clone(),
                locale: Some(resolved_locale.clone()),
                phone_number: user.phone_number.clone(),
                phone_number_verified: user.phone_number_verified,
                updated_at: Some(user.updated_at.timestamp()),
                acr: Some(resolved_acr_amr.acr.clone()),
                amr: Some(resolved_acr_amr.amr.clone()),
            };

            let id_token = match token_svc
                .issue_id_token(&subject, &audience, Some(id_token_extra))
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("Failed to issue ID token in authorize: {e}");
                    return Err((
                        redirect_uri.clone(),
                        "server_error".to_string(),
                        "An internal error occurred".to_string(),
                    ));
                }
            };

            // Optionally encrypt the ID token if the client has JWE configured
            let id_token = match crate::flows::maybe_encrypt_id_token(&state, &id_token, &client) {
                Ok(encrypted) => encrypted,
                Err(e) => {
                    tracing::error!("Failed to encrypt ID token in authorize: {e}");
                    return Err((
                        redirect_uri.clone(),
                        "server_error".to_string(),
                        "An internal error occurred".to_string(),
                    ));
                }
            };

            redirect_fragments.push(format!("id_token={}", urlencoding::encode(&id_token)));
        }
    }

    if let Some(s) = state_param {
        redirect_fragments.push(format!("state={}", urlencoding::encode(&s)));
    }

    // --- session_state (OIDC Session Management §3) ---
    // Compute session_state = SHA256(client_id + " " + sid + " " + origin) base64url
    // The sid comes from the session cookie (for SSO) or is derived from the session.
    // For the authorize endpoint, we use the cookie session's sid if available,
    // otherwise we generate a new one for the response.
    //
    // Note: The "OP browser session ID" in the spec maps to our `sid` field.
    // The RP will compare this session_state with the one computed by the
    // check session iframe to detect session changes.
    if let Some(op_browser_session_id) = cookie_session_id.as_ref() {
        // We have a session cookie — look up the sid from the session
        // For now, use the session_id from the cookie as the op_browser_session_id
        // (the actual sid is stored in the session record in the DB, but for
        // session_state computation, we use the same value the check_session
        // iframe will use — which is the cookie's session_id part)
        if let Some(origin) = oidc_core::utils::extract_origin(&redirect_uri) {
            let session_state = oidc_core::utils::compute_session_state(
                client_id_str,
                op_browser_session_id,
                &origin,
            );
            redirect_fragments.push(format!(
                "session_state={}",
                urlencoding::encode(&session_state)
            ));
        }
    }

    // --- Build the response based on response_mode ---
    if is_jarm {
        // JARM: wrap all response parameters in a JWT signed by the OP
        let jarm_jwt = match issue_jarm_jwt(
            &state,
            client.realm_id,
            &state.issuer,
            client_id_str,
            &redirect_fragments,
        )
        .await
        {
            Ok(jwt) => jwt,
            Err(e) => {
                tracing::error!("Failed to issue JARM JWT: {e}");
                return Err((
                    redirect_uri.clone(),
                    "server_error".to_string(),
                    "An internal error occurred".to_string(),
                ));
            }
        };

        match effective_mode {
            ResponseMode::Query => {
                let redirect = format!(
                    "{}?response={}",
                    redirect_uri,
                    urlencoding::encode(&jarm_jwt)
                );
                Ok(AuthorizeResult::Redirect(redirect))
            }
            ResponseMode::Fragment => {
                let redirect = format!(
                    "{}#response={}",
                    redirect_uri,
                    urlencoding::encode(&jarm_jwt)
                );
                Ok(AuthorizeResult::Redirect(redirect))
            }
            ResponseMode::FormPost => {
                let html = render_form_post_html(&redirect_uri, "response", &jarm_jwt);
                Ok(AuthorizeResult::FormPost { html })
            }
        }
    } else {
        // Non-JARM: deliver parameters directly
        match effective_mode {
            ResponseMode::Query => {
                let redirect = format!("{}?{}", redirect_uri, redirect_fragments.join("&"));
                Ok(AuthorizeResult::Redirect(redirect))
            }
            ResponseMode::Fragment => {
                let redirect = format!("{}#{}", redirect_uri, redirect_fragments.join("&"));
                Ok(AuthorizeResult::Redirect(redirect))
            }
            ResponseMode::FormPost => {
                // Build hidden input fields from the response parameters
                let fields: Vec<(String, String)> = redirect_fragments
                    .iter()
                    .filter_map(|frag| {
                        let mut parts = frag.splitn(2, '=');
                        let name = parts.next()?;
                        let value = parts.next()?;
                        Some((
                            name.to_string(),
                            urlencoding::decode(value).unwrap_or_default().to_string(),
                        ))
                    })
                    .collect();
                let html = render_form_post_multi_html(&redirect_uri, &fields);
                Ok(AuthorizeResult::FormPost { html })
            }
        }
    }
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

// ---------------------------------------------------------------------------
// JARM JWT issuance (RFC 9101)
// ---------------------------------------------------------------------------

/// Issue a JARM JWT containing all authorization response parameters.
///
/// The JWT is signed by the OP using its signing key (RS256 preferred for
/// broadest compatibility). Claims include:
/// - All response parameters (code, access_token, id_token, state, etc.)
/// - `iss` = OP issuer
/// - `aud` = client_id
/// - `exp` = now + 5 minutes
/// - `iat` = now
async fn issue_jarm_jwt(
    state: &OidcState,
    realm_id: uuid::Uuid,
    issuer: &str,
    client_id: &str,
    response_params: &[String],
) -> Result<String, oidc_core::OidcError> {
    let token_svc = state.token_service_for_realm(realm_id).await?;
    let now = chrono::Utc::now().timestamp();

    // Build claims from response parameters
    let mut claims = serde_json::Map::new();
    claims.insert(
        "iss".to_string(),
        serde_json::Value::String(issuer.to_string()),
    );
    claims.insert(
        "aud".to_string(),
        serde_json::Value::String(client_id.to_string()),
    );
    claims.insert(
        "exp".to_string(),
        serde_json::Value::Number((now + 300).into()),
    );
    claims.insert("iat".to_string(), serde_json::Value::Number(now.into()));

    // Parse each response parameter (key=value) and add as claim
    for param in response_params {
        if let Some((key, value)) = param.split_once('=') {
            let decoded_value = urlencoding::decode(value).unwrap_or_default();
            claims.insert(
                key.to_string(),
                serde_json::Value::String(decoded_value.to_string()),
            );
        }
    }

    let claims_value = serde_json::Value::Object(claims);
    token_svc.encode_jwt(&claims_value)
}

// ---------------------------------------------------------------------------
// form_post HTML rendering
// ---------------------------------------------------------------------------

/// Render an auto-submitting HTML form with a single hidden field.
/// Used for JARM `form_post.jwt` responses.
fn render_form_post_html(redirect_uri: &str, param_name: &str, value: &str) -> String {
    let escaped_uri = html_escape(redirect_uri);
    let escaped_name = html_escape(param_name);
    let escaped_value = html_escape(value);
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Redirecting...</title></head>
<body>
<form method="POST" action="{escaped_uri}">
<input type="hidden" name="{escaped_name}" value="{escaped_value}" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>"#
    )
}

/// Render an auto-submitting HTML form with multiple hidden fields.
/// Used for non-JARM `form_post` responses.
fn render_form_post_multi_html(redirect_uri: &str, fields: &[(String, String)]) -> String {
    let escaped_uri = html_escape(redirect_uri);
    let mut inputs = String::new();
    for (name, value) in fields {
        let escaped_name = html_escape(name);
        let escaped_value = html_escape(value);
        inputs.push_str(&format!(
            r#"<input type="hidden" name="{escaped_name}" value="{escaped_value}" />
"#
        ));
    }
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Redirecting...</title></head>
<body>
<form method="POST" action="{escaped_uri}">
{inputs}</form>
<script>document.forms[0].submit();</script>
</body>
</html>"#
    )
}

/// Minimal HTML attribute/element escaping to prevent XSS in form_post pages.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ---------------------------------------------------------------------------
// Error URL builder
// ---------------------------------------------------------------------------

/// Build an error redirect URL with error, error_description, and state.
/// For form_post mode this would need a different approach, but errors
/// are always delivered via query string per spec.
fn build_error_url(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
    _mode: ResponseMode,
) -> String {
    let mut url = format!(
        "{}?error={}&error_description={}",
        redirect_uri,
        urlencoding::encode(error),
        urlencoding::encode(description)
    );
    if let Some(s) = state {
        url.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    url
}

// ---------------------------------------------------------------------------
// JWT payload extraction (for id_token_hint advisory parsing)
// ---------------------------------------------------------------------------

/// Extract the `sub` claim from a JWT payload without signature verification.
///
/// This is used for the `id_token_hint` parameter, which is advisory per
/// OIDC Core §3.1.2.1. If the token cannot be verified (e.g., expired,
/// wrong audience), we still want to extract the subject to check if the
/// currently authenticated user matches the hint.
fn extract_sub_from_jwt_payload(jwt: &str) -> Option<String> {
    // JWT format: header.payload.signature
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
