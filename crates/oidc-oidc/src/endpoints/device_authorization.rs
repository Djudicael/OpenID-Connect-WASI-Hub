//! Device Authorization Grant endpoints (RFC 8628).
//!
//! Implements:
//! - POST /oidc/device/authorize — Device Authorization Request (§3.1)
//! - GET  /oidc/device           — User verification page (§3.3)
//! - POST /oidc/device/confirm   — User confirms authorization

use axum::Json;
use axum::extract::{Form, Query, State};
use axum::response::Html;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

use oidc_core::OidcError;
use oidc_core::models::DeviceCode;
use oidc_core::utils::{generate_opaque_token, generate_user_code, generate_uuid_v7, html_escape, sha2_256_hex};
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::device_code_repo::DeviceCodeRepo;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::session_repo::SessionRepo;

use crate::errors::{OidcErrorResponse, from_oidc_error};
use crate::session_cookie;
use crate::state::OidcState;
use crate::tokens::JwtTokenService;

// ---------------------------------------------------------------------------
// §3.1 Device Authorization Request
// ---------------------------------------------------------------------------

/// Device Authorization Request handler (RFC 8628 §3.1).
///
/// Accepts `client_id`, optional `client_secret`, and optional `scope`.
/// Authenticates the client, generates a device_code and user_code,
/// stores the device_code as a SHA-256 hash, and returns the standard
/// device authorization response.
pub async fn device_authorization_handler(
    state: OidcState,
    headers: axum::http::HeaderMap,
    mut params: HashMap<String, String>,
) -> Result<Json<Value>, OidcError> {
    // Extract client_secret_basic from Authorization header if present
    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(credentials) = auth_str.strip_prefix("Basic ") {
                use base64::{Engine, engine::general_purpose::STANDARD};
                if let Ok(decoded) = STANDARD.decode(credentials) {
                    if let Ok(cred_str) = String::from_utf8(decoded) {
                        if let Some((client_id, client_secret)) = cred_str.split_once(':') {
                            params
                                .entry("client_id".to_string())
                                .or_insert_with(|| client_id.to_string());
                            params
                                .entry("client_secret".to_string())
                                .or_insert_with(|| client_secret.to_string());
                        }
                    }
                }
            }
        }
    }

    // ── Client authentication ──────────────────────────────────────────
    let client = authenticate_client_device(&state, &params).await?;

    // ── Resolve realm ──────────────────────────────────────────────────
    let realm_id = if client.realm_id.is_nil() {
        if let Some(realm_name) = params.get("realm") {
            let mut conn = state.connect().await?;
            RealmRepo
                .find_by_name(&mut conn, realm_name)
                .await?
                .map(|r| r.id)
                .unwrap_or_else(uuid::Uuid::nil)
        } else {
            uuid::Uuid::nil()
        }
    } else {
        client.realm_id
    };

    // ── Generate codes ─────────────────────────────────────────────────
    let device_code_value = generate_opaque_token()?;
    let device_code_hash = sha2_256_hex(&device_code_value);
    let user_code = generate_user_code()?;

    let verification_uri = format!("{}/oidc/device", state.issuer);
    let verification_uri_complete = format!("{}?user_code={}", verification_uri, user_code);

    // Parse requested scopes
    let scope_str = params.get("scope").cloned().unwrap_or_default();
    let scopes: Vec<String> = if scope_str.is_empty() {
        vec!["openid".to_string()]
    } else {
        scope_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect()
    };

    // Validate requested scopes against client's allowed scopes
    for s in &scopes {
        if !client.allowed_scopes.contains(s) {
            return Err(OidcError::InvalidScope(format!(
                "Client not authorized for scope: {}",
                s
            )));
        }
    }

    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(900); // 15 minutes

    let dc = DeviceCode {
        id: generate_uuid_v7(),
        client_id: client.id,
        realm_id,
        device_code: device_code_hash,
        user_code: user_code.clone(),
        verification_uri: verification_uri.clone(),
        verification_uri_complete: Some(verification_uri_complete.clone()),
        expires_at,
        interval: 5,
        used: false,
        authorized: false,
        user_id: None,
        scope: scopes,
        created_at: now,
    };

    let mut conn = state.connect().await?;
    DeviceCodeRepo.create(&mut conn, &dc).await?;

    Ok(Json(json!({
        "device_code": device_code_value,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete,
        "expires_in": 900,
        "interval": 5,
    })))
}

/// Authenticate the client at the device authorization endpoint.
///
/// Supports `private_key_jwt` and `client_secret_basic`/`client_secret_post`.
async fn authenticate_client_device(
    state: &OidcState,
    params: &HashMap<String, String>,
) -> Result<oidc_core::models::Client, OidcError> {
    if let Some(assertion) = params.get("client_assertion") {
        let assertion_type = params
            .get("client_assertion_type")
            .ok_or(OidcError::InvalidClient)?;
        if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            return Err(OidcError::InvalidClient);
        }

        let (_, claims, _, _) = JwtTokenService::parse_client_assertion_unverified(assertion)?;
        let client_id = claims.iss;

        let mut conn = state.connect().await?;
        let client = ClientRepo
            .find_by_client_id(&mut conn, &client_id)
            .await?
            .ok_or(OidcError::InvalidClient)?;

        if !client.enabled {
            return Err(OidcError::InvalidClient);
        }

        match client.token_endpoint_auth_method.as_str() {
            "private_key_jwt" => {
                let jwks = client.jwks.as_ref().ok_or_else(|| {
                    OidcError::InvalidClientAssertion("client has no jwks".into())
                })?;

                let endpoint = format!("{}/oidc/device/authorize", state.issuer);
                let now = chrono::Utc::now().timestamp();
                JwtTokenService::verify_client_assertion(
                    assertion, jwks, &endpoint, &client_id, now,
                )?;
            }
            "client_secret_jwt" => {
                let encrypted_secret =
                    client.client_secret_encrypted.as_ref().ok_or_else(|| {
                        OidcError::InvalidClientAssertion(
                            "client has no encrypted secret for client_secret_jwt".into(),
                        )
                    })?;

                let client_secret_bytes = state
                    .decrypt_client_encryption_key(encrypted_secret)
                    .map_err(|_| {
                        OidcError::InvalidClientAssertion("failed to decrypt client secret".into())
                    })?;
                let client_secret = String::from_utf8(client_secret_bytes).map_err(|_| {
                    OidcError::InvalidClientAssertion("invalid client secret encoding".into())
                })?;

                let endpoint = format!("{}/oidc/device/authorize", state.issuer);
                let now = chrono::Utc::now().timestamp();
                crate::tokens::jwt_service::verify_client_secret_jwt(
                    assertion,
                    &client_secret,
                    &endpoint,
                    &client_id,
                    now,
                )?;
            }
            _ => {
                return Err(OidcError::InvalidClient);
            }
        }

        return Ok(client);
    }

    // --- client_secret_basic / client_secret_post ---
    let client_id = params
        .get("client_id")
        .ok_or(OidcError::InvalidClient)?
        .clone();
    let client_secret = params.get("client_secret").cloned();

    let mut conn = state.connect().await?;
    let client = ClientRepo
        .find_by_client_id(&mut conn, &client_id)
        .await?
        .ok_or(OidcError::InvalidClient)?;

    if !client.enabled {
        return Err(OidcError::InvalidClient);
    }

    if let Some(ref hash) = client.client_secret_hash {
        let secret = client_secret.as_ref().ok_or(OidcError::InvalidClient)?;
        if !state.hasher.verify(secret, hash)? {
            return Err(OidcError::InvalidClient);
        }
    }

    Ok(client)
}

// ---------------------------------------------------------------------------
// §3.3 User Verification Page
// ---------------------------------------------------------------------------

/// Query parameters for the device verification page.
#[derive(Debug, Deserialize, Default)]
pub struct DeviceVerifyParams {
    pub user_code: Option<String>,
}

/// Device verification page handler (RFC 8628 §3.3).
///
/// Renders an HTML page where the user can enter or confirm the user_code.
/// If `user_code` is provided as a query parameter, it is pre-filled.
pub async fn device_authorization_verify_handler(
    State(_state): State<OidcState>,
    Query(params): Query<DeviceVerifyParams>,
) -> Html<String> {
    let prefill = params.user_code.unwrap_or_default();
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Authorization</title>
    <style>
        :root {{ --primary: #2563eb; --bg: #f8fafc; }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex; align-items: center; justify-content: center;
            min-height: 100vh; margin: 0; background: var(--bg);
        }}
        .box {{
            background: #fff; padding: 2.5rem; border-radius: 12px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.08); width: 100%; max-width: 24rem;
            text-align: center;
        }}
        h1 {{ font-size: 1.5rem; font-weight: 600; margin: 0 0 0.25rem 0; color: #111; }}
        .subtitle {{ color: #6b7280; margin-bottom: 1.5rem; font-size: 0.875rem; }}
        .form {{ display: flex; flex-direction: column; gap: 1rem; text-align: left; }}
        label {{ display: block; font-size: 0.875rem; font-weight: 500; margin-bottom: 0.25rem; color: #374151; }}
        input {{
            width: 100%; padding: 0.625rem; border: 1px solid #d1d5db;
            border-radius: 6px; font-size: 1.125rem; background: #fff; color: #111;
            text-align: center; letter-spacing: 0.1em; text-transform: uppercase;
        }}
        input:focus {{ outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }}
        button[type="submit"] {{
            width: 100%; padding: 0.75rem; font-size: 1rem; font-weight: 500;
            background: var(--primary); color: #fff; border: none; border-radius: 6px;
            cursor: pointer; margin-top: 0.5rem;
        }}
        button[type="submit"]:hover {{ opacity: 0.92; }}
        .error {{
            color: #dc2626; font-size: 0.875rem; margin-top: 0.75rem;
            padding: 0.75rem; background: #fef2f2; border-radius: 6px; display: none;
        }}
        .footer {{ margin-top: 1.25rem; font-size: 0.75rem; color: #9ca3af; }}
    </style>
</head>
<body>
    <div class="box">
        <h1>Device Authorization</h1>
        <p class="subtitle">Enter the code displayed on your device</p>
        <form class="form" id="verifyForm">
            <div>
                <label for="user_code">Code</label>
                <input id="user_code" name="user_code" type="text" placeholder="XXXX-XXXX" required
                       maxlength="9" value="{}" {} />
            </div>
            <button type="submit">Authorize</button>
            <div class="error" id="errorBox"></div>
        </form>
        <div class="footer">Powered by OpenID Connect Hub</div>
    </div>
    <script>
        (function() {{
            const form = document.getElementById('verifyForm');
            const errorBox = document.getElementById('errorBox');
            const input = document.getElementById('user_code');

            // Auto-format: insert dash after 4 chars
            input.addEventListener('input', function() {{
                let v = input.value.replace(/[^A-Za-z]/g, '').toUpperCase();
                if (v.length > 4) v = v.slice(0, 4) + '-' + v.slice(4, 8);
                input.value = v;
            }});

            form.addEventListener('submit', async function(e) {{
                e.preventDefault();
                errorBox.style.display = 'none';

                try {{
                    const res = await fetch('/oidc/device/confirm', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
                        body: 'user_code=' + encodeURIComponent(input.value)
                    }});
                    const data = await res.json();
                    if (!res.ok) {{
                        throw new Error(data.error_description || data.error || 'Authorization failed');
                    }}
                    // Show success
                    document.querySelector('.box').innerHTML = '<h1>Authorized!</h1><p class="subtitle">Your device has been authorized. You may close this page.</p><div class="footer">Powered by OpenID Connect Hub</div>';
                }} catch (err) {{
                    errorBox.textContent = err.message;
                    errorBox.style.display = 'block';
                }}
            }});
        }})();
    </script>
</body>
</html>"##,
        html_escape(&prefill),
        if prefill.is_empty() { "autofocus" } else { "" }
    );
    Html(html)
}

// ---------------------------------------------------------------------------
// §3.3 User Confirmation
// ---------------------------------------------------------------------------

/// Form body for the device confirmation.
#[derive(Debug, Deserialize)]
pub struct DeviceConfirmRequest {
    pub user_code: String,
}

/// Device authorization confirm handler.
///
/// The user submits the user_code. We look it up, verify the session,
/// and mark the device code as authorized.
pub async fn device_authorization_confirm_handler(
    State(state): State<OidcState>,
    headers: axum::http::HeaderMap,
    Form(req): Form<DeviceConfirmRequest>,
) -> Result<Json<Value>, OidcErrorResponse> {
    let user_code = req.user_code.trim().to_uppercase();

    // ── Authenticate the user via session cookie ──────────────────────
    let encryption_key = state
        .decode_encryption_key()
        .map_err(|e| from_oidc_error(&e))?;
    let session_id = session_cookie::extract_session_id_from_headers(&headers, &encryption_key)
        .ok_or_else(|| {
            from_oidc_error(&OidcError::AuthenticationFailed("No active session".into()))
        })?;

    let session_uuid = uuid::Uuid::parse_str(&session_id)
        .map_err(|e| from_oidc_error(&OidcError::Internal(format!("Invalid session ID: {e}"))))?;

    let mut conn = state.connect().await.map_err(|e| from_oidc_error(&e))?;

    // Find the session to get the user
    let session = SessionRepo
        .find_by_id(&mut conn, session_uuid)
        .await
        .map_err(|e| from_oidc_error(&e))?
        .ok_or_else(|| {
            from_oidc_error(&OidcError::AuthenticationFailed("Session not found".into()))
        })?;

    let user_id = session.user_id.ok_or_else(|| {
        from_oidc_error(&OidcError::AuthenticationFailed(
            "No user in session".into(),
        ))
    })?;

    // ── Find the device code by user_code ─────────────────────────────
    let dc = DeviceCodeRepo
        .find_by_user_code(&mut conn, &user_code)
        .await
        .map_err(|e| from_oidc_error(&e))?
        .ok_or_else(|| {
            from_oidc_error(&OidcError::NotFound(
                "Device code not found or expired".into(),
            ))
        })?;

    // ── Mark as authorized ────────────────────────────────────────────
    DeviceCodeRepo
        .mark_authorized(&mut conn, dc.id, user_id)
        .await
        .map_err(|e| from_oidc_error(&e))?;

    Ok(Json(json!({
        "status": "authorized",
        "message": "Device has been authorized successfully.",
    })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------


