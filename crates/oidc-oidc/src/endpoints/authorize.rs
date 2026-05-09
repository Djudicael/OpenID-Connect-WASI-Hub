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
pub async fn authorize_handler(
    state: OidcState,
    Query(params): Query<HashMap<String, String>>,
) -> Redirect {
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

    let code_challenge_method = params
        .get("code_challenge_method")
        .unwrap_or(&"plain".to_string())
        .clone();

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
    let expires_at = chrono::Utc::now().timestamp() + 600; // 10 minutes

    let auth_code = AuthCode {
        id: generate_uuid_v7(),
        code: code_value.clone(),
        client_id: client.id,
        user_id: user.id,
        realm_id: client.realm_id,
        redirect_uri: redirect_uri.clone(),
        scope: scope.split(' ').map(|s| s.to_string()).collect(),
        code_challenge: code_challenge.clone(),
        code_challenge_method,
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
