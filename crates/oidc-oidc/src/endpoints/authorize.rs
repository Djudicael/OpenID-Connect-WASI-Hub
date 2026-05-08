use axum::extract::Query;
use axum::response::Redirect;
use std::collections::HashMap;

use oidc_core::models::AuthCode;
use oidc_core::OidcError;
use oidc_core::utils::generate_uuid_v7;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::user_repo::UserRepo;

use crate::state::OidcState;

/// Authorization endpoint handler.
/// Validates the request, authenticates the user (via login_hint for now),
/// generates an authorization code, and redirects back to the client.
pub async fn authorize_handler(
    state: OidcState,
    Query(params): Query<HashMap<String, String>>,
) -> Redirect {
    match authorize_inner(state, params).await {
        Ok(redirect_uri) => Redirect::temporary(&redirect_uri),
        Err(e) => {
            // Best-effort error redirect; if we can't parse redirect_uri, return a generic error
            tracing::warn!("authorize failed: {}", e);
            Redirect::temporary("/oidc/error")
        }
    }
}

async fn authorize_inner(
    state: OidcState,
    params: HashMap<String, String>,
) -> Result<String, OidcError> {
    // --- Parameter extraction ---
    let response_type = params.get("response_type").ok_or(OidcError::InvalidRequest)?;
    if response_type != "code" {
        return Err(OidcError::InvalidRequest);
    }

    let client_id_str = params.get("client_id").ok_or(OidcError::InvalidRequest)?;
    let redirect_uri = params.get("redirect_uri").ok_or(OidcError::InvalidRequest)?;
    let scope = params.get("scope").unwrap_or(&"openid".to_string()).clone();
    let state_param = params.get("state").cloned();
    let code_challenge = params
        .get("code_challenge")
        .ok_or(OidcError::InvalidRequest)?
        .clone();
    let code_challenge_method = params
        .get("code_challenge_method")
        .unwrap_or(&"plain".to_string())
        .clone();

    // --- Client validation ---
    let mut conn = state.connect().await?;
    let client = ClientRepo
        .find_by_client_id(&mut conn, client_id_str)
        .await?
        .ok_or(OidcError::InvalidClient)?;

    if !client.enabled {
        return Err(OidcError::InvalidClient);
    }

    if !client.redirect_uris.contains(redirect_uri) {
        return Err(OidcError::InvalidRequest);
    }

    if client.pkce_required && code_challenge_method != "S256" {
        return Err(OidcError::InvalidRequest);
    }

    // --- User authentication (login_hint for now) ---
    // TODO: Replace with proper session/cookie-based authentication.
    let login_hint = params.get("login_hint").cloned();
    let user = if let Some(email) = login_hint {
        UserRepo
            .find_by_email(&mut conn, client.realm_id, &email)
            .await?
            .ok_or(OidcError::AuthenticationFailed("user not found".into()))?
    } else {
        return Err(OidcError::AuthenticationFailed(
            "login required".into(),
        ));
    };

    if !user.enabled {
        return Err(OidcError::AuthenticationFailed("user disabled".into()));
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
        code_challenge,
        code_challenge_method,
        used: false,
        expires_at,
    };

    oidc_repository::repositories::auth_code_repo::AuthCodeRepo
        .create(&mut conn, &auth_code)
        .await?;

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
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(data)
}
