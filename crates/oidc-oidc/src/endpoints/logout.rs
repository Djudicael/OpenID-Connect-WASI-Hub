//! RP-Initiated Logout endpoint (OIDC Session Management).

use axum::extract::Query;
use axum::http::header::SET_COOKIE;
use axum::response::{IntoResponse, Redirect, Response};
use std::collections::HashMap;

use oidc_core::traits::TokenService;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;

use crate::session_cookie;
use crate::state::OidcState;

/// Logout endpoint handler.
/// Validates id_token_hint, validates post_logout_redirect_uri against client's registered URIs,
/// revokes session, clears the session cookie, and redirects.
pub async fn logout_handler(
    state: OidcState,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let post_logout_redirect_uri = params.get("post_logout_redirect_uri").cloned();
    let state_param = params.get("state").cloned();
    let client_id_param = params.get("client_id").cloned();

    // If id_token_hint is provided, validate it and revoke the session
    if let Some(id_token_hint) = params.get("id_token_hint") {
        if let Ok(mut conn) = state.connect().await {
            // Best-effort transaction: begin, revoke, commit (ignore errors)
            if conn.begin().await.is_ok() {
                if let Ok(subject) = state.token_service.verify_id_token(id_token_hint).await {
                    if let Ok(user_id) = subject.parse::<uuid::Uuid>() {
                        let _ = SessionRepo.revoke_by_user_id(&mut conn, user_id).await;
                    }
                }
                let _ = conn.commit().await;
            }
        }
    }

    // Validate post_logout_redirect_uri against client's registered URIs
    let validated_uri = validate_redirect_uri(
        &state,
        post_logout_redirect_uri.as_deref(),
        client_id_param.as_deref(),
    )
    .await;

    let redirect = build_redirect(validated_uri, state_param);
    let mut response = redirect.into_response();

    // Clear the session cookie
    let clear_header = session_cookie::clear_session_cookie_header();
    if let Ok(value) = clear_header.parse() {
        response.headers_mut().insert(SET_COOKIE, value);
    }

    response
}

/// Validate the post_logout_redirect_uri against the client's registered redirect URIs.
/// Returns the URI if valid, None if invalid.
async fn validate_redirect_uri(
    state: &OidcState,
    uri: Option<&str>,
    client_id: Option<&str>,
) -> Option<String> {
    let uri = uri?;
    let client_id = client_id?;

    let mut conn = state.connect().await.ok()?;
    let client = ClientRepo
        .find_by_client_id(&mut conn, client_id)
        .await
        .ok()??;

    // Check against registered redirect URIs
    if client.redirect_uris.contains(&uri.to_string()) {
        return Some(uri.to_string());
    }

    None
}

fn build_redirect(uri: Option<String>, state: Option<String>) -> Redirect {
    let redirect = match uri {
        Some(mut u) => {
            if let Some(s) = state {
                u.push_str(&format!("?state={}", urlencoding::encode(&s)));
            }
            u
        }
        None => "/".to_string(),
    };
    Redirect::temporary(&redirect)
}
