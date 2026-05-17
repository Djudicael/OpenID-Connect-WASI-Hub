//! RP-Initiated Logout endpoint (OIDC Session Management §5)
//! with Front-Channel Logout (§6) and Back-Channel Logout (§7) support.

use axum::extract::Query;
use axum::http::header::SET_COOKIE;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;

use oidc_core::traits::TokenService;
use oidc_repository::repositories::client_repo::ClientRepo;
use oidc_repository::repositories::session_repo::SessionRepo;

use crate::endpoints::session::backchannel_logout::perform_backchannel_logout;
use crate::endpoints::session::frontchannel_logout::build_frontchannel_logout_html;
use crate::session_cookie;
use crate::state::OidcState;

/// Logout endpoint handler.
///
/// Supports:
/// - **RP-Initiated Logout** (Session §5): Validates `id_token_hint`, revokes session,
///   clears cookie, redirects to `post_logout_redirect_uri`.
/// - **Front-Channel Logout** (Front-Channel §6): If any client has a `frontchannel_logout_uri`,
///   returns an HTML page with iframes to each RP's logout URI.
/// - **Back-Channel Logout** (Back-Channel §7): Sends signed logout tokens via HTTP POST
///   to each client's `backchannel_logout_uri`.
///
/// The `post_logout_redirect_uri` is validated against the client's registered
/// `post_logout_redirect_uris` (preferred) or `redirect_uris` (fallback).
pub async fn logout_handler(
    state: OidcState,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let post_logout_redirect_uri = params.get("post_logout_redirect_uri").cloned();
    let state_param = params.get("state").cloned();
    let client_id_param = params.get("client_id").cloned();

    // Extract user_id and sid from id_token_hint if provided
    let mut user_id_opt: Option<uuid::Uuid> = None;
    let mut sid_opt: Option<String> = None;
    let mut logout_client_ids: Vec<uuid::Uuid> = Vec::new();

    if let Some(id_token_hint) = params.get("id_token_hint") {
        if let Ok(mut conn) = state.connect().await {
            // Best-effort transaction: begin, revoke, commit (ignore errors)
            if conn.begin().await.is_ok() {
                if let Ok(subject) = state.token_service.verify_id_token(id_token_hint).await {
                    if let Ok(user_id) = subject.parse::<uuid::Uuid>() {
                        user_id_opt = Some(user_id);

                        // Find active sessions for this user to get sid and client info
                        if let Ok(sessions) =
                            SessionRepo.find_active_by_user_id(&mut conn, user_id).await
                        {
                            for session in &sessions {
                                if sid_opt.is_none() {
                                    sid_opt = Some(session.sid.clone());
                                }
                                if !logout_client_ids.contains(&session.client_id) {
                                    logout_client_ids.push(session.client_id);
                                }
                            }
                        }

                        // Revoke all sessions for the user
                        let _ = SessionRepo.revoke_by_user_id(&mut conn, user_id).await;
                    }
                }
                let _ = conn.commit().await;
            }
        }
    }

    // Also try to extract session from cookie if id_token_hint wasn't provided
    if user_id_opt.is_none() {
        if let Ok(key) = state.decode_encryption_key() {
            if let Some(session_id_str) =
                session_cookie::extract_session_id_from_headers(&headers, &key)
            {
                if let Ok(sid_uuid) = uuid::Uuid::parse_str(&session_id_str) {
                    if let Ok(mut conn) = state.connect().await {
                        if let Ok(Some(session)) = SessionRepo.find_by_id(&mut conn, sid_uuid).await
                        {
                            if !session.revoked {
                                user_id_opt = session.user_id;
                                sid_opt = Some(session.sid.clone());
                                if !logout_client_ids.contains(&session.client_id) {
                                    logout_client_ids.push(session.client_id);
                                }

                                // Find all sessions for this user (for multi-client logout)
                                if let Some(uid) = session.user_id {
                                    if let Ok(all_sessions) =
                                        SessionRepo.find_active_by_user_id(&mut conn, uid).await
                                    {
                                        for s in &all_sessions {
                                            if !logout_client_ids.contains(&s.client_id) {
                                                logout_client_ids.push(s.client_id);
                                            }
                                        }
                                    }
                                    let _ = SessionRepo.revoke_by_user_id(&mut conn, uid).await;
                                } else {
                                    let _ = SessionRepo.revoke(&mut conn, session.id).await;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // --- Collect clients for front-channel and back-channel logout ---
    let mut frontchannel_clients: Vec<oidc_core::models::Client> = Vec::new();
    let mut backchannel_clients: Vec<oidc_core::models::Client> = Vec::new();

    if !logout_client_ids.is_empty() {
        if let Ok(mut conn) = state.connect().await {
            for client_db_id in &logout_client_ids {
                if let Ok(Some(client)) = ClientRepo.find_by_id(&mut conn, *client_db_id).await {
                    if client.frontchannel_logout_uri.is_some() {
                        frontchannel_clients.push(client.clone());
                    }
                    if client.backchannel_logout_uri.is_some() {
                        backchannel_clients.push(client.clone());
                    }
                }
            }
        }
    }

    // --- Back-Channel Logout (fire-and-forget) ---
    if !backchannel_clients.is_empty() {
        if let (Some(user_id), Some(sid)) = (&user_id_opt, &sid_opt) {
            let subject = user_id.to_string();
            let bc_refs: Vec<&oidc_core::models::Client> = backchannel_clients.iter().collect();
            // Fire-and-forget: log results but don't block the response
            let issuer = state.issuer.clone();
            let token_svc = state.token_service.clone();
            // We spawn the backchannel logout as a best-effort async operation
            // In WASI P2, we can't spawn threads, so we run it inline but don't
            // let failures block the response
            let results =
                perform_backchannel_logout(&token_svc, &issuer, &subject, sid, &bc_refs).await;
            for result in &results {
                if result.success {
                    tracing::info!(
                        "Back-channel logout delivered to {} ({})",
                        result.client_id,
                        result.uri
                    );
                } else {
                    tracing::warn!(
                        "Back-channel logout FAILED for {} ({}): {:?}",
                        result.client_id,
                        result.uri,
                        result.error
                    );
                }
            }
        }
    }

    let validated_uri = validate_redirect_uri(
        &state,
        post_logout_redirect_uri.as_deref(),
        client_id_param.as_deref(),
    )
    .await;

    // --- Front-Channel Logout ---
    // If any clients have frontchannel_logout_uri, return the HTML page with iframes
    if !frontchannel_clients.is_empty() {
        if let (Some(_user_id), Some(sid)) = (&user_id_opt, &sid_opt) {
            let fc_refs: Vec<&oidc_core::models::Client> = frontchannel_clients.iter().collect();
            let mut response = build_frontchannel_logout_html(
                &state.issuer,
                sid,
                &fc_refs,
                validated_uri.as_deref(),
                state_param.as_deref(),
            );

            // Clear the session cookie
            let clear_header = session_cookie::clear_session_cookie_header();
            if let Ok(value) = clear_header.parse() {
                response.headers_mut().insert(SET_COOKIE, value);
            }

            return response;
        }
    }

    // --- Standard redirect-based logout (no front-channel clients) ---

    let redirect = build_redirect(validated_uri, state_param);
    let mut response = redirect.into_response();

    // Clear the session cookie
    let clear_header = session_cookie::clear_session_cookie_header();
    if let Ok(value) = clear_header.parse() {
        response.headers_mut().insert(SET_COOKIE, value);
    }

    response
}

/// Validate the post_logout_redirect_uri against the client's registered URIs.
/// Checks `post_logout_redirect_uris` first (preferred), then falls back to `redirect_uris`.
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

    // Check post_logout_redirect_uris first (preferred per Session §5)
    if client.post_logout_redirect_uris.contains(&uri.to_string()) {
        return Some(uri.to_string());
    }

    // Fallback: check redirect_uris
    if client.redirect_uris.contains(&uri.to_string()) {
        return Some(uri.to_string());
    }

    None
}

fn build_redirect(uri: Option<String>, state: Option<String>) -> Response {
    let redirect = match uri {
        Some(mut u) => {
            if let Some(s) = state {
                u.push_str(&format!("?state={}", urlencoding::encode(&s)));
            }
            u
        }
        None => "/".to_string(),
    };
    // Return a redirect response
    axum::response::Redirect::temporary(&redirect).into_response()
}
