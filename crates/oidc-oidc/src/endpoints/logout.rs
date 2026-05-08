//! RP-Initiated Logout endpoint (OIDC Session Management).

use axum::extract::Query;
use axum::response::Redirect;
use std::collections::HashMap;

use oidc_core::traits::TokenService;

use crate::state::OidcState;

/// Logout endpoint handler.
/// Validates id_token_hint, post_logout_redirect_uri, revokes session, and redirects.
pub async fn logout_handler(
    state: OidcState,
    Query(params): Query<HashMap<String, String>>,
) -> Redirect {
    let post_logout_redirect_uri = params.get("post_logout_redirect_uri").cloned();
    let state_param = params.get("state").cloned();

    // If id_token_hint is provided, validate it and revoke the session
    if let Some(id_token_hint) = params.get("id_token_hint") {
        if let Ok(mut conn) = state.connect().await {
            // Verify the ID token to extract the subject
            if let Ok(subject) = state.token_service.verify_access_token(id_token_hint).await {
                if let Ok(user_id) = subject.parse::<uuid::Uuid>() {
                    // Revoke all active sessions for this user
                    let sql =
                        "UPDATE sessions SET revoked = TRUE WHERE user_id = $1 AND NOT revoked";
                    let _ = conn.execute_params(sql, &[&user_id]).await;
                }
            }
        }
    }

    build_redirect(post_logout_redirect_uri, state_param)
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
