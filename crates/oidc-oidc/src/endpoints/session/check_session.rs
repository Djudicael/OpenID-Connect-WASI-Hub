//! Check Session Iframe endpoint (OIDC Session Management §4).
//!
//! Serves an HTML page that the RP embeds in an iframe. The OP iframe
//! receives `postMessage` events from the RP iframe and responds with
//! the current session state. The RP compares this to its stored
//! `session_state` value to detect session changes.
//!
//! Protocol:
//! 1. RP loads the OP iframe at `check_session_iframe` with query params:
//!    - `client_id`: The RP's client_id
//!    - `redirect_uri`: The RP's redirect URI (used to compute origin)
//! 2. RP iframe sends `postMessage("client_id redirect_uri", op_origin)` to the OP iframe
//! 3. OP iframe responds with `postMessage(session_state, rp_origin)` where:
//!    - `session_state = SHA256(client_id + " " + sid + " " + origin)` base64url
//! 4. RP compares the received `session_state` with the one from the auth response.
//!    If they differ, the RP should perform a prompt=none check or re-authenticate.

use axum::extract::Query;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

use crate::state::OidcState;

/// Query parameters for the check session iframe.
#[derive(Debug, Deserialize)]
pub struct CheckSessionParams {
    /// The RP's client_id.
    pub client_id: Option<String>,
    /// The RP's redirect URI (used to compute origin for session_state).
    pub redirect_uri: Option<String>,
}

/// Check Session Iframe handler (Session §4).
///
/// Returns an HTML page that:
/// 1. Listens for `postMessage` from the RP iframe containing `client_id redirect_uri`
/// 2. Computes `session_state = SHA256(client_id + " " + sid + " " + origin)` base64url
/// 3. Sends `session_state` back to the RP iframe via `postMessage`
///
/// The `sid` (OP browser session ID) is read from the `oidc_session` cookie.
pub async fn check_session_handler(
    state: OidcState,
    Query(_params): Query<CheckSessionParams>,
) -> Response {
    // The iframe HTML/JS handles the postMessage protocol client-side.
    // It reads the session cookie and computes session_state.
    // The encryption key is needed to verify the cookie HMAC.
    let _encryption_key_hex = &state.encryption_key;

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>OIDC Check Session</title></head>
<body>
<script>
(function() {{
    // The OP session cookie name
    var COOKIE_NAME = 'oidc_session';
    // The encryption key hex for HMAC verification (server-side only)
    // We cannot verify the cookie in JS because HMAC verification requires the key.
    // Instead, we send the raw cookie value to the parent and let the server verify.
    // However, per the spec, the OP iframe must compute session_state locally.
    //
    // Approach: The OP iframe reads the session cookie and sends the session ID
    // to the RP via postMessage. The RP then does a prompt=none check if needed.
    //
    // Alternative (spec-compliant): The OP iframe computes session_state using
    // the sid from the cookie. Since the cookie is HMAC-protected, we trust it.

    function getSessionIdFromCookie() {{
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {{
            var cookie = cookies[i].trim();
            if (cookie.indexOf(COOKIE_NAME + '=') === 0) {{
                var value = cookie.substring(COOKIE_NAME.length + 1);
                // Cookie format: session_id.hmac_hex
                // We extract the session_id part (before the dot)
                var dotIndex = value.indexOf('.');
                if (dotIndex > 0) {{
                    return value.substring(0, dotIndex);
                }}
            }}
        }}
        return '';
    }}

    // SHA-256 using Web Crypto API (available in all modern browsers)
    async function sha256(message) {{
        var encoder = new TextEncoder();
        var data = encoder.encode(message);
        var hashBuffer = await crypto.subtle.digest('SHA-256', data);
        var hashArray = Array.from(new Uint8Array(hashBuffer));
        // base64url encode (no padding)
        var base64 = btoa(String.fromCharCode.apply(null, hashArray))
            .replace(/\\+/g, '-')
            .replace(/\\//g, '_')
            .replace(/=+$/, '');
        return base64;
    }}

    function getOrigin(url) {{
        try {{
            var u = new URL(url);
            var origin = u.protocol + '//' + u.host;
            return origin;
        }} catch (e) {{
            return '';
        }}
    }}

    // Listen for postMessage from RP iframe
    window.addEventListener('message', async function(e) {{
        // Per spec, the RP sends: "client_id redirect_uri"
        var msg = e.data;
        if (typeof msg !== 'string') return;

        var parts = msg.split(' ');
        if (parts.length < 2) return;

        var clientId = parts[0];
        var redirectUri = parts[1];
        var origin = getOrigin(redirectUri);

        var sid = getSessionIdFromCookie();

        // Compute session_state per OIDC Session Management §3:
        // session_state = SHA256(client_id + " " + sid + " " + origin) base64url
        var input = clientId + ' ' + sid + ' ' + origin;
        var sessionState = await sha256(input);

        // Send session_state back to the RP
        e.source.postMessage(sessionState, e.origin);
    }});
}})();
</script>
</body>
</html>"#
    );

    Html(html).into_response()
}
