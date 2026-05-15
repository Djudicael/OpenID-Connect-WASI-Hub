//! Front-Channel Logout (OIDC Front-Channel Logout §6).
//!
//! When a session is terminated, the OP renders an HTML page containing
//! invisible iframes pointing to each RP's `frontchannel_logout_uri`.
//! Each RP's iframe receives a logout notification and can clean up
//! the user's session on the RP side.
//!
//! The logout iframe URL may include a `iss` (issuer) and `sid` (session ID)
//! query parameter when the client has `frontchannel_logout_session_required=true`.

use axum::response::{Html, IntoResponse, Response};

use oidc_core::models::Client;

/// Build the front-channel logout HTML page.
///
/// This page contains one invisible iframe per client that has a
/// `frontchannel_logout_uri` configured. Each iframe URL includes:
/// - `iss`: The OP issuer URL
/// - `sid`: The OIDC session ID (if `frontchannel_logout_session_required` is true)
///
/// Per Front-Channel Logout §6, the RP's iframe page should:
/// 1. Validate the `iss` parameter matches the expected OP
/// 2. Validate the `sid` parameter matches the expected session (if present)
/// 3. Log the user out of the RP
pub fn build_frontchannel_logout_html(issuer: &str, sid: &str, clients: &[&Client]) -> Response {
    let mut iframes = String::new();

    for client in clients {
        if let Some(ref uri) = client.frontchannel_logout_uri {
            let iframe_url = if client.frontchannel_logout_session_required {
                format!(
                    "{}?iss={}&sid={}",
                    uri,
                    urlencoding::encode(issuer),
                    urlencoding::encode(sid)
                )
            } else {
                format!("{}?iss={}", uri, urlencoding::encode(issuer))
            };
            iframes.push_str(&format!(
                r#"<iframe src="{}" style="display:none;width:0;height:0;border:none;"></iframe>"#,
                iframe_url
            ));
        }
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Front-Channel Logout</title></head>
<body>
{iframes}
<script>
// Auto-close after iframes have had time to load (5 seconds max)
setTimeout(function() {{
    // If we have a post_logout_redirect_uri, redirect there
    var params = new URLSearchParams(window.location.search);
    var redirect = params.get('post_logout_redirect_uri');
    if (redirect) {{
        var state = params.get('state');
        if (state) {{
            redirect += (redirect.indexOf('?') === -1 ? '?' : '&') + 'state=' + encodeURIComponent(state);
        }}
        window.location.href = redirect;
    }}
}}, 5000);
</script>
</body>
</html>"#
    );

    Html(html).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oidc_core::models::ClientType;
    use uuid::Uuid;

    fn test_client_with_frontchannel(
        frontchannel_uri: Option<&str>,
        session_required: bool,
    ) -> Client {
        Client {
            id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            client_id: "test-client".to_string(),
            client_type: ClientType::Confidential,
            client_secret_hash: None,
            name: "Test Client".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            allowed_scopes: vec!["openid".to_string()],
            allowed_grant_types: vec!["authorization_code".to_string()],
            pkce_required: true,
            enabled: true,
            deleted_at: None,
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            jwks_uri: None,
            jwks: None,
            request_uris: vec![],
            client_secret_encrypted: None,
            frontchannel_logout_uri: frontchannel_uri.map(|s| s.to_string()),
            frontchannel_logout_session_required: session_required,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            post_logout_redirect_uris: vec![],
            subject_type: "public".into(),
            sector_identifier_uri: None,
        }
    }

    #[tokio::test]
    async fn test_frontchannel_html_includes_iframes() {
        let client = test_client_with_frontchannel(
            Some("https://rp.example.com/frontchannel_logout"),
            false,
        );
        let clients: Vec<&Client> = vec![&client];
        let response = build_frontchannel_logout_html("https://op.example.com", "sid123", &clients);

        // Convert to string for assertion
        let (parts, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
        let html = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(html.contains("https://rp.example.com/frontchannel_logout"));
        assert!(html.contains("iss="));
        assert!(
            !html.contains("sid="),
            "sid should NOT be included when session_required is false"
        );
    }

    #[tokio::test]
    async fn test_frontchannel_html_includes_sid_when_required() {
        let client =
            test_client_with_frontchannel(Some("https://rp.example.com/frontchannel_logout"), true);
        let clients: Vec<&Client> = vec![&client];
        let response = build_frontchannel_logout_html("https://op.example.com", "sid123", &clients);

        let (parts, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
        let html = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(html.contains("https://rp.example.com/frontchannel_logout"));
        assert!(html.contains("iss="));
        assert!(
            html.contains("sid="),
            "sid should be included when session_required is true"
        );
    }

    #[tokio::test]
    async fn test_frontchannel_html_skips_clients_without_uri() {
        let client = test_client_with_frontchannel(None, false);
        let clients: Vec<&Client> = vec![&client];
        let response = build_frontchannel_logout_html("https://op.example.com", "sid123", &clients);

        let (parts, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
        let html = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(
            !html.contains("<iframe"),
            "no iframes should be rendered for clients without frontchannel_logout_uri"
        );
    }

    #[tokio::test]
    async fn test_frontchannel_html_multiple_clients() {
        let client1 = test_client_with_frontchannel(
            Some("https://rp1.example.com/frontchannel_logout"),
            false,
        );
        let client2 = test_client_with_frontchannel(
            Some("https://rp2.example.com/frontchannel_logout"),
            true,
        );
        let clients: Vec<&Client> = vec![&client1, &client2];
        let response = build_frontchannel_logout_html("https://op.example.com", "sid123", &clients);

        let (parts, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
        let html = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(html.contains("rp1.example.com"));
        assert!(html.contains("rp2.example.com"));
        // Count iframes
        let iframe_count = html.matches("<iframe").count();
        assert_eq!(
            iframe_count, 2,
            "should have 2 iframes for 2 clients with frontchannel_logout_uri"
        );
    }
}
