//! Front-Channel Logout (OIDC Front-Channel Logout §6).
//!
//! When a session is terminated, the OP renders an HTML page containing
//! invisible iframes pointing to each RP's `frontchannel_logout_uri`.
//! Each RP's iframe receives a logout notification and can clean up
//! the user's session on the RP side.
//!
//! The logout iframe URL may include a `iss` (issuer) and `sid` (session ID)
//! query parameter when the client has `frontchannel_logout_session_required=true`.

use std::collections::BTreeSet;

use axum::http::HeaderValue;
use axum::http::header::CONTENT_SECURITY_POLICY;
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
pub fn build_frontchannel_logout_html(
    issuer: &str,
    sid: &str,
    clients: &[&Client],
    post_logout_redirect_uri: Option<&str>,
    state: Option<&str>,
) -> Response {
    let mut iframes = String::new();
    let mut frame_origins = BTreeSet::new();

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
            if let Ok(parsed) = url::Url::parse(uri) {
                frame_origins.insert(parsed.origin().unicode_serialization());
            }
        }
    }

    let redirect_target = post_logout_redirect_uri.unwrap_or("/");
    let redirect_state = state.unwrap_or("");
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Front-Channel Logout</title></head>
<body>
{iframes}
<script>
const redirectTarget = {redirect_target:?};
const redirectState = {redirect_state:?};
setTimeout(function() {{
    var redirect = redirectTarget;
    if (redirectState) {{
        redirect += (redirect.indexOf('?') === -1 ? '?' : '&') + 'state=' + encodeURIComponent(redirectState);
    }}
    window.location.href = redirect;
}}, 5000);
</script>
</body>
</html>"#
    );

    let mut response = Html(html).into_response();
    let frame_src = if frame_origins.is_empty() {
        "frame-src 'none'".to_string()
    } else {
        format!(
            "frame-src 'self' {}",
            frame_origins.into_iter().collect::<Vec<_>>().join(" ")
        )
    };
    let csp = format!(
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; {frame_src}; frame-ancestors 'none'"
    );
    if let Ok(value) = HeaderValue::from_str(&csp) {
        response
            .headers_mut()
            .insert(CONTENT_SECURITY_POLICY, value);
    }

    response
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
            response_modes: vec!["query".to_string(), "fragment".to_string()],
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            id_token_encryption_key_encrypted: None,
            id_token_encryption_key_pem: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            request_object_encryption_key_encrypted: None,
            request_object_encryption_key_pem: None,
        }
    }

    #[tokio::test]
    async fn test_frontchannel_html_includes_iframes() {
        let client = test_client_with_frontchannel(
            Some("https://rp.example.com/frontchannel_logout"),
            false,
        );
        let clients: Vec<&Client> = vec![&client];
        let response = build_frontchannel_logout_html(
            "https://op.example.com",
            "sid123",
            &clients,
            Some("https://app.example.com/logged-out"),
            Some("logout-state"),
        );

        let csp = response
            .headers()
            .get(CONTENT_SECURITY_POLICY)
            .expect("frontchannel response should set a CSP override")
            .to_str()
            .expect("CSP should be valid ASCII")
            .to_string();

        // Convert to string for assertion
        let (_parts, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
        let html = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(html.contains("https://rp.example.com/frontchannel_logout"));
        assert!(html.contains("iss="));
        assert!(html.contains("https://app.example.com/logged-out"));
        assert!(html.contains("logout-state"));
        assert!(
            !html.contains("sid="),
            "sid should NOT be included when session_required is false"
        );
        assert!(csp.contains("frame-src 'self' https://rp.example.com"));
        assert!(csp.contains("script-src 'self' 'unsafe-inline'"));
    }

    #[tokio::test]
    async fn test_frontchannel_html_includes_sid_when_required() {
        let client =
            test_client_with_frontchannel(Some("https://rp.example.com/frontchannel_logout"), true);
        let clients: Vec<&Client> = vec![&client];
        let response = build_frontchannel_logout_html(
            "https://op.example.com",
            "sid123",
            &clients,
            None,
            None,
        );

        let (_parts, body) = response.into_parts();
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
        let response = build_frontchannel_logout_html(
            "https://op.example.com",
            "sid123",
            &clients,
            None,
            None,
        );

        let (_parts, body) = response.into_parts();
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
        let response = build_frontchannel_logout_html(
            "https://op.example.com",
            "sid123",
            &clients,
            None,
            None,
        );

        let (_parts, body) = response.into_parts();
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
