//! WebFinger endpoint (RFC 7033 / OIDC Discovery §5).
//!
//! Allows discovery of the OIDC issuer for a given account (email).
//! Query: GET /.well-known/webfinger?resource=acct:user@example.com

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use oidc_core::OidcError;
use oidc_repository::repositories::realm_repo::RealmRepo;
use oidc_repository::repositories::user_repo::UserRepo;

use crate::state::OidcState;

/// WebFinger query parameters.
#[derive(Debug, Deserialize)]
pub struct WebFingerQuery {
    /// The resource being queried (e.g., "acct:user@example.com").
    pub resource: String,
    /// Optional: the relation type to filter by (e.g., "http://openid.net/specs/connect/1.0/issuer").
    pub rel: Option<String>,
}

/// WebFinger JRD (JSON Resource Descriptor) response per RFC 7033 §4.4.
#[derive(Debug, Serialize)]
pub struct WebFingerResponse {
    /// The subject of the query (same as the resource parameter).
    pub subject: String,
    /// Aliases for the subject (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,
    /// Properties about the subject (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, String>>,
    /// Links related to the subject.
    pub links: Vec<WebFingerLink>,
}

/// A single link in a WebFinger response per RFC 7033 §4.5.
#[derive(Debug, Serialize)]
pub struct WebFingerLink {
    /// The relation type.
    pub rel: String,
    /// The target URI (optional — may use titles instead).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    /// The type of the link target (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub type_: Option<String>,
    /// Titles for the link (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub titles: Option<HashMap<String, String>>,
    /// Properties about the link (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, String>>,
}

/// WebFinger handler.
///
/// Supports the `acct` URI scheme per OIDC Discovery §5:
///   resource=acct:user@example.com
///
/// Returns the OIDC issuer URL for the user's realm.
pub async fn webfinger_handler(
    State(state): State<OidcState>,
    Query(query): Query<WebFingerQuery>,
) -> Result<Json<WebFingerResponse>, OidcError> {
    // Parse the acct URI: "acct:user@host"
    let (local_part, _host) = parse_acct_uri(&query.resource).ok_or_else(|| {
        OidcError::InvalidInput("Invalid resource URI. Expected format: acct:user@host".into())
    })?;

    // The local_part is typically the user's email
    let email = local_part;

    // Look up the user across all realms
    let mut conn = state.connect().await?;

    // Try to find the user in any enabled realm
    let realms = RealmRepo.find_all_enabled(&mut conn).await?;

    for realm in realms {
        if let Ok(Some(_user)) = UserRepo.find_by_email(&mut conn, realm.id, &email).await {
            let issuer = if realm.name == "master" {
                state.issuer.clone()
            } else {
                format!("{}/realms/{}", state.issuer, realm.name)
            };

            // Filter links by rel if requested
            let rel_filter = query.rel.as_deref();
            let desired_rel = "http://openid.net/specs/connect/1.0/issuer";

            let links = if rel_filter.is_some() && rel_filter != Some(desired_rel) {
                // Client asked for a rel we don't support — return empty links
                vec![]
            } else {
                vec![WebFingerLink {
                    rel: desired_rel.to_string(),
                    href: Some(issuer),
                    type_: Some("application/json".to_string()),
                    titles: None,
                    properties: None,
                }]
            };

            return Ok(Json(WebFingerResponse {
                subject: query.resource.clone(),
                aliases: None,
                properties: None,
                links,
            }));
        }
    }

    // User not found — per RFC 7033, return 404
    Err(OidcError::NotFound("resource".into()))
}

/// Parse an `acct:` URI into (local_part, host).
///
/// Format: `acct:user@host` or `acct:user@host:port`
fn parse_acct_uri(resource: &str) -> Option<(String, String)> {
    let acct = resource.strip_prefix("acct:")?;
    let (local, host) = acct.rsplit_once('@')?;
    if local.is_empty() || host.is_empty() {
        return None;
    }
    Some((local.to_string(), host.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_acct_uri_simple() {
        let (local, host) = parse_acct_uri("acct:alice@example.com").unwrap();
        assert_eq!(local, "alice");
        assert_eq!(host, "example.com");
    }

    #[test]
    fn test_parse_acct_uri_with_port() {
        let (local, host) = parse_acct_uri("acct:bob@example.com:8080").unwrap();
        assert_eq!(local, "bob");
        assert_eq!(host, "example.com:8080");
    }

    #[test]
    fn test_parse_acct_uri_email_local() {
        let (local, host) = parse_acct_uri("acct:user.name@example.com").unwrap();
        assert_eq!(local, "user.name");
        assert_eq!(host, "example.com");
    }

    #[test]
    fn test_parse_acct_uri_invalid_no_acct() {
        assert!(parse_acct_uri("alice@example.com").is_none());
    }

    #[test]
    fn test_parse_acct_uri_invalid_no_at() {
        assert!(parse_acct_uri("acct:aliceexample.com").is_none());
    }

    #[test]
    fn test_parse_acct_uri_invalid_empty_local() {
        assert!(parse_acct_uri("acct:@example.com").is_none());
    }

    #[test]
    fn test_parse_acct_uri_invalid_empty_host() {
        assert!(parse_acct_uri("acct:alice@").is_none());
    }
}
