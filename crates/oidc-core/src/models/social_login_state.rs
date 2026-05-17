use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Persisted one-time state for a social-login/federation flow.
///
/// The raw browser state token is never stored directly. Instead, the
/// `state_token_hash` is persisted and looked up during the callback after the
/// browser proves possession of the original token via its cookie.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SocialLoginState {
    /// Unique identifier.
    pub id: Uuid,
    /// SHA-256 hex hash of the opaque browser state token.
    pub state_token_hash: String,
    /// Realm associated with the social login.
    pub realm_id: Uuid,
    /// Upstream identity provider associated with the social login.
    pub identity_provider_id: Uuid,
    /// Local client bound to the resulting login/session.
    pub client_id: Uuid,
    /// Redirect URI validated against the local client.
    pub redirect_uri: String,
    /// Original RP state to echo back after successful completion.
    pub original_state: Option<String>,
    /// OIDC nonce to place into the resulting local ID token.
    pub nonce: Option<String>,
    /// When this state expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Whether this state has already been consumed.
    pub used: bool,
    /// When this state was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn social_login_state_serde_roundtrip() {
        let state = SocialLoginState {
            id: Uuid::now_v7(),
            state_token_hash: "abc123".into(),
            realm_id: Uuid::now_v7(),
            identity_provider_id: Uuid::now_v7(),
            client_id: Uuid::now_v7(),
            redirect_uri: "https://app.example.com/callback".into(),
            original_state: Some("rp-state".into()),
            nonce: Some("nonce-123".into()),
            expires_at: chrono::Utc::now(),
            used: false,
            created_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&state).expect("serialization should succeed");
        let parsed: SocialLoginState =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(state, parsed);
    }
}
