use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A link between a local user and an upstream identity provider.
/// This represents the "federated identity" — the mapping between
/// the upstream IdP's subject and the local user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederatedIdentity {
    /// Unique identifier.
    pub id: Uuid,
    /// The local user this federated identity belongs to.
    pub user_id: Uuid,
    /// The realm.
    pub realm_id: Uuid,
    /// The identity provider's ID.
    pub identity_provider_id: Uuid,
    /// The subject identifier from the upstream IdP.
    pub upstream_subject: String,
    /// The upstream username/display name (optional).
    pub upstream_username: Option<String>,
    /// The upstream email (optional).
    pub upstream_email: Option<String>,
    /// When this federated identity was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When this federated identity was last used.
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federated_identity_creation() {
        let fi = FederatedIdentity {
            id: Uuid::now_v7(),
            user_id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            identity_provider_id: Uuid::now_v7(),
            upstream_subject: "1234567890".into(),
            upstream_username: Some("johndoe".into()),
            upstream_email: Some("john@example.com".into()),
            created_at: chrono::Utc::now(),
            last_used_at: None,
        };
        assert!(!fi.upstream_subject.is_empty());
        assert!(fi.upstream_username.is_some());
        assert!(fi.upstream_email.is_some());
    }

    #[test]
    fn test_federated_identity_serde_roundtrip() {
        let fi = FederatedIdentity {
            id: Uuid::now_v7(),
            user_id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            identity_provider_id: Uuid::now_v7(),
            upstream_subject: "sub-123".into(),
            upstream_username: None,
            upstream_email: Some("jane@example.com".into()),
            created_at: chrono::Utc::now(),
            last_used_at: Some(chrono::Utc::now()),
        };
        let json = serde_json::to_string(&fi).unwrap();
        let parsed: FederatedIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(fi, parsed);
    }
}
