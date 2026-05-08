use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// A comprehensive audit trail event for compliance and security.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    /// Unique identifier.
    pub id: Uuid,
    /// The realm this event belongs to (optional for system-wide events).
    pub realm_id: Option<Uuid>,
    /// Type of event (e.g., "user.login", "api_key.created").
    pub event_type: String,
    /// ID of the actor who performed the action.
    pub actor_id: Option<Uuid>,
    /// Type of actor.
    pub actor_type: ActorType,
    /// Type of target resource.
    pub target_type: Option<String>,
    /// ID of the target resource.
    pub target_id: Option<Uuid>,
    /// Additional event details as JSON.
    pub details: serde_json::Value,
    /// IP address of the actor.
    pub ip_address: Option<IpAddr>,
    /// User agent string.
    pub user_agent: Option<String>,
    /// When the event occurred.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Type of actor that triggered an audit event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// A human user.
    User,
    /// An API key.
    ApiKey,
    /// The system itself.
    System,
}

impl std::fmt::Display for ActorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActorType::User => write!(f, "user"),
            ActorType::ApiKey => write!(f, "api_key"),
            ActorType::System => write!(f, "system"),
        }
    }
}
