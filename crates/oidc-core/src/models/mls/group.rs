use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An MLS group managed by the hub.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MlsGroup {
    /// Internal DB identifier.
    pub id: Uuid,
    /// The realm this group belongs to.
    pub realm_id: Uuid,
    /// Current MLS epoch.
    pub epoch: u64,
    /// Whether the group is active.
    pub active: bool,
}
