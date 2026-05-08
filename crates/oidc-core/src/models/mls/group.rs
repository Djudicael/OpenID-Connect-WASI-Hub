use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An MLS group managed by the hub.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MlsGroup {
    /// Internal DB identifier.
    pub id: Uuid,
    /// Opaque MLS group ID bytes.
    pub group_id: Vec<u8>,
    /// The realm this group belongs to.
    pub realm_id: Uuid,
    /// Current MLS epoch.
    pub epoch: u64,
    /// Hash of current roster for quick sync.
    pub roster_hash: Option<Vec<u8>>,
    /// Encrypted MLSGroupState.
    pub group_state_encrypted: Vec<u8>,
    /// Latest Welcome message for late joiners.
    pub welcome_message: Option<Vec<u8>>,
}

/// An MLS group member.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MlsMember {
    /// Unique identifier.
    pub id: Uuid,
    /// Reference to the MLS group.
    pub group_id: Uuid,
    /// The user who is a member.
    pub user_id: Uuid,
    /// MLS credential bytes.
    pub credential: Vec<u8>,
    /// Leaf index in the MLS tree.
    pub leaf_index: i64,
    /// When the member was added.
    pub added_at: chrono::DateTime<chrono::Utc>,
    /// When the member was removed (NULL if still active).
    pub removed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A stored MLS commit record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MlsCommit {
    /// Unique identifier.
    pub id: Uuid,
    /// Reference to the MLS group.
    pub group_id: Uuid,
    /// Epoch at which the commit was made.
    pub epoch: u64,
    /// Raw commit data bytes.
    pub commit_data: Vec<u8>,
    /// When the commit was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}
