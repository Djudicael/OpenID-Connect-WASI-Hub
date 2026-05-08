use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A stored KeyPackage for an MLS user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyPackageEntry {
    /// Unique identifier.
    pub id: Uuid,
    /// The user who owns this KeyPackage.
    pub user_id: Uuid,
    /// MLS KeyPackage reference hash.
    pub key_package_ref: Vec<u8>,
    /// Encrypted KeyPackage bytes.
    pub key_package_encrypted: Vec<u8>,
    /// Whether this KeyPackage has been consumed.
    pub used: bool,
    /// When the KeyPackage was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Optional expiration timestamp.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}
