//! MLS domain models.

use serde::Deserialize;
use uuid::Uuid;

pub use oidc_core::models::mls::{KeyPackageEntry, MlsGroup};

/// Request to create a new MLS group.
#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub realm_id: Uuid,
    pub creator_user_id: Uuid,
}

/// Response after creating a group.
#[derive(serde::Serialize)]
pub struct CreateGroupResponse {
    pub id: Uuid,
    pub epoch: u64,
}

/// Request to join an MLS group.
#[derive(Deserialize)]
pub struct JoinGroupRequest {
    pub user_id: Uuid,
    pub key_package_ref: String,
}

/// Request to send a commit.
#[derive(Deserialize)]
pub struct SendCommitRequest {
    pub epoch: u64,
    pub commit_data: String,
}

/// Request to upload a KeyPackage.
#[derive(Deserialize)]
pub struct UploadKeyPackageRequest {
    pub user_id: Uuid,
    pub key_package_data: String,
}

/// Response after uploading a KeyPackage.
#[derive(serde::Serialize)]
pub struct KeyPackageResponse {
    pub id: Uuid,
    pub key_package_ref: String,
}

/// A stored MLS commit record.
#[derive(Debug, Clone)]
pub struct CommitRecord {
    pub id: Uuid,
    pub group_id: Uuid,
    pub epoch: u64,
    pub commit_data: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
