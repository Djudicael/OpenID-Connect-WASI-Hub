//! MLS commit processor for replay protection and state updates.

use oidc_core::OidcError;
use oidc_repository::Connection;
use uuid::Uuid;

use crate::epoch_manager::EpochManager;
use crate::models::CommitRecord;

/// Processes MLS commits with epoch validation.
pub struct CommitProcessor {
    epoch_manager: EpochManager,
}

impl CommitProcessor {
    /// Create a new commit processor.
    pub fn new() -> Self {
        Self {
            epoch_manager: EpochManager::new(),
        }
    }

    /// Validate and process a commit.
    pub async fn process_commit(
        &mut self,
        conn: &mut Connection,
        group_id: Uuid,
        epoch: u64,
        commit_data: Vec<u8>,
    ) -> Result<(), OidcError> {
        let group_id_bytes = group_id.as_bytes().to_vec();
        if !self.epoch_manager.validate(&group_id_bytes, epoch) {
            return Err(OidcError::InvalidRequest);
        }

        let id = oidc_core::utils::generate_uuid_v7();
        let sql = r#"
            INSERT INTO mls_commits (id, group_id, epoch, commit_data)
            VALUES ($1, $2, $3, $4)
        "#;
        conn.execute_params(sql, &[&id, &group_id, &(epoch as i64), &commit_data])
            .await
            .map_err(|e| OidcError::Internal(e.to_string()))?;

        self.epoch_manager.advance(group_id_bytes, epoch);

        let sql = "UPDATE mls_groups SET epoch = $1, updated_at = NOW() WHERE id = $2";
        conn.execute_params(sql, &[&(epoch as i64), &group_id])
            .await
            .map_err(|e| OidcError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Retrieve all commits for a group.
    pub async fn get_commits(
        &self,
        conn: &mut Connection,
        group_id: Uuid,
    ) -> Result<Vec<CommitRecord>, OidcError> {
        let sql = r#"
            SELECT id, group_id, epoch, commit_data, created_at
            FROM mls_commits
            WHERE group_id = $1
            ORDER BY epoch ASC
        "#;
        let result = conn
            .query_params(sql, &[&group_id])
            .await
            .map_err(|e| OidcError::Internal(e.to_string()))?;

        let mut records = Vec::new();
        for row in result.into_rows() {
            let id: Uuid = row.get(0).map_err(|e| OidcError::Internal(e.to_string()))?;
            let group_id: Uuid = row.get(1).map_err(|e| OidcError::Internal(e.to_string()))?;
            let epoch: i64 = row.get(2).map_err(|e| OidcError::Internal(e.to_string()))?;
            let commit_data: Vec<u8> = row.get(3).map_err(|e| OidcError::Internal(e.to_string()))?;
            let created_at: chrono::DateTime<chrono::Utc> = row.get(4).map_err(|e| OidcError::Internal(e.to_string()))?;
            records.push(CommitRecord {
                id,
                group_id,
                epoch: epoch as u64,
                commit_data,
                created_at,
            });
        }
        Ok(records)
    }
}

impl Default for CommitProcessor {
    fn default() -> Self {
        Self::new()
    }
}
