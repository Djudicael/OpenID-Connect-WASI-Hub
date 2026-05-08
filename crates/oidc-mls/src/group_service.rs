//! MLS group lifecycle service.

use oidc_core::models::mls::MlsGroup;
use oidc_core::OidcError;
use oidc_repository::Connection;
use uuid::Uuid;

/// Service for managing MLS groups.
pub struct GroupService;

impl GroupService {
    /// Create a new MLS group.
    pub async fn create_group(
        conn: &mut Connection,
        realm_id: Uuid,
        _creator_user_id: Uuid,
    ) -> Result<MlsGroup, OidcError> {
        let id = oidc_core::utils::generate_uuid_v7();
        let group_id = id.as_bytes().to_vec();
        let epoch = 0u64;
        let group_state_encrypted = vec![];

        let sql = r#"
            INSERT INTO mls_groups (id, group_id, realm_id, epoch, group_state_encrypted)
            VALUES ($1, $2, $3, $4, $5)
        "#;
        conn.execute_params(
            sql,
            &[&id, &group_id, &realm_id, &(epoch as i64), &group_state_encrypted],
        )
        .await
        .map_err(|e| OidcError::Internal(e.to_string()))?;

        Ok(MlsGroup {
            id,
            realm_id,
            epoch,
            active: true,
        })
    }

    /// Find a group by its ID.
    pub async fn get_group(
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<MlsGroup>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, epoch, group_state_encrypted IS NOT NULL as active
            FROM mls_groups WHERE id = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(|e| OidcError::Internal(e.to_string()))?;

        Ok(row.map(|r| {
            let id: Uuid = r.get(0).unwrap();
            let realm_id: Uuid = r.get(1).unwrap();
            let epoch: i64 = r.get(2).unwrap();
            let active: bool = r.get(3).unwrap();
            MlsGroup {
                id,
                realm_id,
                epoch: epoch as u64,
                active,
            }
        }))
    }

    /// Add a member to a group.
    pub async fn add_member(
        conn: &mut Connection,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), OidcError> {
        let id = oidc_core::utils::generate_uuid_v7();
        let credential = vec![];
        let leaf_index = 0i32;

        let sql = r#"
            INSERT INTO mls_members (id, group_id, user_id, credential, leaf_index)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (group_id, user_id) DO NOTHING
        "#;
        conn.execute_params(sql, &[&id, &group_id, &user_id, &credential, &leaf_index])
            .await
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        Ok(())
    }

    /// Remove a member from a group.
    pub async fn remove_member(
        conn: &mut Connection,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), OidcError> {
        let sql = r#"
            UPDATE mls_members SET removed_at = NOW()
            WHERE group_id = $1 AND user_id = $2 AND removed_at IS NULL
        "#;
        conn.execute_params(sql, &[&group_id, &user_id])
            .await
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        Ok(())
    }

    /// Update the epoch for a group.
    pub async fn update_epoch(
        conn: &mut Connection,
        group_id: Uuid,
        new_epoch: u64,
    ) -> Result<(), OidcError> {
        let sql = "UPDATE mls_groups SET epoch = $1, updated_at = NOW() WHERE id = $2";
        conn.execute_params(sql, &[&(new_epoch as i64), &group_id])
            .await
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        Ok(())
    }
}
