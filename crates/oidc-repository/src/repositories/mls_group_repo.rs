use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::mls::MlsGroup;
use uuid::Uuid;

/// PostgreSQL implementation of the MLS Group repository.
pub struct MlsGroupRepo;

impl MlsGroupRepo {
    /// Find an MLS group by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<MlsGroup>, OidcError> {
        let sql = r#"
            SELECT id, group_id, realm_id, epoch, roster_hash,
                   group_state_encrypted, welcome_message
            FROM mls_groups
            WHERE id = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find an MLS group by its opaque group_id bytes.
    pub async fn find_by_group_id(
        &self,
        conn: &mut Connection,
        group_id: &[u8],
    ) -> Result<Option<MlsGroup>, OidcError> {
        let sql = r#"
            SELECT id, group_id, realm_id, epoch, roster_hash,
                   group_state_encrypted, welcome_message
            FROM mls_groups
            WHERE group_id = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&group_id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find all groups within a realm.
    pub async fn find_by_realm(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<Vec<MlsGroup>, OidcError> {
        let sql = r#"
            SELECT id, group_id, realm_id, epoch, roster_hash,
                   group_state_encrypted, welcome_message
            FROM mls_groups
            WHERE realm_id = $1
        "#;
        let result = conn
            .query_params(sql, &[&realm_id])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Insert a new MLS group.
    pub async fn create(&self, conn: &mut Connection, entity: &MlsGroup) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO mls_groups (
                id, group_id, realm_id, epoch, roster_hash,
                group_state_encrypted, welcome_message
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.group_id,
                &entity.realm_id,
                &(entity.epoch as i64),
                &entity.roster_hash,
                &entity.group_state_encrypted,
                &entity.welcome_message,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Update an existing MLS group (epoch, roster_hash, state, welcome).
    pub async fn update(&self, conn: &mut Connection, entity: &MlsGroup) -> Result<(), OidcError> {
        let sql = r#"
            UPDATE mls_groups SET
                epoch = $1,
                roster_hash = $2,
                group_state_encrypted = $3,
                welcome_message = $4,
                updated_at = NOW()
            WHERE id = $5
        "#;
        conn.execute_params(
            sql,
            &[
                &(entity.epoch as i64),
                &entity.roster_hash,
                &entity.group_state_encrypted,
                &entity.welcome_message,
                &entity.id,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Delete an MLS group by ID.
    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "DELETE FROM mls_groups WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<MlsGroup, OidcError> {
        Ok(MlsGroup {
            id: mapper::uuid(row, 0)?,
            group_id: mapper::bytes(row, 1)?,
            realm_id: mapper::uuid(row, 2)?,
            epoch: mapper::i64_(row, 3)? as u64,
            roster_hash: mapper::opt_bytes(row, 4)?,
            group_state_encrypted: mapper::bytes(row, 5)?,
            welcome_message: mapper::opt_bytes(row, 6)?,
        })
    }
}
