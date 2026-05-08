use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::mls::MlsMember;
use uuid::Uuid;

/// PostgreSQL implementation of the MLS Member repository.
pub struct MlsMemberRepo;

impl MlsMemberRepo {
    /// Find an MLS member by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<MlsMember>, OidcError> {
        let sql = r#"
            SELECT id, group_id, user_id, credential, leaf_index, added_at, removed_at
            FROM mls_members
            WHERE id = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find all active members of a group.
    pub async fn find_active_by_group(
        &self,
        conn: &mut Connection,
        group_id: Uuid,
    ) -> Result<Vec<MlsMember>, OidcError> {
        let sql = r#"
            SELECT id, group_id, user_id, credential, leaf_index, added_at, removed_at
            FROM mls_members
            WHERE group_id = $1 AND removed_at IS NULL
        "#;
        let result = conn
            .query_params(sql, &[&group_id])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Find a specific member by group + user.
    pub async fn find_by_group_and_user(
        &self,
        conn: &mut Connection,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<MlsMember>, OidcError> {
        let sql = r#"
            SELECT id, group_id, user_id, credential, leaf_index, added_at, removed_at
            FROM mls_members
            WHERE group_id = $1 AND user_id = $2
        "#;
        let row = conn
            .query_one_params(sql, &[&group_id, &user_id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Insert a new MLS member.
    pub async fn create(&self, conn: &mut Connection, entity: &MlsMember) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO mls_members (
                id, group_id, user_id, credential, leaf_index, added_at, removed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.group_id,
                &entity.user_id,
                &entity.credential,
                &entity.leaf_index,
                &entity.added_at,
                &entity.removed_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Soft-remove a member by setting removed_at = NOW().
    pub async fn remove_member(
        &self,
        conn: &mut Connection,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), OidcError> {
        let sql = r#"
            UPDATE mls_members
            SET removed_at = NOW()
            WHERE group_id = $1 AND user_id = $2 AND removed_at IS NULL
        "#;
        conn.execute_params(sql, &[&group_id, &user_id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Hard-delete a member by ID.
    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "DELETE FROM mls_members WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<MlsMember, OidcError> {
        Ok(MlsMember {
            id: mapper::uuid(row, 0)?,
            group_id: mapper::uuid(row, 1)?,
            user_id: mapper::uuid(row, 2)?,
            credential: mapper::bytes(row, 3)?,
            leaf_index: mapper::i64_(row, 4)?,
            added_at: mapper::datetime(row, 5)?,
            removed_at: mapper::opt_datetime(row, 6)?,
        })
    }
}
