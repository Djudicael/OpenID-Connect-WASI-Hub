use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::Realm;
use uuid::Uuid;

/// PostgreSQL implementation of the Realm repository.
pub struct RealmRepo;

impl RealmRepo {
    /// Find a realm by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<Realm>, OidcError> {
        let sql = "SELECT id, name, display_name, enabled FROM realms WHERE id = $1";
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a realm by its unique name.
    pub async fn find_by_name(
        &self,
        conn: &mut Connection,
        name: &str,
    ) -> Result<Option<Realm>, OidcError> {
        let sql = "SELECT id, name, display_name, enabled FROM realms WHERE name = $1";
        let row = conn
            .query_one_params(sql, &[&name])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Insert a new realm.
    pub async fn create(&self, conn: &mut Connection, entity: &Realm) -> Result<(), OidcError> {
        let sql = "INSERT INTO realms (id, name, display_name, enabled) VALUES ($1, $2, $3, $4)";
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.name,
                &entity.display_name,
                &entity.enabled,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Update an existing realm.
    pub async fn update(&self, conn: &mut Connection, entity: &Realm) -> Result<(), OidcError> {
        let sql = "UPDATE realms SET name = $1, display_name = $2, enabled = $3, updated_at = NOW() WHERE id = $4";
        conn.execute_params(
            sql,
            &[
                &entity.name,
                &entity.display_name,
                &entity.enabled,
                &entity.id,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Hard-delete a realm by ID.
    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "DELETE FROM realms WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// List all realms with pagination.
    pub async fn list(
        &self,
        conn: &mut Connection,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Realm>, OidcError> {
        let sql = r#"
            SELECT id, name, display_name, enabled
            FROM realms
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        "#;
        let result = conn
            .query_params(sql, &[&limit, &offset])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Count all realms.
    pub async fn count(&self, conn: &mut Connection) -> Result<i64, OidcError> {
        let sql = "SELECT COUNT(*) FROM realms";
        let result = conn.query(sql).await.map_err(mapper::pg_err)?;
        let row = result
            .into_rows()
            .into_iter()
            .next()
            .ok_or(OidcError::Internal("count returned no rows".into()))?;
        mapper::i64_(&row, 0)
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<Realm, OidcError> {
        Ok(Realm {
            id: mapper::uuid(row, 0)?,
            name: mapper::string(row, 1)?,
            display_name: mapper::string(row, 2)?,
            enabled: mapper::bool_(row, 3)?,
        })
    }
}
