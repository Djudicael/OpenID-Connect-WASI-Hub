use uuid::Uuid;

use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::Scope;

/// PostgreSQL implementation of the Scope repository.
pub struct ScopeRepo;

/// Column list for scope SELECT queries (order must match map_row indices).
const SCOPE_COLUMNS: &str = "id, realm_id, name, description, enabled";

impl ScopeRepo {
    /// Find a scope by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<Scope>, OidcError> {
        let sql = format!("SELECT {SCOPE_COLUMNS} FROM scopes WHERE id = $1");
        let row = conn
            .query_one_params(&sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a scope by its name within a specific realm.
    pub async fn find_by_name(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
        name: &str,
    ) -> Result<Option<Scope>, OidcError> {
        let sql = format!("SELECT {SCOPE_COLUMNS} FROM scopes WHERE realm_id = $1 AND name = $2");
        let row = conn
            .query_one_params(&sql, &[&realm_id, &name])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// List all scopes in a realm, ordered alphabetically by name.
    pub async fn list_by_realm(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<Vec<Scope>, OidcError> {
        let sql = format!("SELECT {SCOPE_COLUMNS} FROM scopes WHERE realm_id = $1 ORDER BY name");
        let result = conn
            .query_params(&sql, &[&realm_id])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect()
    }

    /// Insert a new scope.
    pub async fn create(&self, conn: &mut Connection, entity: &Scope) -> Result<(), OidcError> {
        let sql = "INSERT INTO scopes (id, realm_id, name, description, enabled) VALUES ($1, $2, $3, $4, $5)";
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.realm_id,
                &entity.name,
                &entity.description,
                &entity.enabled,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Update an existing scope.
    pub async fn update(&self, conn: &mut Connection, entity: &Scope) -> Result<(), OidcError> {
        let sql = "UPDATE scopes SET name = $1, description = $2, enabled = $3 WHERE id = $4";
        conn.execute_params(
            sql,
            &[
                &entity.name,
                &entity.description,
                &entity.enabled,
                &entity.id,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Hard-delete a scope by ID.
    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "DELETE FROM scopes WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// List all scopes across all realms with pagination.
    pub async fn list(
        &self,
        conn: &mut Connection,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Scope>, OidcError> {
        let sql = format!(
            "SELECT {SCOPE_COLUMNS} FROM scopes ORDER BY created_at DESC LIMIT $1 OFFSET $2"
        );
        let result = conn
            .query_params(&sql, &[&limit, &offset])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect()
    }

    /// Count all scopes.
    pub async fn count(&self, conn: &mut Connection) -> Result<i64, OidcError> {
        let sql = "SELECT COUNT(*) FROM scopes";
        let result = conn.query(sql).await.map_err(mapper::pg_err)?;
        let row = result
            .into_rows()
            .into_iter()
            .next()
            .ok_or(OidcError::Internal("count returned no rows".into()))?;
        mapper::i64_(&row, 0)
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<Scope, OidcError> {
        Ok(Scope {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::uuid(row, 1)?,
            name: mapper::string(row, 2)?,
            description: mapper::opt_string(row, 3)?,
            enabled: mapper::bool_(row, 4)?,
        })
    }
}
