use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::Role;
use uuid::Uuid;

/// Escape special LIKE pattern characters (`%`, `_`, `\`) in a search string.
fn escape_like(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '%' | '_' | '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// PostgreSQL implementation of the Role repository.
pub struct RoleRepo;

/// Column list for role SELECT queries (order must match map_row indices).
const ROLE_COLUMNS: &str = r#"
    id, realm_id, name, description, permissions, created_at, updated_at
"#;

impl RoleRepo {
    /// Find a role by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<Role>, OidcError> {
        let sql = &format!("SELECT {ROLE_COLUMNS} FROM roles WHERE id = $1 AND deleted_at IS NULL");
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a role by name within a realm.
    pub async fn find_by_name(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
        name: &str,
    ) -> Result<Option<Role>, OidcError> {
        let sql = &format!(
            "SELECT {ROLE_COLUMNS} FROM roles WHERE realm_id = $1 AND name = $2 AND deleted_at IS NULL"
        );
        let row = conn
            .query_one_params(sql, &[&realm_id, &name])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Insert a new role.
    pub async fn create(&self, conn: &mut Connection, entity: &Role) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO roles (
                id, realm_id, name, description, permissions, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.realm_id,
                &entity.name,
                &entity.description,
                &mapper::to_json_value_vec(&entity.permissions),
                &entity.created_at,
                &entity.updated_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Update an existing role.
    pub async fn update(&self, conn: &mut Connection, entity: &Role) -> Result<(), OidcError> {
        let sql = r#"
            UPDATE roles SET
                name = $1,
                description = $2,
                permissions = $3,
                updated_at = NOW()
            WHERE id = $4 AND deleted_at IS NULL
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.name,
                &entity.description,
                &mapper::to_json_value_vec(&entity.permissions),
                &entity.id,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Soft-delete a role by ID.
    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE roles SET deleted_at = NOW() WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// List roles in a realm with optional search and pagination.
    /// If realm_id is None, returns roles from all realms.
    pub async fn list(
        &self,
        conn: &mut Connection,
        realm_id: Option<Uuid>,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Role>, OidcError> {
        let mut where_clauses = vec!["deleted_at IS NULL".to_string()];
        let mut param_idx = 1usize;

        if realm_id.is_some() {
            where_clauses.push(format!("realm_id = ${param_idx}"));
            param_idx += 1;
        }

        if search.is_some() {
            where_clauses.push(format!(
                "(name ILIKE ${} OR description ILIKE ${})",
                param_idx, param_idx
            ));
            param_idx += 1;
        }

        let where_sql = where_clauses.join(" AND ");
        let limit_idx = param_idx;
        let offset_idx = param_idx + 1;

        let sql = format!(
            "SELECT {ROLE_COLUMNS} FROM roles WHERE {where_sql} ORDER BY created_at DESC LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );

        let pattern = search.map(|s| format!("%{}%", escape_like(s)));

        let mut params: Vec<&dyn wasi_pg_client::ToSql> = Vec::new();
        if realm_id.is_some() {
            params.push(realm_id.as_ref().unwrap());
        }
        if let Some(ref p) = pattern {
            params.push(p);
        }
        params.push(&limit);
        params.push(&offset);

        let result = conn
            .query_params(&sql, &params)
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Count roles in a realm. If realm_id is None, counts all realms.
    pub async fn count(
        &self,
        conn: &mut Connection,
        realm_id: Option<Uuid>,
    ) -> Result<i64, OidcError> {
        let sql = match realm_id {
            Some(_) => "SELECT COUNT(*) FROM roles WHERE deleted_at IS NULL AND realm_id = $1",
            None => "SELECT COUNT(*) FROM roles WHERE deleted_at IS NULL",
        };
        let result = match realm_id.as_ref() {
            Some(rid) => conn
                .query_params(sql, &[rid])
                .await
                .map_err(mapper::pg_err)?,
            None => conn.query_params(sql, &[]).await.map_err(mapper::pg_err)?,
        };
        let row = result
            .into_rows()
            .into_iter()
            .next()
            .ok_or(OidcError::Internal("count returned no rows".into()))?;
        mapper::i64_(&row, 0)
    }

    /// Find all roles assigned to a user (through user_roles junction).
    pub async fn find_by_user_id(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<Role>, OidcError> {
        let sql = &format!(
            "SELECT r.{ROLE_COLUMNS} FROM roles r \
             INNER JOIN user_roles ur ON ur.role_id = r.id \
             WHERE ur.user_id = $1 AND r.deleted_at IS NULL"
        );
        let result = conn
            .query_params(sql, &[&user_id])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<Role, OidcError> {
        Ok(Role {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::uuid(row, 1)?,
            name: mapper::string(row, 2)?,
            description: mapper::opt_string(row, 3)?,
            permissions: mapper::json_string_vec(row, 4)?,
            created_at: mapper::datetime(row, 5)?,
            updated_at: mapper::datetime(row, 6)?,
        })
    }
}
