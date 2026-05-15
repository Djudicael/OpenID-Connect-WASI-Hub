use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::Role;
use uuid::Uuid;

/// Column list for role SELECT queries (order must match RoleRepo::map_row indices).
const ROLE_COLUMNS: &str = r#"
    r.id, r.realm_id, r.name, r.description, r.permissions, r.created_at, r.updated_at
"#;

/// PostgreSQL implementation of the Group-Role assignment repository.
pub struct GroupRoleRepo;

impl GroupRoleRepo {
    /// Assign a role to a group.
    pub async fn assign(
        &self,
        conn: &mut Connection,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<(), OidcError> {
        let sql = "INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2)";
        conn.execute_params(sql, &[&group_id, &role_id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Unassign a role from a group.
    pub async fn unassign(
        &self,
        conn: &mut Connection,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<(), OidcError> {
        let sql = "DELETE FROM group_roles WHERE group_id = $1 AND role_id = $2";
        conn.execute_params(sql, &[&group_id, &role_id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Find all roles assigned to a group.
    pub async fn find_roles_by_group(
        &self,
        conn: &mut Connection,
        group_id: Uuid,
    ) -> Result<Vec<Role>, OidcError> {
        let sql = &format!(
            "SELECT {ROLE_COLUMNS} FROM roles r \
             INNER JOIN group_roles gr ON gr.role_id = r.id \
             WHERE gr.group_id = $1 AND r.deleted_at IS NULL"
        );
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
