use crate::{connection::Connection, mapper};
use oidc_core::{OidcError, models::Role};
use uuid::Uuid;

const ROLE_COLUMNS: &str = "r.id, r.realm_id, r.name, r.description, r.permissions, r.created_at, r.updated_at, r.client_id";

pub struct RoleCompositeRepo;

impl RoleCompositeRepo {
    pub async fn add(
        &self,
        conn: &mut Connection,
        parent_role_id: Uuid,
        child_role_id: Uuid,
    ) -> Result<(), OidcError> {
        if parent_role_id == child_role_id
            || self
                .would_create_cycle(conn, parent_role_id, child_role_id)
                .await?
        {
            return Err(OidcError::InvalidInput(
                "A composite role cannot contain itself directly or indirectly".into(),
            ));
        }
        conn.execute_params(
            "INSERT INTO role_composites (parent_role_id, child_role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&parent_role_id, &child_role_id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn remove(
        &self,
        conn: &mut Connection,
        parent_role_id: Uuid,
        child_role_id: Uuid,
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "DELETE FROM role_composites WHERE parent_role_id = $1 AND child_role_id = $2",
            &[&parent_role_id, &child_role_id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn list_children(
        &self,
        conn: &mut Connection,
        parent_role_id: Uuid,
    ) -> Result<Vec<Role>, OidcError> {
        conn.query_params(
            &format!("SELECT {ROLE_COLUMNS} FROM roles r JOIN role_composites rc ON rc.child_role_id = r.id WHERE rc.parent_role_id = $1 AND r.deleted_at IS NULL ORDER BY r.name"),
            &[&parent_role_id],
        )
        .await
        .map_err(mapper::pg_err)?
        .into_rows()
        .iter()
        .map(map_role)
        .collect()
    }

    async fn would_create_cycle(
        &self,
        conn: &mut Connection,
        parent_role_id: Uuid,
        child_role_id: Uuid,
    ) -> Result<bool, OidcError> {
        let row = conn
            .query_one_params(
                "WITH RECURSIVE descendants(id) AS (\
                   SELECT child_role_id FROM role_composites WHERE parent_role_id = $1 \
                   UNION \
                   SELECT rc.child_role_id FROM role_composites rc JOIN descendants d ON rc.parent_role_id = d.id\
                 ) SELECT EXISTS(SELECT 1 FROM descendants WHERE id = $2)",
                &[&child_role_id, &parent_role_id],
            )
            .await
            .map_err(mapper::pg_err)?
            .ok_or_else(|| OidcError::Internal("cycle check returned no row".into()))?;
        mapper::bool_(&row, 0)
    }
}

fn map_role(row: &wasi_pg_client::Row) -> Result<Role, OidcError> {
    Ok(Role {
        id: mapper::uuid(row, 0)?,
        realm_id: mapper::uuid(row, 1)?,
        name: mapper::string(row, 2)?,
        description: mapper::opt_string(row, 3)?,
        permissions: mapper::json_string_vec(row, 4)?,
        created_at: mapper::datetime(row, 5)?,
        updated_at: mapper::datetime(row, 6)?,
        client_id: mapper::opt_uuid(row, 7)?,
    })
}
