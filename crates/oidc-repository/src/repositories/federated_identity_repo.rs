use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::FederatedIdentity;
use uuid::Uuid;

/// PostgreSQL implementation of the FederatedIdentity repository.
pub struct FederatedIdentityRepo;

/// Column list for federated_identities SELECT queries (order must match map_row indices).
const FI_COLUMNS: &str = r#"
    id, user_id, realm_id, identity_provider_id,
    upstream_subject, upstream_username, upstream_email,
    created_at, last_used_at
"#;

impl FederatedIdentityRepo {
    /// Find a federated identity by the upstream subject identifier.
    pub async fn find_by_upstream_subject(
        &self,
        conn: &mut Connection,
        identity_provider_id: Uuid,
        upstream_subject: &str,
    ) -> Result<Option<FederatedIdentity>, OidcError> {
        let sql = &format!(
            "SELECT {FI_COLUMNS} FROM federated_identities WHERE identity_provider_id = $1 AND upstream_subject = $2"
        );
        let row = conn
            .query_one_params(sql, &[&identity_provider_id, &upstream_subject])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find all federated identities for a user.
    pub async fn find_by_user_id(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<FederatedIdentity>, OidcError> {
        let sql = &format!("SELECT {FI_COLUMNS} FROM federated_identities WHERE user_id = $1");
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

    /// Insert a new federated identity.
    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &FederatedIdentity,
    ) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO federated_identities (
                id, user_id, realm_id, identity_provider_id,
                upstream_subject, upstream_username, upstream_email,
                created_at, last_used_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.user_id,
                &entity.realm_id,
                &entity.identity_provider_id,
                &entity.upstream_subject,
                &entity.upstream_username,
                &entity.upstream_email,
                &entity.created_at,
                &entity.last_used_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Update the last_used_at timestamp for a federated identity.
    pub async fn update_last_used(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE federated_identities SET last_used_at = NOW() WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<FederatedIdentity, OidcError> {
        Ok(FederatedIdentity {
            id: mapper::uuid(row, 0)?,
            user_id: mapper::uuid(row, 1)?,
            realm_id: mapper::uuid(row, 2)?,
            identity_provider_id: mapper::uuid(row, 3)?,
            upstream_subject: mapper::string(row, 4)?,
            upstream_username: mapper::opt_string(row, 5)?,
            upstream_email: mapper::opt_string(row, 6)?,
            created_at: mapper::datetime(row, 7)?,
            last_used_at: mapper::opt_datetime(row, 8)?,
        })
    }
}
