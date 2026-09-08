use oidc_core::OidcError;
use oidc_core::models::{FederatedDirectoryUser, UserFederationProvider};
use uuid::Uuid;

use crate::{connection::Connection, mapper};

pub struct UserFederationRepo;

const PROVIDER_COLUMNS: &str = "id, realm_id, name, provider_type, enabled, priority, gateway_url, gateway_secret, config, import_users, sync_groups, last_sync_at, last_sync_status, last_sync_error, created_at, updated_at";
const LINK_COLUMNS: &str = "id, provider_id, user_id, external_id, external_username, external_dn, last_login_at, last_synced_at";

impl UserFederationRepo {
    pub async fn find_provider(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<UserFederationProvider>, OidcError> {
        let sql = format!(
            "SELECT {PROVIDER_COLUMNS} FROM user_federation_providers WHERE id = $1 AND deleted_at IS NULL"
        );
        conn.query_one_params(&sql, &[&id])
            .await
            .map_err(mapper::pg_err)?
            .map(|row| Self::map_provider(&row))
            .transpose()
    }

    pub async fn list_providers(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<Vec<UserFederationProvider>, OidcError> {
        let sql = format!(
            "SELECT {PROVIDER_COLUMNS} FROM user_federation_providers WHERE realm_id = $1 AND deleted_at IS NULL ORDER BY priority, name"
        );
        conn.query_params(&sql, &[&realm_id])
            .await
            .map_err(mapper::pg_err)?
            .into_rows()
            .iter()
            .map(Self::map_provider)
            .collect()
    }

    pub async fn list_enabled(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<Vec<UserFederationProvider>, OidcError> {
        let sql = format!(
            "SELECT {PROVIDER_COLUMNS} FROM user_federation_providers WHERE realm_id = $1 AND enabled = TRUE AND deleted_at IS NULL ORDER BY priority, name"
        );
        conn.query_params(&sql, &[&realm_id])
            .await
            .map_err(mapper::pg_err)?
            .into_rows()
            .iter()
            .map(Self::map_provider)
            .collect()
    }

    pub async fn create_provider(
        &self,
        conn: &mut Connection,
        value: &UserFederationProvider,
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "INSERT INTO user_federation_providers (id, realm_id, name, provider_type, enabled, priority, gateway_url, gateway_secret, config, import_users, sync_groups, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            &[&value.id, &value.realm_id, &value.name, &value.provider_type.to_string(), &value.enabled, &value.priority, &value.gateway_url, &value.gateway_secret, &value.config, &value.import_users, &value.sync_groups, &value.created_at, &value.updated_at],
        ).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn update_provider(
        &self,
        conn: &mut Connection,
        value: &UserFederationProvider,
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE user_federation_providers SET name=$1, provider_type=$2, enabled=$3, priority=$4, gateway_url=$5, gateway_secret=$6, config=$7, import_users=$8, sync_groups=$9, updated_at=NOW() WHERE id=$10 AND deleted_at IS NULL",
            &[&value.name, &value.provider_type.to_string(), &value.enabled, &value.priority, &value.gateway_url, &value.gateway_secret, &value.config, &value.import_users, &value.sync_groups, &value.id],
        ).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn delete_provider(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params("UPDATE user_federation_providers SET deleted_at=NOW(), enabled=FALSE, updated_at=NOW() WHERE id=$1", &[&id]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn record_sync(
        &self,
        conn: &mut Connection,
        id: Uuid,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), OidcError> {
        conn.execute_params("UPDATE user_federation_providers SET last_sync_at=NOW(), last_sync_status=$1, last_sync_error=$2, updated_at=NOW() WHERE id=$3", &[&status, &error, &id]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn find_link_by_external_id(
        &self,
        conn: &mut Connection,
        provider_id: Uuid,
        external_id: &str,
    ) -> Result<Option<FederatedDirectoryUser>, OidcError> {
        let sql = format!(
            "SELECT {LINK_COLUMNS} FROM federated_directory_users WHERE provider_id=$1 AND external_id=$2"
        );
        conn.query_one_params(&sql, &[&provider_id, &external_id])
            .await
            .map_err(mapper::pg_err)?
            .map(|row| Self::map_link(&row))
            .transpose()
    }

    pub async fn upsert_link(
        &self,
        conn: &mut Connection,
        value: &FederatedDirectoryUser,
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "INSERT INTO federated_directory_users (id, provider_id, user_id, external_id, external_username, external_dn, last_login_at, last_synced_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (provider_id, external_id) DO UPDATE SET user_id=EXCLUDED.user_id, external_username=EXCLUDED.external_username, external_dn=EXCLUDED.external_dn, last_login_at=COALESCE(EXCLUDED.last_login_at, federated_directory_users.last_login_at), last_synced_at=EXCLUDED.last_synced_at",
            &[&value.id, &value.provider_id, &value.user_id, &value.external_id, &value.external_username, &value.external_dn, &value.last_login_at, &value.last_synced_at],
        ).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn count_links(
        &self,
        conn: &mut Connection,
        provider_id: Uuid,
    ) -> Result<i64, OidcError> {
        let row = conn
            .query_one_params(
                "SELECT COUNT(*) FROM federated_directory_users WHERE provider_id=$1",
                &[&provider_id],
            )
            .await
            .map_err(mapper::pg_err)?
            .ok_or_else(|| OidcError::Internal("count query returned no row".into()))?;
        row.get::<i64>(0).map_err(mapper::pg_err)
    }

    fn map_provider(row: &wasi_pg_client::Row) -> Result<UserFederationProvider, OidcError> {
        Ok(UserFederationProvider {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::uuid(row, 1)?,
            name: mapper::string(row, 2)?,
            provider_type: mapper::string(row, 3)?.parse()?,
            enabled: mapper::bool_(row, 4)?,
            priority: row.get::<i32>(5).map_err(mapper::pg_err)?,
            gateway_url: mapper::string(row, 6)?,
            gateway_secret: mapper::string(row, 7)?,
            config: row.get::<serde_json::Value>(8).map_err(mapper::pg_err)?,
            import_users: mapper::bool_(row, 9)?,
            sync_groups: mapper::bool_(row, 10)?,
            last_sync_at: mapper::opt_datetime(row, 11)?,
            last_sync_status: mapper::opt_string(row, 12)?,
            last_sync_error: mapper::opt_string(row, 13)?,
            created_at: mapper::datetime(row, 14)?,
            updated_at: mapper::datetime(row, 15)?,
        })
    }

    fn map_link(row: &wasi_pg_client::Row) -> Result<FederatedDirectoryUser, OidcError> {
        Ok(FederatedDirectoryUser {
            id: mapper::uuid(row, 0)?,
            provider_id: mapper::uuid(row, 1)?,
            user_id: mapper::uuid(row, 2)?,
            external_id: mapper::string(row, 3)?,
            external_username: mapper::string(row, 4)?,
            external_dn: mapper::opt_string(row, 5)?,
            last_login_at: mapper::opt_datetime(row, 6)?,
            last_synced_at: mapper::datetime(row, 7)?,
        })
    }
}
