use crate::{Connection, mapper};
use oidc_core::{OidcError, models::UserConsent};
use uuid::Uuid;

pub struct UserConsentRepo;

const COLUMNS: &str = "id, user_id, realm_id, client_id, scopes, created_at, updated_at";

impl UserConsentRepo {
    pub async fn find(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
        client_id: Uuid,
    ) -> Result<Option<UserConsent>, OidcError> {
        let sql =
            format!("SELECT {COLUMNS} FROM user_consents WHERE user_id = $1 AND client_id = $2");
        let row = conn
            .query_one_params(&sql, &[&user_id, &client_id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|row| Self::map_row(&row)).transpose()
    }

    pub async fn list_by_user(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<UserConsent>, OidcError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM user_consents WHERE user_id = $1 ORDER BY updated_at DESC"
        );
        let result = conn
            .query_params(&sql, &[&user_id])
            .await
            .map_err(mapper::pg_err)?;
        result.into_rows().iter().map(Self::map_row).collect()
    }

    pub async fn grant(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
        realm_id: Uuid,
        client_id: Uuid,
        scopes: &[String],
    ) -> Result<(), OidcError> {
        let mut combined = self
            .find(conn, user_id, client_id)
            .await?
            .map(|consent| consent.scopes)
            .unwrap_or_default();
        for scope in scopes {
            if !combined.contains(scope) {
                combined.push(scope.clone());
            }
        }
        combined.sort();
        let scopes = mapper::to_json_value_vec(&combined);
        let id = oidc_core::utils::generate_uuid_v7();
        conn.execute_params(
            r#"INSERT INTO user_consents (id, user_id, realm_id, client_id, scopes)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (user_id, client_id) DO UPDATE
               SET scopes = EXCLUDED.scopes, updated_at = NOW()"#,
            &[&id, &user_id, &realm_id, &client_id, &scopes],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn revoke(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
        client_id: Uuid,
    ) -> Result<u64, OidcError> {
        conn.execute_params(
            "DELETE FROM user_consents WHERE user_id = $1 AND client_id = $2",
            &[&user_id, &client_id],
        )
        .await
        .map_err(mapper::pg_err)
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<UserConsent, OidcError> {
        Ok(UserConsent {
            id: mapper::uuid(row, 0)?,
            user_id: mapper::uuid(row, 1)?,
            realm_id: mapper::uuid(row, 2)?,
            client_id: mapper::uuid(row, 3)?,
            scopes: mapper::json_string_vec(row, 4)?,
            created_at: mapper::datetime(row, 5)?,
            updated_at: mapper::datetime(row, 6)?,
        })
    }
}
