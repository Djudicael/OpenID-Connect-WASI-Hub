use crate::{Connection, mapper};
use oidc_core::{
    OidcError,
    models::{CibaAuthenticationRequest, CibaClientConfig},
};
use uuid::Uuid;

pub struct CibaRepo;

const REQUEST_COLUMNS: &str = "id, auth_req_id_hash, auth_req_id_encrypted, client_id, realm_id, user_id, scope, binding_message, request_context, client_notification_token_encrypted, delivery_mode, client_notification_endpoint, status, interval_seconds, last_polled_at, requested_acr, auth_time, acr, amr, expires_at, created_at, updated_at";

impl CibaRepo {
    pub async fn config(
        &self,
        conn: &mut Connection,
        client_id: Uuid,
    ) -> Result<Option<CibaClientConfig>, OidcError> {
        let row = conn.query_one_params("SELECT client_id, delivery_mode, client_notification_endpoint, request_lifetime_seconds, polling_interval_seconds FROM ciba_client_configs WHERE client_id=$1", &[&client_id]).await.map_err(mapper::pg_err)?;
        row.map(|r| {
            Ok(CibaClientConfig {
                client_id: mapper::uuid(&r, 0)?,
                delivery_mode: mapper::string(&r, 1)?,
                client_notification_endpoint: mapper::opt_string(&r, 2)?,
                request_lifetime_seconds: mapper::i32_(&r, 3)?,
                polling_interval_seconds: mapper::i32_(&r, 4)?,
            })
        })
        .transpose()
    }

    pub async fn save_config(
        &self,
        conn: &mut Connection,
        config: &CibaClientConfig,
    ) -> Result<(), OidcError> {
        conn.execute_params("INSERT INTO ciba_client_configs (client_id,delivery_mode,client_notification_endpoint,request_lifetime_seconds,polling_interval_seconds) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (client_id) DO UPDATE SET delivery_mode=EXCLUDED.delivery_mode,client_notification_endpoint=EXCLUDED.client_notification_endpoint,request_lifetime_seconds=EXCLUDED.request_lifetime_seconds,polling_interval_seconds=EXCLUDED.polling_interval_seconds,updated_at=NOW()", &[&config.client_id,&config.delivery_mode,&config.client_notification_endpoint,&config.request_lifetime_seconds,&config.polling_interval_seconds]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn create(
        &self,
        conn: &mut Connection,
        r: &CibaAuthenticationRequest,
    ) -> Result<(), OidcError> {
        conn.execute_params("INSERT INTO ciba_authentication_requests (id,auth_req_id_hash,auth_req_id_encrypted,client_id,realm_id,user_id,scope,binding_message,request_context,client_notification_token_encrypted,delivery_mode,client_notification_endpoint,status,interval_seconds,last_polled_at,requested_acr,auth_time,acr,amr,expires_at,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)", &[&r.id,&r.auth_req_id_hash,&r.auth_req_id_encrypted,&r.client_id,&r.realm_id,&r.user_id,&mapper::to_json_value_vec(&r.scope),&r.binding_message,&r.request_context,&r.client_notification_token_encrypted,&r.delivery_mode,&r.client_notification_endpoint,&r.status,&r.interval_seconds,&r.last_polled_at,&mapper::to_json_value_vec(&r.requested_acr),&r.auth_time,&r.acr,&mapper::to_json_value_vec(&r.amr),&r.expires_at,&r.created_at,&r.updated_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn find_for_update(
        &self,
        conn: &mut Connection,
        hash: &str,
    ) -> Result<Option<CibaAuthenticationRequest>, OidcError> {
        let sql = format!(
            "SELECT {REQUEST_COLUMNS} FROM ciba_authentication_requests WHERE auth_req_id_hash=$1 FOR UPDATE"
        );
        let row = conn
            .query_one_params(&sql, &[&hash])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map(&r)).transpose()
    }

    pub async fn find_user_request(
        &self,
        conn: &mut Connection,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<CibaAuthenticationRequest>, OidcError> {
        let sql = format!(
            "SELECT {REQUEST_COLUMNS} FROM ciba_authentication_requests WHERE id=$1 AND user_id=$2"
        );
        let row = conn
            .query_one_params(&sql, &[&id, &user_id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map(&r)).transpose()
    }

    pub async fn list_pending_for_user(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<(CibaAuthenticationRequest, String, String)>, OidcError> {
        let request_columns = format!("r.{}", REQUEST_COLUMNS.replace(", ", ", r."));
        let sql = format!(
            "SELECT {request_columns}, c.name, c.client_id FROM ciba_authentication_requests r JOIN clients c ON c.id=r.client_id WHERE r.user_id=$1 AND r.status='pending' AND r.expires_at>NOW() ORDER BY r.created_at DESC"
        );
        let rows = conn
            .query_params(&sql, &[&user_id])
            .await
            .map_err(mapper::pg_err)?
            .into_rows();
        rows.iter()
            .map(|row| {
                Ok((
                    Self::map(row)?,
                    mapper::string(row, 22)?,
                    mapper::string(row, 23)?,
                ))
            })
            .collect()
    }

    pub async fn decide(
        &self,
        conn: &mut Connection,
        id: Uuid,
        user_id: Uuid,
        status: &str,
        auth_time: chrono::DateTime<chrono::Utc>,
        acr: &str,
        amr: &[String],
    ) -> Result<u64, OidcError> {
        conn.execute_params("UPDATE ciba_authentication_requests SET status=$3,auth_time=$4,acr=$5,amr=$6,updated_at=NOW() WHERE id=$1 AND user_id=$2 AND status='pending' AND expires_at>NOW()", &[&id,&user_id,&status,&auth_time,&acr,&mapper::to_json_value_vec(amr)]).await.map_err(mapper::pg_err)
    }

    pub async fn record_poll(
        &self,
        conn: &mut Connection,
        id: Uuid,
        interval: i32,
    ) -> Result<(), OidcError> {
        conn.execute_params("UPDATE ciba_authentication_requests SET last_polled_at=NOW(),interval_seconds=$2,updated_at=NOW() WHERE id=$1", &[&id,&interval]).await.map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn consume(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params("UPDATE ciba_authentication_requests SET status='consumed',updated_at=NOW() WHERE id=$1", &[&id]).await.map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn expire(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE ciba_authentication_requests SET status='expired',updated_at=NOW() WHERE id=$1",
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn cleanup_expired(&self, conn: &mut Connection) -> Result<u64, OidcError> {
        conn.execute_params(
            "DELETE FROM ciba_authentication_requests WHERE expires_at<NOW() OR (status IN ('consumed','denied','expired') AND updated_at<NOW()-INTERVAL '1 day')",
            &[],
        )
        .await
        .map_err(mapper::pg_err)
    }

    fn map(row: &wasi_pg_client::Row) -> Result<CibaAuthenticationRequest, OidcError> {
        Ok(CibaAuthenticationRequest {
            id: mapper::uuid(row, 0)?,
            auth_req_id_hash: mapper::string(row, 1)?,
            auth_req_id_encrypted: mapper::string(row, 2)?,
            client_id: mapper::uuid(row, 3)?,
            realm_id: mapper::uuid(row, 4)?,
            user_id: mapper::uuid(row, 5)?,
            scope: mapper::json_string_vec(row, 6)?,
            binding_message: mapper::opt_string(row, 7)?,
            request_context: mapper::opt_string(row, 8)?,
            client_notification_token_encrypted: mapper::opt_string(row, 9)?,
            delivery_mode: mapper::string(row, 10)?,
            client_notification_endpoint: mapper::opt_string(row, 11)?,
            status: mapper::string(row, 12)?,
            interval_seconds: mapper::i32_(row, 13)?,
            last_polled_at: mapper::opt_datetime(row, 14)?,
            requested_acr: mapper::json_string_vec(row, 15)?,
            auth_time: mapper::opt_datetime(row, 16)?,
            acr: mapper::opt_string(row, 17)?,
            amr: mapper::json_string_vec(row, 18)?,
            expires_at: mapper::datetime(row, 19)?,
            created_at: mapper::datetime(row, 20)?,
            updated_at: mapper::datetime(row, 21)?,
        })
    }
}
