use crate::{Connection, mapper};
use oidc_core::{
    OidcError,
    models::{SamlPendingRequest, SamlRealmKey, SamlServiceProvider},
};
use uuid::Uuid;

pub struct SamlRepo;

const SP_COLUMNS: &str = "id, realm_id, name, entity_id, metadata_xml, enabled, require_signed_requests, sign_responses, sign_assertions, encrypt_assertions, attribute_mapping, created_at, updated_at, deleted_at";
const PENDING_COLUMNS: &str = "id, token_hash, realm_id, service_provider_id, identity_provider_id, purpose, wire_payload, binding, relay_state, tracker, return_to, expires_at, used, created_at";

impl SamlRepo {
    pub async fn get_key(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<Option<SamlRealmKey>, OidcError> {
        let row = conn.query_one_params("SELECT realm_id, private_key_encrypted, certificate_pem, created_at, updated_at FROM saml_realm_keys WHERE realm_id = $1", &[&realm_id]).await.map_err(mapper::pg_err)?;
        row.map(|r| {
            Ok(SamlRealmKey {
                realm_id: mapper::uuid(&r, 0)?,
                private_key_encrypted: mapper::string(&r, 1)?,
                certificate_pem: mapper::string(&r, 2)?,
                created_at: mapper::datetime(&r, 3)?,
                updated_at: mapper::datetime(&r, 4)?,
            })
        })
        .transpose()
    }

    pub async fn create_key(
        &self,
        conn: &mut Connection,
        key: &SamlRealmKey,
    ) -> Result<(), OidcError> {
        conn.execute_params("INSERT INTO saml_realm_keys (realm_id, private_key_encrypted, certificate_pem, created_at, updated_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (realm_id) DO NOTHING", &[&key.realm_id,&key.private_key_encrypted,&key.certificate_pem,&key.created_at,&key.updated_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn list_service_providers(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<Vec<SamlServiceProvider>, OidcError> {
        let rows=conn.query_params(&format!("SELECT {SP_COLUMNS} FROM saml_service_providers WHERE realm_id=$1 AND deleted_at IS NULL ORDER BY name"), &[&realm_id]).await.map_err(mapper::pg_err)?;
        rows.into_rows().iter().map(Self::map_sp).collect()
    }

    pub async fn find_service_provider(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<SamlServiceProvider>, OidcError> {
        let row=conn.query_one_params(&format!("SELECT {SP_COLUMNS} FROM saml_service_providers WHERE id=$1 AND deleted_at IS NULL"), &[&id]).await.map_err(mapper::pg_err)?;
        row.map(|r| Self::map_sp(&r)).transpose()
    }

    pub async fn create_service_provider(
        &self,
        conn: &mut Connection,
        sp: &SamlServiceProvider,
    ) -> Result<(), OidcError> {
        conn.execute_params("INSERT INTO saml_service_providers (id,realm_id,name,entity_id,metadata_xml,enabled,require_signed_requests,sign_responses,sign_assertions,encrypt_assertions,attribute_mapping,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)", &[&sp.id,&sp.realm_id,&sp.name,&sp.entity_id,&sp.metadata_xml,&sp.enabled,&sp.require_signed_requests,&sp.sign_responses,&sp.sign_assertions,&sp.encrypt_assertions,&sp.attribute_mapping,&sp.created_at,&sp.updated_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn update_service_provider(
        &self,
        conn: &mut Connection,
        sp: &SamlServiceProvider,
    ) -> Result<(), OidcError> {
        conn.execute_params("UPDATE saml_service_providers SET name=$1,metadata_xml=$2,enabled=$3,require_signed_requests=$4,sign_responses=$5,sign_assertions=$6,encrypt_assertions=$7,attribute_mapping=$8,updated_at=NOW() WHERE id=$9 AND deleted_at IS NULL", &[&sp.name,&sp.metadata_xml,&sp.enabled,&sp.require_signed_requests,&sp.sign_responses,&sp.sign_assertions,&sp.encrypt_assertions,&sp.attribute_mapping,&sp.id]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn delete_service_provider(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<u64, OidcError> {
        conn.execute_params(
            "UPDATE saml_service_providers SET deleted_at=NOW() WHERE id=$1 AND deleted_at IS NULL",
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)
    }

    pub async fn create_pending(
        &self,
        conn: &mut Connection,
        p: &SamlPendingRequest,
    ) -> Result<(), OidcError> {
        conn.execute_params("INSERT INTO saml_pending_requests (id,token_hash,realm_id,service_provider_id,identity_provider_id,purpose,wire_payload,binding,relay_state,tracker,return_to,expires_at,used,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)", &[&p.id,&p.token_hash,&p.realm_id,&p.service_provider_id,&p.identity_provider_id,&p.purpose,&p.wire_payload,&p.binding,&p.relay_state,&p.tracker,&p.return_to,&p.expires_at,&p.used,&p.created_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn consume_pending(
        &self,
        conn: &mut Connection,
        hash: &str,
        purpose: &str,
    ) -> Result<Option<SamlPendingRequest>, OidcError> {
        let row=conn.query_one_params(&format!("UPDATE saml_pending_requests SET used=TRUE WHERE id=(SELECT id FROM saml_pending_requests WHERE token_hash=$1 AND purpose=$2 AND NOT used AND expires_at>NOW() LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING {PENDING_COLUMNS}"), &[&hash,&purpose]).await.map_err(mapper::pg_err)?;
        row.map(|r| Self::map_pending(&r)).transpose()
    }

    pub async fn find_pending(
        &self,
        conn: &mut Connection,
        hash: &str,
        purpose: &str,
    ) -> Result<Option<SamlPendingRequest>, OidcError> {
        let row=conn.query_one_params(&format!("SELECT {PENDING_COLUMNS} FROM saml_pending_requests WHERE token_hash=$1 AND purpose=$2 AND NOT used AND expires_at>NOW()"), &[&hash,&purpose]).await.map_err(mapper::pg_err)?;
        row.map(|r| Self::map_pending(&r)).transpose()
    }

    pub async fn mark_pending_used(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<bool, OidcError> {
        Ok(conn.execute_params("UPDATE saml_pending_requests SET used=TRUE WHERE id=$1 AND NOT used AND expires_at>NOW()", &[&id]).await.map_err(mapper::pg_err)? == 1)
    }

    pub async fn record_assertion(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
        assertion_id: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, OidcError> {
        let count=conn.execute_params("INSERT INTO saml_assertion_replays(assertion_id,realm_id,expires_at) VALUES($1,$2,$3) ON CONFLICT(realm_id,assertion_id) DO NOTHING", &[&assertion_id,&realm_id,&expires_at]).await.map_err(mapper::pg_err)?;
        Ok(count == 1)
    }

    pub async fn cleanup(&self, conn: &mut Connection) -> Result<u64, OidcError> {
        let a = conn
            .execute_params(
                "DELETE FROM saml_pending_requests WHERE used OR expires_at<=NOW()",
                &[],
            )
            .await
            .map_err(mapper::pg_err)?;
        let b = conn
            .execute_params(
                "DELETE FROM saml_assertion_replays WHERE expires_at<=NOW()",
                &[],
            )
            .await
            .map_err(mapper::pg_err)?;
        Ok(a + b)
    }

    fn map_sp(r: &wasi_pg_client::Row) -> Result<SamlServiceProvider, OidcError> {
        Ok(SamlServiceProvider {
            id: mapper::uuid(r, 0)?,
            realm_id: mapper::uuid(r, 1)?,
            name: mapper::string(r, 2)?,
            entity_id: mapper::string(r, 3)?,
            metadata_xml: mapper::string(r, 4)?,
            enabled: mapper::bool_(r, 5)?,
            require_signed_requests: mapper::bool_(r, 6)?,
            sign_responses: mapper::bool_(r, 7)?,
            sign_assertions: mapper::bool_(r, 8)?,
            encrypt_assertions: mapper::bool_(r, 9)?,
            attribute_mapping: mapper::json_value(r, 10)?,
            created_at: mapper::datetime(r, 11)?,
            updated_at: mapper::datetime(r, 12)?,
            deleted_at: mapper::opt_datetime(r, 13)?,
        })
    }
    fn map_pending(r: &wasi_pg_client::Row) -> Result<SamlPendingRequest, OidcError> {
        Ok(SamlPendingRequest {
            id: mapper::uuid(r, 0)?,
            token_hash: mapper::string(r, 1)?,
            realm_id: mapper::uuid(r, 2)?,
            service_provider_id: mapper::opt_uuid(r, 3)?,
            identity_provider_id: mapper::opt_uuid(r, 4)?,
            purpose: mapper::string(r, 5)?,
            wire_payload: mapper::opt_string(r, 6)?,
            binding: mapper::opt_string(r, 7)?,
            relay_state: mapper::opt_string(r, 8)?,
            tracker: mapper::opt_json_value(r, 9)?,
            return_to: mapper::opt_string(r, 10)?,
            expires_at: mapper::datetime(r, 11)?,
            used: mapper::bool_(r, 12)?,
            created_at: mapper::datetime(r, 13)?,
        })
    }
}
