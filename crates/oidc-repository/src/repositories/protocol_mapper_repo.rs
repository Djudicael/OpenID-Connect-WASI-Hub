use oidc_core::{
    OidcError,
    models::{ProtocolMapper, ProtocolMapperType},
};
use uuid::Uuid;

use crate::{connection::Connection, mapper};

const COLUMNS: &str = "id, scope_id, name, mapper_type, claim_name, source, claim_value, multivalued, add_to_access_token, add_to_id_token, add_to_userinfo";
const PM_COLUMNS: &str = "pm.id, pm.scope_id, pm.name, pm.mapper_type, pm.claim_name, pm.source, pm.claim_value, pm.multivalued, pm.add_to_access_token, pm.add_to_id_token, pm.add_to_userinfo";

pub struct ProtocolMapperRepo;

impl ProtocolMapperRepo {
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<ProtocolMapper>, OidcError> {
        conn.query_one_params(
            &format!("SELECT {COLUMNS} FROM protocol_mappers WHERE id = $1"),
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)?
        .map(|row| map_row(&row))
        .transpose()
    }

    pub async fn list_by_scope(
        &self,
        conn: &mut Connection,
        scope_id: Uuid,
    ) -> Result<Vec<ProtocolMapper>, OidcError> {
        conn.query_params(
            &format!("SELECT {COLUMNS} FROM protocol_mappers WHERE scope_id = $1 ORDER BY name"),
            &[&scope_id],
        )
        .await
        .map_err(mapper::pg_err)?
        .into_rows()
        .iter()
        .map(map_row)
        .collect()
    }

    pub async fn list_active_for_client(
        &self,
        conn: &mut Connection,
        client_id: Uuid,
        granted_scopes: &[String],
    ) -> Result<Vec<ProtocolMapper>, OidcError> {
        let scopes = mapper::to_json_value_vec(granted_scopes);
        conn.query_params(
            &format!("SELECT {PM_COLUMNS} FROM protocol_mappers pm JOIN scopes s ON s.id = pm.scope_id JOIN client_scopes cs ON cs.scope_id = s.id WHERE cs.client_id = $1 AND s.enabled = TRUE AND s.name IN (SELECT jsonb_array_elements_text($2::jsonb)) ORDER BY s.name, pm.name"),
            &[&client_id, &scopes],
        ).await.map_err(mapper::pg_err)?.into_rows().iter().map(map_row).collect()
    }

    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &ProtocolMapper,
    ) -> Result<(), OidcError> {
        entity.validate()?;
        conn.execute_params(
            "INSERT INTO protocol_mappers (id, scope_id, name, mapper_type, claim_name, source, claim_value, multivalued, add_to_access_token, add_to_id_token, add_to_userinfo) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            &[&entity.id, &entity.scope_id, &entity.name, &entity.mapper_type.as_str(), &entity.claim_name, &entity.source, &entity.claim_value, &entity.multivalued, &entity.add_to_access_token, &entity.add_to_id_token, &entity.add_to_userinfo],
        ).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn update(
        &self,
        conn: &mut Connection,
        entity: &ProtocolMapper,
    ) -> Result<(), OidcError> {
        entity.validate()?;
        conn.execute_params(
            "UPDATE protocol_mappers SET name=$1, mapper_type=$2, claim_name=$3, source=$4, claim_value=$5, multivalued=$6, add_to_access_token=$7, add_to_id_token=$8, add_to_userinfo=$9, updated_at=NOW() WHERE id=$10",
            &[&entity.name, &entity.mapper_type.as_str(), &entity.claim_name, &entity.source, &entity.claim_value, &entity.multivalued, &entity.add_to_access_token, &entity.add_to_id_token, &entity.add_to_userinfo, &entity.id],
        ).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params("DELETE FROM protocol_mappers WHERE id=$1", &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }
}

fn map_row(row: &wasi_pg_client::Row) -> Result<ProtocolMapper, OidcError> {
    let mapper_type = ProtocolMapperType::try_from(mapper::string(row, 3)?.as_str())?;
    Ok(ProtocolMapper {
        id: mapper::uuid(row, 0)?,
        scope_id: mapper::uuid(row, 1)?,
        name: mapper::string(row, 2)?,
        mapper_type,
        claim_name: mapper::opt_string(row, 4)?,
        source: mapper::opt_string(row, 5)?,
        claim_value: row
            .get::<Option<serde_json::Value>>(6)
            .map_err(mapper::pg_err)?,
        multivalued: mapper::bool_(row, 7)?,
        add_to_access_token: mapper::bool_(row, 8)?,
        add_to_id_token: mapper::bool_(row, 9)?,
        add_to_userinfo: mapper::bool_(row, 10)?,
    })
}
