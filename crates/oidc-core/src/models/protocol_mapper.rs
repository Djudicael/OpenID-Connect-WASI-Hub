use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::OidcError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolMapperType {
    UserProperty,
    UserAttribute,
    HardcodedClaim,
    Audience,
    RealmRoles,
    ClientRoles,
}

impl ProtocolMapperType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserProperty => "user_property",
            Self::UserAttribute => "user_attribute",
            Self::HardcodedClaim => "hardcoded_claim",
            Self::Audience => "audience",
            Self::RealmRoles => "realm_roles",
            Self::ClientRoles => "client_roles",
        }
    }
}

impl TryFrom<&str> for ProtocolMapperType {
    type Error = OidcError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "user_property" => Ok(Self::UserProperty),
            "user_attribute" => Ok(Self::UserAttribute),
            "hardcoded_claim" => Ok(Self::HardcodedClaim),
            "audience" => Ok(Self::Audience),
            "realm_roles" => Ok(Self::RealmRoles),
            "client_roles" => Ok(Self::ClientRoles),
            _ => Err(OidcError::InvalidInput(
                "unsupported protocol mapper type".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolMapper {
    pub id: Uuid,
    pub scope_id: Uuid,
    pub name: String,
    pub mapper_type: ProtocolMapperType,
    pub claim_name: Option<String>,
    pub source: Option<String>,
    pub claim_value: Option<Value>,
    pub multivalued: bool,
    pub add_to_access_token: bool,
    pub add_to_id_token: bool,
    pub add_to_userinfo: bool,
}

impl ProtocolMapper {
    pub fn validate(&self) -> Result<(), OidcError> {
        if self.name.trim().is_empty() {
            return Err(OidcError::InvalidInput(
                "mapper name must not be empty".into(),
            ));
        }
        if self.mapper_type == ProtocolMapperType::Audience {
            if self.claim_value.as_ref().and_then(Value::as_str).is_none() {
                return Err(OidcError::InvalidInput(
                    "audience mapper requires a string value".into(),
                ));
            }
            return Ok(());
        }
        let claim_name = self.claim_name.as_deref().unwrap_or("").trim();
        if claim_name.is_empty() {
            return Err(OidcError::InvalidInput(
                "claim name must not be empty".into(),
            ));
        }
        let root = claim_name.split('.').next().unwrap_or_default();
        if matches!(
            root,
            "iss"
                | "sub"
                | "aud"
                | "exp"
                | "iat"
                | "jti"
                | "scope"
                | "azp"
                | "nonce"
                | "auth_time"
                | "sid"
                | "at_hash"
                | "c_hash"
                | "cnf"
                | "authorization_details"
                | "organization"
                | "realm_access"
                | "resource_access"
                | "roles"
                | "groups"
                | "acr"
                | "amr"
                | "address"
                | "name"
                | "given_name"
                | "family_name"
                | "middle_name"
                | "nickname"
                | "preferred_username"
                | "profile"
                | "picture"
                | "website"
                | "gender"
                | "birthdate"
                | "zoneinfo"
                | "locale"
                | "email"
                | "email_verified"
                | "phone_number"
                | "phone_number_verified"
                | "updated_at"
        ) {
            return Err(OidcError::InvalidInput(
                "claim name conflicts with a protected token claim".into(),
            ));
        }
        match self.mapper_type {
            ProtocolMapperType::UserProperty
            | ProtocolMapperType::UserAttribute
            | ProtocolMapperType::ClientRoles
                if self.source.as_deref().unwrap_or("").trim().is_empty() =>
            {
                Err(OidcError::InvalidInput(
                    "this mapper type requires a source".into(),
                ))
            }
            ProtocolMapperType::UserProperty
                if !matches!(
                    self.source.as_deref(),
                    Some(
                        "id" | "email"
                            | "email_verified"
                            | "username"
                            | "given_name"
                            | "family_name"
                            | "middle_name"
                            | "nickname"
                            | "preferred_username"
                            | "profile"
                            | "picture"
                            | "website"
                            | "gender"
                            | "birthdate"
                            | "zoneinfo"
                            | "locale"
                            | "phone_number"
                            | "phone_number_verified"
                            | "updated_at"
                    )
                ) =>
            {
                Err(OidcError::InvalidInput("unsupported user property".into()))
            }
            ProtocolMapperType::HardcodedClaim if self.claim_value.is_none() => Err(
                OidcError::InvalidInput("hardcoded mapper requires a value".into()),
            ),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientScopeAssignment {
    pub scope_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub assignment_type: String,
}
