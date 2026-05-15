use serde::{Deserialize, Serialize};

/// A single authorization detail per RFC 9396.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationDetail {
    /// The type of authorization being requested (required per RFC 9396 §2).
    #[serde(rename = "type")]
    pub detail_type: String,
    /// The locations (resource servers) the client wants to access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,
    /// The actions the client wants to perform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    /// The data types the client wants to access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datatypes: Option<Vec<String>>,
    /// The identifier of the resource being accessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    /// Privileges being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges: Option<Vec<String>>,
    /// Any additional fields not in the standard.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Stored authorization details for an auth code or session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationDetails(pub Vec<AuthorizationDetail>);

impl AuthorizationDetails {
    /// Parse from a JSON value (the `authorization_details` parameter).
    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, crate::OidcError> {
        let details: Vec<AuthorizationDetail> =
            serde_json::from_value(value.clone()).map_err(|e| {
                crate::OidcError::InvalidInput(format!("Invalid authorization_details: {e}"))
            })?;
        // Validate each detail has a type
        for d in &details {
            if d.detail_type.is_empty() {
                return Err(crate::OidcError::InvalidInput(
                    "authorization_detail must have a 'type' field".into(),
                ));
            }
        }
        Ok(Self(details))
    }

    /// Convert to JSON value for storage.
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::to_value(&self.0).unwrap_or(serde_json::Value::Array(vec![]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_authorization_details() {
        let json = serde_json::json!([
            {
                "type": "payment_initiation",
                "actions": ["initiate"],
                "locations": ["https://api.example.com/payments"],
                "identifier": "account-123"
            }
        ]);
        let details = AuthorizationDetails::from_json_value(&json).unwrap();
        assert_eq!(details.0.len(), 1);
        assert_eq!(details.0[0].detail_type, "payment_initiation");
        assert_eq!(details.0[0].actions.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_parse_missing_type_fails() {
        let json = serde_json::json!([
            {
                "actions": ["read"]
            }
        ]);
        let result = AuthorizationDetails::from_json_value(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_type_fails() {
        let json = serde_json::json!([
            {
                "type": ""
            }
        ]);
        let result = AuthorizationDetails::from_json_value(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_to_json_value_roundtrip() {
        let json = serde_json::json!([
            {
                "type": "account_information",
                "actions": ["read"],
                "locations": ["https://api.example.com/accounts"]
            }
        ]);
        let details = AuthorizationDetails::from_json_value(&json).unwrap();
        let roundtrip = details.to_json_value();
        assert_eq!(roundtrip, json);
    }

    #[test]
    fn test_extra_fields_preserved() {
        let json = serde_json::json!([
            {
                "type": "custom",
                "custom_field": "custom_value",
                "nested": {"key": "value"}
            }
        ]);
        let details = AuthorizationDetails::from_json_value(&json).unwrap();
        assert_eq!(
            details.0[0].extra.get("custom_field").unwrap(),
            "custom_value"
        );
    }
}
