use serde::{Deserialize, Serialize};

use crate::OidcError;

/// Parsed `response_type` from an OIDC authorization request.
///
/// Per OIDC Core §3:
/// - `code` → Authorization Code Flow
/// - `token` → OAuth2 Implicit Flow (access token only)
/// - `id_token` → OIDC Implicit Flow (ID token only)
/// - `code token` → Hybrid Flow
/// - `code id_token` → Hybrid Flow
/// - `id_token token` → OIDC Implicit Flow
/// - `code id_token token` → Hybrid Flow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub struct ResponseType {
    code: bool,
    token: bool,
    id_token: bool,
}

impl ResponseType {
    /// Authorization Code Flow only.
    pub const CODE: Self = Self {
        code: true,
        token: false,
        id_token: false,
    };

    /// OAuth2 Implicit Flow (access token).
    pub const TOKEN: Self = Self {
        code: false,
        token: true,
        id_token: false,
    };

    /// OIDC Implicit Flow (ID token).
    pub const ID_TOKEN: Self = Self {
        code: false,
        token: false,
        id_token: true,
    };

    /// Hybrid: code + access token.
    pub const CODE_TOKEN: Self = Self {
        code: true,
        token: true,
        id_token: false,
    };

    /// Hybrid: code + ID token.
    pub const CODE_ID_TOKEN: Self = Self {
        code: true,
        token: false,
        id_token: true,
    };

    /// OIDC Implicit Flow: ID token + access token.
    pub const ID_TOKEN_TOKEN: Self = Self {
        code: false,
        token: true,
        id_token: true,
    };

    /// Hybrid: code + ID token + access token.
    pub const CODE_ID_TOKEN_TOKEN: Self = Self {
        code: true,
        token: true,
        id_token: true,
    };

    /// All supported response types, in the order they should appear in discovery metadata.
    pub const ALL_SUPPORTED: &[Self] = &[
        Self::CODE,
        Self::TOKEN,
        Self::ID_TOKEN,
        Self::CODE_TOKEN,
        Self::CODE_ID_TOKEN,
        Self::ID_TOKEN_TOKEN,
        Self::CODE_ID_TOKEN_TOKEN,
    ];

    /// Parse a space-separated `response_type` string.
    pub fn parse(s: &str) -> Result<Self, OidcError> {
        let parts: std::collections::HashSet<&str> = s.split(' ').collect();

        let code = parts.contains("code");
        let token = parts.contains("token");
        let id_token = parts.contains("id_token");

        // Reject unknown components
        let known = ["code", "token", "id_token"];
        for part in &parts {
            if !known.contains(part) {
                return Err(OidcError::InvalidInput(format!(
                    "unsupported response_type component: {}",
                    part
                )));
            }
        }

        // At least one component must be present
        if !code && !token && !id_token {
            return Err(OidcError::InvalidInput(
                "response_type must contain at least one of: code, token, id_token".into(),
            ));
        }

        Ok(Self {
            code,
            token,
            id_token,
        })
    }

    /// Returns the canonical space-separated string representation.
    pub fn as_str(&self) -> &'static str {
        match (self.code, self.token, self.id_token) {
            (true, false, false) => "code",
            (false, true, false) => "token",
            (false, false, true) => "id_token",
            (true, true, false) => "code token",
            (true, false, true) => "code id_token",
            (false, true, true) => "id_token token",
            (true, true, true) => "code id_token token",
            _ => unreachable!(),
        }
    }

    pub fn has_code(&self) -> bool {
        self.code
    }

    pub fn has_token(&self) -> bool {
        self.token
    }

    pub fn has_id_token(&self) -> bool {
        self.id_token
    }

    /// Returns true if this is an implicit or hybrid flow that returns tokens
    /// directly in the authorization response (rather than just a code).
    pub fn is_implicit_or_hybrid(&self) -> bool {
        self.token || self.id_token
    }
}

impl From<String> for ResponseType {
    fn from(s: String) -> Self {
        Self::parse(&s).unwrap_or(Self::CODE)
    }
}

impl<'a> From<&'a str> for ResponseType {
    fn from(s: &'a str) -> Self {
        Self::parse(s).unwrap_or(Self::CODE)
    }
}

impl From<ResponseType> for String {
    fn from(rt: ResponseType) -> Self {
        rt.to_string()
    }
}

impl std::fmt::Display for ResponseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_code() {
        let rt = ResponseType::parse("code").unwrap();
        assert!(rt.has_code());
        assert!(!rt.has_token());
        assert!(!rt.has_id_token());
        assert_eq!(rt.as_str(), "code");
    }

    #[test]
    fn test_parse_token() {
        let rt = ResponseType::parse("token").unwrap();
        assert!(!rt.has_code());
        assert!(rt.has_token());
        assert!(!rt.has_id_token());
        assert_eq!(rt.as_str(), "token");
    }

    #[test]
    fn test_parse_id_token() {
        let rt = ResponseType::parse("id_token").unwrap();
        assert!(!rt.has_code());
        assert!(!rt.has_token());
        assert!(rt.has_id_token());
        assert_eq!(rt.as_str(), "id_token");
    }

    #[test]
    fn test_parse_code_token() {
        let rt = ResponseType::parse("code token").unwrap();
        assert!(rt.has_code());
        assert!(rt.has_token());
        assert!(!rt.has_id_token());
        assert_eq!(rt.as_str(), "code token");
    }

    #[test]
    fn test_parse_code_id_token() {
        let rt = ResponseType::parse("code id_token").unwrap();
        assert!(rt.has_code());
        assert!(!rt.has_token());
        assert!(rt.has_id_token());
        assert_eq!(rt.as_str(), "code id_token");
    }

    #[test]
    fn test_parse_id_token_token() {
        let rt = ResponseType::parse("id_token token").unwrap();
        assert!(!rt.has_code());
        assert!(rt.has_token());
        assert!(rt.has_id_token());
        assert_eq!(rt.as_str(), "id_token token");
    }

    #[test]
    fn test_parse_code_id_token_token() {
        let rt = ResponseType::parse("code id_token token").unwrap();
        assert!(rt.has_code());
        assert!(rt.has_token());
        assert!(rt.has_id_token());
        assert_eq!(rt.as_str(), "code id_token token");
    }

    #[test]
    fn test_parse_unsupported() {
        let err = ResponseType::parse("none").unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(_)));
    }

    #[test]
    fn test_parse_empty() {
        let err = ResponseType::parse("").unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(_)));
    }

    #[test]
    fn test_display() {
        assert_eq!(ResponseType::CODE.to_string(), "code");
        assert_eq!(
            ResponseType::CODE_ID_TOKEN_TOKEN.to_string(),
            "code id_token token"
        );
    }
}
