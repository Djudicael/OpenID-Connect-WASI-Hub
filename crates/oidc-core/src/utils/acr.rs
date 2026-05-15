//! ACR (Authentication Context Class Reference) and AMR (Authentication Methods References) resolution.
//!
//! Per OIDC Core §3.1.2.1, the `acr_values` parameter in the authorization request
//! indicates the requested ACR values in order of preference. The OP must either
//! satisfy the request or return an error.
//!
//! Per OIDC Core §2.1, the `acr` claim in the ID token represents the ACR value
//! that was actually achieved, and the `amr` claim represents the authentication
//! methods used.

/// Supported ACR values, ordered from weakest to strongest.
pub const ACR_BRONZE: &str = "urn:mace:incommon:iap:bronze";
pub const ACR_SILVER: &str = "urn:mace:incommon:iap:silver";

/// All supported ACR values, ordered from weakest to strongest.
pub const SUPPORTED_ACR_VALUES: &[&str] = &[ACR_BRONZE, ACR_SILVER];

/// Supported AMR values.
pub const AMR_PWD: &str = "pwd";
pub const AMR_MFA: &str = "mfa";
pub const AMR_OTP: &str = "otp";
pub const AMR_SMS: &str = "sms";
pub const AMR_DEVICE_CODE: &str = "device_code";
pub const AMR_TOKEN_EXCHANGE: &str = "token_exchange";
pub const AMR_SOCIAL: &str = "social";

/// All supported AMR values.
pub const SUPPORTED_AMR_VALUES: &[&str] = &[
    AMR_PWD,
    AMR_MFA,
    AMR_OTP,
    AMR_SMS,
    AMR_DEVICE_CODE,
    AMR_TOKEN_EXCHANGE,
    AMR_SOCIAL,
];

/// Resolved ACR/AMR result for an authentication event.
#[derive(Debug, Clone)]
pub struct ResolvedAcrAmr {
    /// The ACR value that was achieved.
    pub acr: String,
    /// The authentication methods references.
    pub amr: Vec<String>,
}

/// Resolve the ACR and AMR values based on the authentication method and requested ACR values.
///
/// Per OIDC Core §3.1.2.2:
/// - If the OP can satisfy the requested ACR, it should do so.
/// - If the OP cannot satisfy any of the requested ACR values, it MUST return an error
///   (`login_required` or `account_selection_required`).
///
/// The `auth_method` parameter indicates how the user authenticated:
/// - `"pwd"` — password-based authentication
/// - `"device_code"` — device authorization flow
/// - `"token_exchange"` — token exchange
/// - `"social"` — social login / federation
/// - `"mfa"` — multi-factor authentication
/// - `"otp"` — one-time password
/// - `"sms"` — SMS-based authentication
///
/// The `requested_acr_values` parameter contains the space-separated ACR values from the
/// authorization request, in order of preference.
///
/// Returns `Ok(ResolvedAcrAmr)` if the authentication satisfies at least one requested ACR value
/// (or if no ACR values were requested), or `Err(acr_resolution_error)` if none can be satisfied.
pub fn resolve_acr_amr(
    auth_method: &str,
    requested_acr_values: &[String],
) -> Result<ResolvedAcrAmr, String> {
    // Determine the achieved ACR based on the authentication method
    let achieved_acr = match auth_method {
        "mfa" => ACR_SILVER, // MFA achieves silver
        "pwd" | "otp" | "sms" | "device_code" | "token_exchange" | "social" => ACR_BRONZE,
        _ => ACR_BRONZE, // Default to bronze for unknown methods
    };

    // Determine the AMR values
    let amr = match auth_method {
        "mfa" => vec![AMR_MFA.to_string(), AMR_PWD.to_string()],
        "otp" => vec![AMR_OTP.to_string()],
        "sms" => vec![AMR_SMS.to_string()],
        "device_code" => vec![AMR_DEVICE_CODE.to_string()],
        "token_exchange" => vec![AMR_TOKEN_EXCHANGE.to_string()],
        "social" => vec![AMR_SOCIAL.to_string()],
        _ => vec![AMR_PWD.to_string()],
    };

    // If no ACR values were requested, return the achieved ACR
    if requested_acr_values.is_empty() {
        return Ok(ResolvedAcrAmr {
            acr: achieved_acr.to_string(),
            amr,
        });
    }

    // Check if any requested ACR value can be satisfied
    // Per OIDC Core, the requested values are in order of preference
    for requested in requested_acr_values {
        // Check if the requested ACR is supported
        if !SUPPORTED_ACR_VALUES.contains(&requested.as_str()) {
            continue; // Skip unsupported ACR values
        }

        // Check if the achieved ACR satisfies the requested ACR
        // An achieved ACR satisfies a requested ACR if it is equal or stronger
        let achieved_level = acr_level(achieved_acr);
        let requested_level = acr_level(requested.as_str());

        if achieved_level >= requested_level {
            return Ok(ResolvedAcrAmr {
                acr: requested.clone(), // Return the requested ACR (not the achieved one)
                amr,
            });
        }
    }

    // None of the requested ACR values could be satisfied
    Err(format!(
        "Cannot satisfy any of the requested ACR values: {:?}. Achieved ACR: {}",
        requested_acr_values, achieved_acr
    ))
}

/// Get the numeric level of an ACR value for comparison.
/// Higher values indicate stronger authentication.
fn acr_level(acr: &str) -> u8 {
    match acr {
        ACR_BRONZE => 1,
        ACR_SILVER => 2,
        _ => 0, // Unknown ACR values are treated as level 0
    }
}

/// Select the best matching locale from the user's locale and the requested claims locales.
///
/// Per OIDC Core §5.2, the `claims_locales` parameter indicates the end-user's preferred
/// languages/scripts for claims returned. The OP should use this to select the most
/// appropriate localized claim values.
///
/// If the user's locale matches one of the requested locales, return it.
/// Otherwise, return the first requested locale if available, or the user's own locale.
pub fn resolve_locale(user_locale: &str, claims_locales: &[String]) -> String {
    if claims_locales.is_empty() {
        return user_locale.to_string();
    }

    // Check if the user's locale is in the requested locales (exact match or prefix match)
    for requested in claims_locales {
        if user_locale == requested || user_locale.starts_with(&format!("{}-", requested)) {
            return user_locale.to_string();
        }
    }

    // Check if any requested locale is a prefix of the user's locale
    for requested in claims_locales {
        if requested.starts_with(&format!("{}-", user_locale)) {
            return requested.clone();
        }
    }

    // No match — return the first requested locale as a hint for the OP
    // (The OP may not have claims in that locale, but it's the preferred one)
    claims_locales
        .first()
        .cloned()
        .unwrap_or_else(|| user_locale.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_acr_amr_no_request() {
        let result = resolve_acr_amr("pwd", &[]).unwrap();
        assert_eq!(result.acr, ACR_BRONZE);
        assert_eq!(result.amr, vec![AMR_PWD.to_string()]);
    }

    #[test]
    fn test_resolve_acr_amr_pwd_bronze_requested() {
        let result = resolve_acr_amr("pwd", &[ACR_BRONZE.to_string()]).unwrap();
        assert_eq!(result.acr, ACR_BRONZE);
        assert_eq!(result.amr, vec![AMR_PWD.to_string()]);
    }

    #[test]
    fn test_resolve_acr_amr_pwd_silver_requested_fails() {
        let result = resolve_acr_amr("pwd", &[ACR_SILVER.to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_acr_amr_mfa_silver_requested() {
        let result = resolve_acr_amr("mfa", &[ACR_SILVER.to_string()]).unwrap();
        assert_eq!(result.acr, ACR_SILVER);
        assert_eq!(result.amr, vec![AMR_MFA.to_string(), AMR_PWD.to_string()]);
    }

    #[test]
    fn test_resolve_acr_amr_mfa_bronze_requested() {
        // MFA achieves silver, which satisfies bronze request
        let result = resolve_acr_amr("mfa", &[ACR_BRONZE.to_string()]).unwrap();
        assert_eq!(result.acr, ACR_BRONZE);
        assert_eq!(result.amr, vec![AMR_MFA.to_string(), AMR_PWD.to_string()]);
    }

    #[test]
    fn test_resolve_acr_amr_mfa_bronze_and_silver_requested() {
        // Both requested, silver is preferred (stronger), and MFA satisfies it
        let result =
            resolve_acr_amr("mfa", &[ACR_SILVER.to_string(), ACR_BRONZE.to_string()]).unwrap();
        assert_eq!(result.acr, ACR_SILVER);
    }

    #[test]
    fn test_resolve_acr_amr_pwd_bronze_and_silver_requested() {
        // Password only achieves bronze, so silver can't be satisfied, but bronze can
        let result =
            resolve_acr_amr("pwd", &[ACR_SILVER.to_string(), ACR_BRONZE.to_string()]).unwrap();
        assert_eq!(result.acr, ACR_BRONZE);
    }

    #[test]
    fn test_resolve_acr_amr_unsupported_acr_ignored() {
        // Unsupported ACR values are skipped
        let result = resolve_acr_amr(
            "pwd",
            &["urn:unknown:acr".to_string(), ACR_BRONZE.to_string()],
        )
        .unwrap();
        assert_eq!(result.acr, ACR_BRONZE);
    }

    #[test]
    fn test_resolve_acr_amr_device_code() {
        let result = resolve_acr_amr("device_code", &[]).unwrap();
        assert_eq!(result.acr, ACR_BRONZE);
        assert_eq!(result.amr, vec![AMR_DEVICE_CODE.to_string()]);
    }

    #[test]
    fn test_resolve_acr_amr_token_exchange() {
        let result = resolve_acr_amr("token_exchange", &[]).unwrap();
        assert_eq!(result.acr, ACR_BRONZE);
        assert_eq!(result.amr, vec![AMR_TOKEN_EXCHANGE.to_string()]);
    }

    #[test]
    fn test_resolve_acr_amr_social() {
        let result = resolve_acr_amr("social", &[]).unwrap();
        assert_eq!(result.acr, ACR_BRONZE);
        assert_eq!(result.amr, vec![AMR_SOCIAL.to_string()]);
    }

    #[test]
    fn test_resolve_locale_no_claims_locales() {
        assert_eq!(resolve_locale("en", &[]), "en");
    }

    #[test]
    fn test_resolve_locale_exact_match() {
        assert_eq!(
            resolve_locale("en", &["en".to_string(), "fr".to_string()]),
            "en"
        );
    }

    #[test]
    fn test_resolve_locale_prefix_match() {
        // User locale "en-US" matches requested "en"
        assert_eq!(
            resolve_locale("en-US", &["en".to_string(), "fr".to_string()]),
            "en-US"
        );
    }

    #[test]
    fn test_resolve_locale_no_match_returns_first_requested() {
        // User locale "de" doesn't match any requested locale, return first requested
        assert_eq!(
            resolve_locale("de", &["fr".to_string(), "es".to_string()]),
            "fr"
        );
    }

    #[test]
    fn test_resolve_locale_requested_is_prefix_of_user() {
        // Requested "en-US" is more specific than user "en"
        assert_eq!(
            resolve_locale("en", &["en-US".to_string(), "fr".to_string()]),
            "en-US"
        );
    }

    #[test]
    fn test_acr_level_ordering() {
        assert!(acr_level(ACR_SILVER) > acr_level(ACR_BRONZE));
        assert!(acr_level(ACR_BRONZE) > acr_level("unknown"));
    }
}
