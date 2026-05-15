//! OIDC Core §5.1.1 — Address Claim
//!
//! The `address` claim represents a physical mailing address.
//! Per the spec, `street_address` may contain multiple lines separated
//! by `\n` (e.g., for European addresses with building number on a
//! separate line, or French addresses with "BP" / "CEDEX" lines).
//!
//! Example French address:
//! ```json
//! {
//!   "formatted": "12 Rue de la Paix\n75002 Paris\nFR",
//!   "street_address": "12 Rue de la Paix",
//!   "locality": "Paris",
//!   "region": "Île-de-France",
//!   "postal_code": "75002",
//!   "country": "FR"
//! }
//! ```
//!
//! Example multi-line European address:
//! ```json
//! {
//!   "formatted": "Apt 3B\n12 Rue de la Paix\n75002 Paris\nFR",
//!   "street_address": "Apt 3B\n12 Rue de la Paix",
//!   "locality": "Paris",
//!   "region": "Île-de-France",
//!   "postal_code": "75002",
//!   "country": "FR"
//! }
//! ```

use serde::{Deserialize, Serialize};

/// OIDC Core §5.1.1 — Address Claim.
///
/// All fields are optional per the spec. The `formatted` field is a
/// full mailing address suitable for display or mailing labels.
/// When stored in the database, each component is stored in its own
/// column for queryability; `formatted` is computed on the fly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AddressClaim {
    /// Full mailing address, formatted for display or mailing labels.
    /// Per OIDC Core §5.1.1, this MAY contain newlines (`\n`).
    /// If not explicitly set, it is auto-generated from the component fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,

    /// Full street address component, which MAY include house number,
    /// street name, apartment/suite number, etc.
    ///
    /// Per OIDC Core §5.1.1, this MAY contain multiple lines separated
    /// by `\n`. This is important for European addresses where the
    /// building number is on a separate line, or for addresses with
    /// "BP" (Boîte Postale) / "CEDEX" lines in France.
    ///
    /// Examples:
    /// - US: `"123 Main St"`
    /// - French: `"12 Rue de la Paix"`
    /// - Multi-line: `"Apt 3B\n12 Rue de la Paix"`
    /// - French with CEDEX: `"BP 123\n12 Rue de la Paix"`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,

    /// City or locality component.
    /// Works for any locale: "San Francisco", "Paris", "München", "Madrid".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,

    /// State, province, prefecture, or region component.
    /// Generic enough for any locale:
    /// - US: "CA" (state)
    /// - France: "Île-de-France" (région)
    /// - Germany: "Bayern" (Bundesland)
    /// - Spain: "Comunidad de Madrid" (comunidad autónoma)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Zip code or postal code component.
    /// Supports any format:
    /// - US: "94105" (5-digit)
    /// - France: "75002" (5-digit)
    /// - Germany: "80331" (5-digit)
    /// - UK: "SW1A 1AA" (alphanumeric)
    /// - Netherlands: "1234 AB" (4-digit + 2-letter)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,

    /// Country name or ISO 3166-1 alpha-2 code.
    /// Per OIDC Core, this SHOULD be an ISO 3166-1 code:
    /// - "US", "FR", "DE", "ES", "GB", "NL", etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl AddressClaim {
    /// Build an `AddressClaim` from its individual components,
    /// auto-generating the `formatted` field if not provided.
    ///
    /// The formatted address is built as:
    /// ```text
    /// street_address
    /// postal_code locality
    /// country
    /// ```
    ///
    /// For multi-line `street_address`, all lines are included.
    /// This format works well for European addresses:
    ///
    /// French: `"12 Rue de la Paix\n75002 Paris\nFR"`
    /// German: `"Marienplatz 1\n80331 München\nDE"`
    /// US:     `"123 Main St\nSan Francisco, CA 94105\nUS"`
    pub fn from_components(
        formatted: Option<String>,
        street_address: Option<String>,
        locality: Option<String>,
        region: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
    ) -> Self {
        let computed_formatted = formatted.or_else(|| {
            // Only generate formatted if at least one component exists
            if street_address.is_none()
                && locality.is_none()
                && region.is_none()
                && postal_code.is_none()
                && country.is_none()
            {
                return None;
            }

            let mut lines = Vec::new();

            // Street address (may already contain \n for multi-line)
            if let Some(ref sa) = street_address {
                lines.push(sa.clone());
            }

            // City line: "postal_code locality" or "locality, region" or combinations
            // European format: "75002 Paris" or "Paris, Île-de-France"
            // US format: "San Francisco, CA 94105"
            let city_line = match (&locality, &region, &postal_code) {
                (Some(loc), Some(reg), Some(pc)) => {
                    // European: "75002 Paris, Île-de-France"
                    // We put postal_code first as is common in Europe
                    format!("{pc} {loc}, {reg}")
                }
                (Some(loc), Some(reg), None) => format!("{loc}, {reg}"),
                (Some(loc), None, Some(pc)) => format!("{pc} {loc}"),
                (Some(loc), None, None) => loc.clone(),
                (None, Some(reg), Some(pc)) => format!("{pc} {reg}"),
                (None, Some(reg), None) => reg.clone(),
                (None, None, Some(pc)) => pc.clone(),
                (None, None, None) => String::new(),
            };
            if !city_line.is_empty() {
                lines.push(city_line);
            }

            // Country on its own line
            if let Some(ref c) = country {
                lines.push(c.clone());
            }

            Some(lines.join("\n"))
        });

        Self {
            formatted: computed_formatted,
            street_address,
            locality,
            region,
            postal_code,
            country,
        }
    }

    /// Returns true if all address fields are empty/None.
    pub fn is_empty(&self) -> bool {
        self.formatted.is_none()
            && self.street_address.is_none()
            && self.locality.is_none()
            && self.region.is_none()
            && self.postal_code.is_none()
            && self.country.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_claim_french() {
        let addr = AddressClaim::from_components(
            None,
            Some("12 Rue de la Paix".into()),
            Some("Paris".into()),
            Some("Île-de-France".into()),
            Some("75002".into()),
            Some("FR".into()),
        );
        assert_eq!(addr.street_address.as_deref(), Some("12 Rue de la Paix"));
        assert_eq!(addr.locality.as_deref(), Some("Paris"));
        assert_eq!(addr.region.as_deref(), Some("Île-de-France"));
        assert_eq!(addr.postal_code.as_deref(), Some("75002"));
        assert_eq!(addr.country.as_deref(), Some("FR"));
        // formatted should be auto-generated
        let formatted = addr.formatted.unwrap();
        assert!(formatted.contains("12 Rue de la Paix"));
        assert!(formatted.contains("75002 Paris"));
        assert!(formatted.contains("Île-de-France"));
        assert!(formatted.contains("FR"));
    }

    #[test]
    fn test_address_claim_multiline_street() {
        let addr = AddressClaim::from_components(
            None,
            Some("Apt 3B\n12 Rue de la Paix".into()),
            Some("Paris".into()),
            None,
            Some("75002".into()),
            Some("FR".into()),
        );
        let formatted = addr.formatted.unwrap();
        assert!(formatted.starts_with("Apt 3B\n12 Rue de la Paix"));
        assert!(formatted.contains("75002 Paris"));
        assert!(formatted.ends_with("FR"));
    }

    #[test]
    fn test_address_claim_us() {
        let addr = AddressClaim::from_components(
            Some("123 Main St\nSan Francisco, CA 94105\nUS".into()),
            Some("123 Main St".into()),
            Some("San Francisco".into()),
            Some("CA".into()),
            Some("94105".into()),
            Some("US".into()),
        );
        // When formatted is explicitly provided, it should be used as-is
        assert_eq!(
            addr.formatted.as_deref(),
            Some("123 Main St\nSan Francisco, CA 94105\nUS")
        );
    }

    #[test]
    fn test_address_claim_german() {
        let addr = AddressClaim::from_components(
            None,
            Some("Marienplatz 1".into()),
            Some("München".into()),
            Some("Bayern".into()),
            Some("80331".into()),
            Some("DE".into()),
        );
        let formatted = addr.formatted.unwrap();
        assert!(formatted.contains("Marienplatz 1"));
        assert!(formatted.contains("80331 München, Bayern"));
        assert!(formatted.ends_with("DE"));
    }

    #[test]
    fn test_address_claim_spanish() {
        let addr = AddressClaim::from_components(
            None,
            Some("Calle Gran Vía 28".into()),
            Some("Madrid".into()),
            Some("Comunidad de Madrid".into()),
            Some("28013".into()),
            Some("ES".into()),
        );
        let formatted = addr.formatted.unwrap();
        assert!(formatted.contains("Calle Gran Vía 28"));
        assert!(formatted.contains("28013 Madrid, Comunidad de Madrid"));
        assert!(formatted.ends_with("ES"));
    }

    #[test]
    fn test_address_claim_empty() {
        let addr = AddressClaim::from_components(None, None, None, None, None, None);
        assert!(addr.is_empty());
        assert!(addr.formatted.is_none());
    }

    #[test]
    fn test_address_claim_partial() {
        let addr = AddressClaim::from_components(
            None,
            None,
            Some("Paris".into()),
            None,
            Some("75002".into()),
            Some("FR".into()),
        );
        assert!(!addr.is_empty());
        let formatted = addr.formatted.unwrap();
        assert!(formatted.contains("75002 Paris"));
        assert!(formatted.contains("FR"));
    }

    #[test]
    fn test_address_claim_serialization() {
        let addr = AddressClaim::from_components(
            None,
            Some("12 Rue de la Paix".into()),
            Some("Paris".into()),
            Some("Île-de-France".into()),
            Some("75002".into()),
            Some("FR".into()),
        );
        let json = serde_json::to_value(&addr).unwrap();
        // All fields should be present
        assert!(json.get("formatted").is_some());
        assert!(json.get("street_address").is_some());
        assert!(json.get("locality").is_some());
        assert!(json.get("region").is_some());
        assert!(json.get("postal_code").is_some());
        assert!(json.get("country").is_some());
    }

    #[test]
    fn test_address_claim_skip_none() {
        let addr = AddressClaim::default();
        let json = serde_json::to_value(&addr).unwrap();
        // All fields are None, so none should appear in JSON
        assert!(json.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_address_claim_deserialization() {
        let json = r#"{
            "formatted": "12 Rue de la Paix\n75002 Paris\nFR",
            "street_address": "12 Rue de la Paix",
            "locality": "Paris",
            "region": "Île-de-France",
            "postal_code": "75002",
            "country": "FR"
        }"#;
        let addr: AddressClaim = serde_json::from_str(json).unwrap();
        assert_eq!(addr.street_address.as_deref(), Some("12 Rue de la Paix"));
        assert_eq!(addr.locality.as_deref(), Some("Paris"));
        assert_eq!(addr.country.as_deref(), Some("FR"));
    }

    #[test]
    fn test_address_claim_french_bpo() {
        // French address with BP (Boîte Postale) — common in corporate addresses
        let addr = AddressClaim::from_components(
            Some("BP 123\n12 Rue de la Paix\n75002 Paris\nFR".into()),
            Some("BP 123\n12 Rue de la Paix".into()),
            Some("Paris".into()),
            Some("Île-de-France".into()),
            Some("75002".into()),
            Some("FR".into()),
        );
        assert_eq!(
            addr.street_address.as_deref(),
            Some("BP 123\n12 Rue de la Paix")
        );
        assert_eq!(
            addr.formatted.as_deref(),
            Some("BP 123\n12 Rue de la Paix\n75002 Paris\nFR")
        );
    }
}
