//! OAuth2/OIDC grant flows.

pub mod authorization_code;
pub mod client_credentials;
pub mod device_code;
pub mod jwt_bearer;
pub mod password;
pub mod refresh_token;
pub mod token_exchange;

use oidc_core::OidcError;
use oidc_core::models::Client;

use crate::state::OidcState;

/// Apply JWE encryption to a signed ID token if the client has encryption configured.
///
/// For `dir` algorithm, the symmetric key is decrypted from the client's
/// `id_token_encryption_key_encrypted` field using the server's encryption key.
/// For `RSA-OAEP-256`, the RSA public key PEM is used directly.
///
/// Returns the (possibly encrypted) ID token string.
pub fn maybe_encrypt_id_token(
    state: &OidcState,
    signed_id_token: &str,
    client: &Client,
) -> Result<String, OidcError> {
    if client.id_token_encrypted_response_alg.is_none() {
        return Ok(signed_id_token.to_string());
    }

    // Resolve the symmetric key for "dir" algorithm
    let enc_key: Option<Vec<u8>> = match client.id_token_encrypted_response_alg.as_deref() {
        Some("dir") => match &client.id_token_encryption_key_encrypted {
            Some(encrypted) => Some(state.decrypt_client_encryption_key(encrypted)?),
            None => {
                return Err(OidcError::InvalidInput(
                    "Client has JWE dir configured but no encryption key".into(),
                ));
            }
        },
        _ => None,
    };

    let encrypted = oidc_core::utils::encrypt_id_token_if_configured(
        signed_id_token,
        client.id_token_encrypted_response_alg.as_deref(),
        client.id_token_encrypted_response_enc.as_deref(),
        enc_key.as_deref(),
        client.id_token_encryption_key_pem.as_deref(),
    )?;

    // If encryption was configured, we should always get Some back
    match encrypted {
        Some(jwe) => Ok(jwe),
        None => Ok(signed_id_token.to_string()),
    }
}
