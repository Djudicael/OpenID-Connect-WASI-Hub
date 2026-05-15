//! Utilities shared across the workspace.

pub mod id;
pub mod pkce;
pub mod time;
pub mod token;
pub mod validation;

pub use id::generate_uuid_v7;
pub use pkce::{generate_code_verifier, s256_challenge, verify_s256};
pub use token::{
    compute_at_hash, compute_c_hash, compute_pairwise_sub, compute_session_state, extract_origin,
    extract_sector_identifier, generate_opaque_token, generate_sid, sha2_256_hex,
};
pub use validation::{is_strong_password, is_valid_email, is_valid_username};

#[cfg(test)]
mod proptest_tests;
