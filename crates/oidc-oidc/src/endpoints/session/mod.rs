//! OIDC Session Management endpoints.
//!
//! Implements:
//! - **Check Session Iframe** (Session §4) — OP iframe for RP session state polling
//! - **Session State** (Session §3) — `session_state` parameter in authorization responses
//! - **Front-Channel Logout** (Front-Channel §6) — Cross-iframe logout notifications
//! - **Back-Channel Logout** (Back-Channel §7) — Server-to-server logout notifications

pub mod backchannel_logout;
pub mod check_session;
pub mod frontchannel_logout;
