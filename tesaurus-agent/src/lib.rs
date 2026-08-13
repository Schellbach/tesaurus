//! Tesaurus owner-operated agent library.
//!
//! **Still fail-closed as a binary:** `tesaurus-agent` exits non-zero with the
//! PSBT-only / disabled message. This library does **not** unlock `--via-agent`,
//! restore HTTP co-signing, or sign PSBTs.
//!
//! What landed: Core B RPC mapping into sealed `tesaurus-policy` [`ChainView`] /
//! [`PrevoutFact`]. tesaurus-agent is the production TCB that builds those
//! types. [`AgentAuth`] is fail-closed until a transport MAC is specified.
//!
//! This crate must not depend on the coordinator `tesaurus` crate and must not
//! load primary/override key material.

pub mod auth;
pub mod chain;
pub mod error;
pub mod rpc;

pub use auth::agent_auth_from_unspecified_mac;
pub use chain::{chain_view_from_core_b, ChainViewFromCoreB, CoreB, CoreBChainInfo, CoreBUnspent};
pub use error::AgentError;
pub use rpc::{is_loopback_rpc_url, BitcoindCoreB, CoreBConfig};

/// Containment message for the disabled binary entrypoint (CI-01).
pub fn disabled_message() -> &'static str {
    "tesaurus-agent is disabled: the legacy HTTP protocol could expose primary key material; \
     use only local regtest/testnet signing until a reviewed PSBT-only protocol ships"
}
