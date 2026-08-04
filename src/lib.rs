//! Tesaurus — experimental Bitcoin vault research.
//!
//! Spending policy (miniscript):
//! `thresh(2, pk(primary), pk(override), and(pk(agent), older(csv)))`
//!
//! - **Primary path:** primary + override (always)
//! - **Recovery path:** after `csv` confirmations, primary + agent (or any other 2-of-3)
//!
//! Network co-signing and mainnet operation are intentionally disabled.

pub mod config;
pub mod descriptor;
pub mod error;
pub mod keys;
pub mod rpc;
pub mod spend;
pub mod wallet;

pub use config::Config;
pub use descriptor::VaultDescriptor;
pub use error::{Error, Result};
pub use keys::{generate_vault_keys, KeyRole, VaultKey};
pub use spend::{SpendPath, SpendRequest};
pub use wallet::VaultState;
