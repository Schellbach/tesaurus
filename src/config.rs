//! Configuration for Tesaurus vault, daemon, and agent.

use crate::error::{Error, Result};
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub bitcoin: BitcoinConfig,
    pub vault: VaultConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinConfig {
    /// Network: mainnet | testnet | signet | regtest
    pub network: String,
    /// Bitcoin Core cookie file, or leave empty and use user/password.
    #[serde(default)]
    pub cookie_path: Option<PathBuf>,
    #[serde(default = "default_rpc_url")]
    pub rpc_url: String,
    #[serde(default)]
    pub rpc_user: Option<String>,
    #[serde(default)]
    pub rpc_password: Option<String>,
    /// Bitcoin Core wallet name used as a watch-only backend.
    #[serde(default = "default_wallet_name")]
    pub wallet_name: String,
}

fn default_rpc_url() -> String {
    "http://127.0.0.1:18443".into()
}

fn default_wallet_name() -> String {
    "tesaurus".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Path to vault state JSON (descriptor + metadata).
    pub state_path: PathBuf,
    /// Relative timelock (CSV) in blocks before the agent path is available.
    #[serde(default = "default_csv_blocks")]
    pub csv_blocks: u32,
    /// Directory for key material (WIF files). Keep offline / encrypted at rest.
    pub keys_dir: PathBuf,
}

fn default_csv_blocks() -> u32 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Bind address for the agent co-signer HTTP API.
    #[serde(default = "default_agent_bind")]
    pub bind: String,
    /// Path to agent WIF file.
    pub key_path: PathBuf,
    /// Optional bearer token required by the agent API.
    #[serde(default)]
    pub api_token: Option<String>,
    /// Maximum amount (sats) the agent will co-sign in a single transaction.
    #[serde(default = "default_max_amount")]
    pub max_amount_sats: u64,
    /// If non-empty, destinations must be in this allowlist.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Require CSV path to be mature before signing.
    #[serde(default = "default_true")]
    pub require_timelock: bool,
}

fn default_agent_bind() -> String {
    "127.0.0.1:18480".into()
}

fn default_max_amount() -> u64 {
    50_000_000 // 0.5 BTC
}

fn default_true() -> bool {
    true
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            bind: default_agent_bind(),
            key_path: PathBuf::from("./keys/agent.wif"),
            api_token: None,
            max_amount_sats: default_max_amount(),
            allowlist: Vec::new(),
            require_timelock: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_poll_secs")]
    pub poll_interval_secs: u64,
    /// Optional URL of a local agent to request co-signatures from.
    #[serde(default)]
    pub agent_url: Option<String>,
}

fn default_poll_secs() -> u64 {
    30
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: default_poll_secs(),
            agent_url: Some("http://127.0.0.1:18480".into()),
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref())?;
        let cfg: Self = toml::from_str(&raw).map_err(|e| Error::config(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn network(&self) -> Result<Network> {
        Network::from_str(&self.bitcoin.network)
            .map_err(|_| Error::config(format!("invalid network '{}'", self.bitcoin.network)))
    }

    pub fn validate(&self) -> Result<()> {
        self.network()?;
        if self.vault.csv_blocks == 0 {
            return Err(Error::config("vault.csv_blocks must be >= 1"));
        }
        if self.vault.csv_blocks > 65535 {
            return Err(Error::config("vault.csv_blocks must fit in a 16-bit CSV value"));
        }
        Ok(())
    }

    pub fn example_toml(network: &str) -> String {
        format!(
            r#"# Tesaurus configuration

[bitcoin]
network = "{network}"
rpc_url = "http://127.0.0.1:18332"
rpc_user = "tesaurus"
rpc_password = "changeme"
wallet_name = "tesaurus"
# cookie_path = "/home/bitcoin/.bitcoin/testnet3/.cookie"

[vault]
state_path = "./data/vault.json"
keys_dir = "./keys"
csv_blocks = 10

[agent]
bind = "127.0.0.1:18480"
key_path = "./keys/agent.wif"
# api_token = "replace-me"
max_amount_sats = 50000000
allowlist = []
require_timelock = true

[daemon]
poll_interval_secs = 30
agent_url = "http://127.0.0.1:18480"
"#
        )
    }
}
