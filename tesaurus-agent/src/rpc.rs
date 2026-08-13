//! Live Bitcoin Core (Core B) RPC client.
//!
//! Independent of the coordinator `tesaurus` crate. No wallet load, no WIF,
//! no primary/override key paths. Mainnet and non-loopback URLs are rejected.

use std::path::PathBuf;

use bitcoin::block::Header;
use bitcoin::{Amount, BlockHash, Network, OutPoint, ScriptBuf};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use crate::chain::{CoreB, CoreBChainInfo, CoreBUnspent};
use crate::error::AgentError;

/// Connection parameters for Core B. Agent-local; not a coordinator config.
#[derive(Debug, Clone)]
pub struct CoreBConfig {
    pub network: Network,
    pub rpc_url: String,
    pub cookie_path: Option<PathBuf>,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
}

impl CoreBConfig {
    pub fn validate(&self) -> Result<(), AgentError> {
        if self.network == Network::Bitcoin {
            return Err(AgentError::Mainnet);
        }
        if !matches!(
            self.network,
            Network::Regtest | Network::Testnet | Network::Signet
        ) {
            return Err(AgentError::config(format!(
                "network {} is not enabled; use regtest, testnet, or signet",
                self.network
            )));
        }
        if !is_loopback_rpc_url(&self.rpc_url) {
            return Err(AgentError::RpcUrlNotLoopback);
        }
        let cookie = self.cookie_path.is_some();
        let userpass = self.rpc_user.is_some() && self.rpc_password.is_some();
        if cookie == userpass && !cookie {
            return Err(AgentError::RpcAuthMissing);
        }
        if self.rpc_user.is_some() != self.rpc_password.is_some() {
            return Err(AgentError::config(
                "rpc_user and rpc_password must be set together",
            ));
        }
        Ok(())
    }
}

/// Bitcoin Core RPC URL must be plain HTTP on loopback (same containment as
/// the coordinator, reimplemented here so this crate does not depend on it).
pub fn is_loopback_rpc_url(url: &str) -> bool {
    let Some(authority) = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
    else {
        return false;
    };
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    ["127.0.0.1", "[::1]"].iter().any(|host| {
        authority == *host
            || authority
                .strip_prefix(host)
                .and_then(|rest| rest.strip_prefix(':'))
                .is_some_and(|port| {
                    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
                })
    })
}

/// Core B bitcoind handle. Watch-only queries only (`gettxout`, headers, tip).
pub struct BitcoindCoreB {
    client: Client,
    expected_network: Network,
}

impl BitcoindCoreB {
    pub fn connect(cfg: &CoreBConfig) -> Result<Self, AgentError> {
        cfg.validate()?;
        let auth = if let Some(cookie) = &cfg.cookie_path {
            Auth::CookieFile(cookie.clone())
        } else if let (Some(user), Some(pass)) = (&cfg.rpc_user, &cfg.rpc_password) {
            Auth::UserPass(user.clone(), pass.clone())
        } else {
            return Err(AgentError::RpcAuthMissing);
        };
        let client = Client::new(&cfg.rpc_url, auth)
            .map_err(|e| AgentError::rpc(format!("RPC connect failed: {e}")))?;
        let info = client
            .get_blockchain_info()
            .map_err(|e| AgentError::rpc(e.to_string()))?;
        if info.chain != cfg.network {
            return Err(AgentError::NetworkMismatch {
                expected: cfg.network,
                actual: info.chain,
            });
        }
        Ok(Self {
            client,
            expected_network: cfg.network,
        })
    }
}

impl CoreB for BitcoindCoreB {
    fn chain_info(&self) -> Result<CoreBChainInfo, AgentError> {
        let info = self
            .client
            .get_blockchain_info()
            .map_err(|e| AgentError::rpc(e.to_string()))?;
        if info.chain == Network::Bitcoin || self.expected_network == Network::Bitcoin {
            return Err(AgentError::Mainnet);
        }
        let tip_height = u32::try_from(info.blocks)
            .map_err(|_| AgentError::chain(format!("block height {} exceeds u32", info.blocks)))?;
        let genesis_hash = self
            .client
            .get_block_hash(0)
            .map_err(|e| AgentError::rpc(e.to_string()))?;
        Ok(CoreBChainInfo {
            network: info.chain,
            genesis_hash,
            tip_height,
            initial_block_download: info.initial_block_download,
        })
    }

    fn get_tx_out(&self, outpoint: OutPoint) -> Result<Option<CoreBUnspent>, AgentError> {
        let got = self
            .client
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
            .map_err(|e| AgentError::rpc(e.to_string()))?;
        let Some(txout) = got else {
            return Ok(None);
        };
        Ok(Some(CoreBUnspent {
            value: Amount::from_sat(txout.value.to_sat()),
            script_pubkey: ScriptBuf::from_bytes(txout.script_pub_key.hex),
            confirmations: txout.confirmations,
        }))
    }

    fn header_time_unix(&self, height: u32) -> Result<u64, AgentError> {
        let hash: BlockHash = self
            .client
            .get_block_hash(u64::from(height))
            .map_err(|e| AgentError::rpc(e.to_string()))?;
        let header: Header = self
            .client
            .get_block_header(&hash)
            .map_err(|e| AgentError::rpc(e.to_string()))?;
        Ok(u64::from(header.time))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cfg() -> CoreBConfig {
        CoreBConfig {
            network: Network::Regtest,
            rpc_url: "http://127.0.0.1:18443".into(),
            cookie_path: None,
            rpc_user: Some("user".into()),
            rpc_password: Some("pass".into()),
        }
    }

    #[test]
    fn rejects_mainnet_without_connecting() {
        let mut cfg = base_cfg();
        cfg.network = Network::Bitcoin;
        assert!(matches!(cfg.validate(), Err(AgentError::Mainnet)));
    }

    #[test]
    fn rejects_non_loopback_and_missing_auth() {
        let mut cfg = base_cfg();
        cfg.rpc_url = "http://example.com:18443".into();
        assert!(matches!(cfg.validate(), Err(AgentError::RpcUrlNotLoopback)));
        cfg.rpc_url = "http://127.0.0.1:18443".into();
        cfg.rpc_user = None;
        cfg.rpc_password = None;
        cfg.cookie_path = None;
        assert!(matches!(cfg.validate(), Err(AgentError::RpcAuthMissing)));
    }

    #[test]
    fn accepts_research_loopback() {
        for network in [Network::Regtest, Network::Testnet, Network::Signet] {
            let mut cfg = base_cfg();
            cfg.network = network;
            cfg.validate().unwrap();
        }
        assert!(is_loopback_rpc_url("http://127.0.0.1:18443"));
        assert!(is_loopback_rpc_url("http://[::1]:18443"));
        assert!(!is_loopback_rpc_url("https://127.0.0.1:18443"));
        assert!(!is_loopback_rpc_url("http://127.0.0.1:18443@evil"));
    }
}
