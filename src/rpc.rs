//! Bitcoin Core RPC helpers.

use crate::config::BitcoinConfig;
use crate::error::{Error, Result};
use bitcoincore_rpc::jsonrpc::serde_json::{json, Value};
use bitcoincore_rpc::{Auth, Client, RpcApi};

pub struct BitcoinRpc {
    client: Client,
}

impl BitcoinRpc {
    pub fn connect(cfg: &BitcoinConfig) -> Result<Self> {
        cfg.validate()?;
        let expected_network = cfg.network()?;
        if !matches!(
            expected_network,
            bitcoin::Network::Regtest | bitcoin::Network::Testnet | bitcoin::Network::Signet
        ) {
            return Err(Error::config(
                "Bitcoin Core connections are disabled for this network",
            ));
        }
        let auth = if let Some(cookie) = &cfg.cookie_path {
            Auth::CookieFile(cookie.clone())
        } else if let (Some(user), Some(pass)) = (&cfg.rpc_user, &cfg.rpc_password) {
            Auth::UserPass(user.clone(), pass.clone())
        } else {
            return Err(Error::config(
                "bitcoin RPC auth required: set cookie_path or rpc_user/rpc_password",
            ));
        };

        let base = Client::new(&cfg.rpc_url, auth.clone())
            .map_err(|e| Error::wallet(format!("RPC connect failed: {e}")))?;
        let actual_network = base.get_blockchain_info()?.chain;
        if actual_network != expected_network {
            return Err(Error::wallet(format!(
                "Bitcoin Core network {actual_network} does not match configured network {expected_network}"
            )));
        }

        // Ensure wallet exists / is loaded.
        ensure_wallet(&base, &cfg.wallet_name)?;

        let wallet_url = wallet_rpc_url(&cfg.rpc_url, &cfg.wallet_name);
        let client = Client::new(&wallet_url, auth)
            .map_err(|e| Error::wallet(format!("wallet RPC connect failed: {e}")))?;

        Ok(Self { client })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn block_count(&self) -> Result<u64> {
        Ok(self.client.get_block_count()?)
    }
}

fn wallet_rpc_url(base: &str, wallet: &str) -> String {
    let base = base.trim_end_matches('/');
    format!("{base}/wallet/{wallet}")
}

fn ensure_wallet(client: &Client, name: &str) -> Result<()> {
    // Try load; if missing, create watch-capable blank wallet.
    match client.load_wallet(name) {
        Ok(_) => return Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already loaded") {
                return Ok(());
            }
            // fall through to create
        }
    }

    // createwallet (name, disable_private_keys=true, blank=true)
    let result = client.create_wallet(name, Some(true), Some(true), None, None);
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already exists") {
                // try load again
                client.load_wallet(name)?;
                Ok(())
            } else {
                Err(Error::from(e))
            }
        }
    }
}

pub fn import_watch_descriptor(client: &Client, descriptor: &str, label: &str) -> Result<()> {
    // Fixed-key (non-ranged) descriptors cannot be `active` in Bitcoin Core.
    // Import as watch-only and verify each request succeeded.
    let req = json!([{
        "desc": descriptor,
        "active": false,
        "timestamp": 0,
        "internal": false,
        "label": label,
    }]);
    let res: Value = client.call("importdescriptors", &[req])?;
    let arr = res
        .as_array()
        .ok_or_else(|| Error::wallet(format!("unexpected importdescriptors response: {res}")))?;
    for (i, item) in arr.iter().enumerate() {
        let ok = item
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !ok {
            return Err(Error::wallet(format!(
                "importdescriptors[{i}] failed: {item}"
            )));
        }
    }
    Ok(())
}
