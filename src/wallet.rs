//! Vault state persistence and Bitcoin Core watch-only sync.

use crate::descriptor::VaultDescriptor;
use crate::error::Result;
use crate::rpc::{import_watch_descriptor, BitcoinRpc};
use bitcoin::{Address, OutPoint, TxOut};
use bitcoincore_rpc::RpcApi;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultState {
    pub version: u32,
    pub vault: VaultDescriptor,
    #[serde(default)]
    pub notes: Option<String>,
}

impl VaultState {
    pub fn new(vault: VaultDescriptor) -> Self {
        Self {
            version: 1,
            vault,
            notes: Some(
                "Back up this file and your key WIFs. The descriptor alone cannot spend funds."
                    .into(),
            ),
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref())?;
        let state: Self = serde_json::from_str(&raw)?;
        // Validate descriptor still parses.
        state.vault.parsed()?;
        Ok(state)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(self)?;
        fs::write(path, raw)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VaultUtxo {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub confirmations: u32,
    pub spendable_primary: bool,
    pub spendable_recovery: bool,
}

pub struct VaultWallet {
    pub state: VaultState,
    rpc: BitcoinRpc,
}

impl VaultWallet {
    pub fn open(state: VaultState, rpc: BitcoinRpc) -> Self {
        Self { state, rpc }
    }

    pub fn address(&self) -> Result<Address> {
        self.state.vault.address()
    }

    /// Import the vault descriptor into Bitcoin Core as watch-only and rescan if requested.
    pub fn import_watch_only(&self) -> Result<()> {
        import_watch_descriptor(
            self.rpc.client(),
            &self.state.vault.descriptor,
            "tesaurus-vault",
        )?;
        Ok(())
    }

    pub fn list_utxos(&self) -> Result<Vec<VaultUtxo>> {
        let addr = self.address()?;
        let unspent = self.rpc.client().list_unspent(
            Some(0),
            None,
            Some(&[&addr]),
            Some(true),
            None,
        )?;

        let csv = self.state.vault.csv_blocks;
        let mut out = Vec::new();
        for u in unspent {
            let confirmations = u.confirmations;
            out.push(VaultUtxo {
                outpoint: OutPoint {
                    txid: u.txid,
                    vout: u.vout,
                },
                txout: TxOut {
                    value: u.amount,
                    script_pubkey: addr.script_pubkey(),
                },
                confirmations,
                spendable_primary: true,
                spendable_recovery: confirmations >= csv,
            });
        }
        Ok(out)
    }

    pub fn balance_sats(&self) -> Result<u64> {
        Ok(self.list_utxos()?.iter().map(|u| u.txout.value.to_sat()).sum())
    }

    pub fn tip_height(&self) -> Result<u64> {
        self.rpc.block_count()
    }
}
