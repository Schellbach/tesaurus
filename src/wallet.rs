//! Vault state persistence and Bitcoin Core watch-only sync.

use crate::descriptor::VaultDescriptor;
use crate::error::{Error, Result};
use crate::rpc::{import_watch_descriptor, BitcoinRpc};
use bitcoin::{Address, OutPoint, TxOut};
use bitcoincore_rpc::RpcApi;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::wallet(format!(
                "vault state path {} must be a regular file, not a symlink",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::wallet(format!(
                    "vault state file {} must not be accessible by group or others",
                    path.display()
                )));
            }
        }
        let raw = fs::read_to_string(path)?;
        let state: Self = serde_json::from_str(&raw)?;
        if state.version != 1 {
            return Err(Error::wallet(format!(
                "unsupported vault state version {}",
                state.version
            )));
        }
        state.vault.validate()?;
        Ok(state)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        self.vault.validate()?;
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() {
                return Err(Error::wallet(format!(
                    "refusing to write vault state through symlink {}",
                    path.display()
                )));
            }
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(self)?;

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true).mode(0o600);
            let mut file = options.open(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            file.write_all(raw.as_bytes())?;
            file.sync_all()?;
        }

        #[cfg(not(unix))]
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
        self.state.vault.validate()?;
        import_watch_descriptor(
            self.rpc.client(),
            &self.state.vault.descriptor,
            "tesaurus-vault",
        )?;
        Ok(())
    }

    pub fn list_utxos(&self) -> Result<Vec<VaultUtxo>> {
        let addr = self.address()?;
        let unspent =
            self.rpc
                .client()
                .list_unspent(Some(0), None, Some(&[&addr]), Some(true), None)?;

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
        self.list_utxos()?.iter().try_fold(0u64, |total, utxo| {
            total
                .checked_add(utxo.txout.value.to_sat())
                .ok_or_else(|| Error::wallet("wallet balance overflows u64"))
        })
    }

    pub fn tip_height(&self) -> Result<u64> {
        self.rpc.block_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Network, PrivateKey, PublicKey};

    fn public_key(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [seed; 32];
        bytes[31] = seed.wrapping_add(1);
        let secret = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_private_key(&secp, &PrivateKey::new(secret, Network::Regtest))
    }

    fn state() -> VaultState {
        VaultState::new(
            VaultDescriptor::build(
                public_key(1),
                public_key(2),
                public_key(3),
                10,
                Network::Regtest,
            )
            .unwrap(),
        )
    }

    #[test]
    fn rejects_unknown_state_versions() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.json");
        let mut value = serde_json::to_value(state()).unwrap();
        value["version"] = serde_json::json!(2);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let err = VaultState::load(path).unwrap_err().to_string();
        assert!(err.contains("unsupported vault state version"));
    }

    #[cfg(unix)]
    #[test]
    fn writes_vault_state_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.json");
        state().save(&path).unwrap();

        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
