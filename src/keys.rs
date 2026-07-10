//! Vault key material helpers.

use crate::error::{Error, Result};
use bitcoin::secp256k1::{rand, Secp256k1, SecretKey};
use bitcoin::{Network, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Role of a vault key in the 2-of-3 decaying multisig.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyRole {
    Primary,
    Override,
    Agent,
}

impl KeyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Override => "override",
            Self::Agent => "agent",
        }
    }

    pub fn filename(self) -> &'static str {
        match self {
            Self::Primary => "primary.wif",
            Self::Override => "override.wif",
            Self::Agent => "agent.wif",
        }
    }
}

#[derive(Clone)]
pub struct VaultKey {
    pub role: KeyRole,
    inner: PrivateKey,
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        // Best-effort wipe of key material on drop.
        self.inner.inner.non_secure_erase();
    }
}

impl VaultKey {
    pub fn generate(role: KeyRole, network: Network) -> Self {
        let sk = SecretKey::new(&mut rand::thread_rng());
        Self {
            role,
            inner: PrivateKey::new(sk, network),
        }
    }

    pub fn from_wif(role: KeyRole, wif: &str) -> Result<Self> {
        let inner = PrivateKey::from_wif(wif.trim()).map_err(|e| Error::key(e.to_string()))?;
        Ok(Self { role, inner })
    }

    pub fn from_file(role: KeyRole, path: impl AsRef<Path>) -> Result<Self> {
        let wif = fs::read_to_string(path.as_ref())?;
        Self::from_wif(role, &wif)
    }

    pub fn write_wif_file(&self, path: impl AsRef<Path>, overwrite: bool) -> Result<()> {
        let path = path.as_ref();
        if path.exists() && !overwrite {
            return Err(Error::key(format!(
                "refusing to overwrite existing key file {}",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);
            use std::io::Write;
            let mut f = opts.open(path)?;
            writeln!(f, "{}", self.inner)?;
        }
        #[cfg(not(unix))]
        {
            fs::write(path, format!("{}\n", self.inner))?;
        }
        Ok(())
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.inner
    }

    pub fn public_key(&self, secp: &Secp256k1<bitcoin::secp256k1::All>) -> PublicKey {
        PublicKey::from_private_key(secp, &self.inner)
    }

    pub fn wif(&self) -> String {
        self.inner.to_wif()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicVaultKeys {
    pub primary: String,
    pub override_key: String,
    pub agent: String,
}

impl PublicVaultKeys {
    pub fn parse(&self) -> Result<(PublicKey, PublicKey, PublicKey)> {
        Ok((
            parse_pubkey(&self.primary)?,
            parse_pubkey(&self.override_key)?,
            parse_pubkey(&self.agent)?,
        ))
    }
}

fn parse_pubkey(s: &str) -> Result<PublicKey> {
    s.parse::<PublicKey>()
        .map_err(|e| Error::key(format!("invalid pubkey '{s}': {e}")))
}

/// Generate the three vault keys and write WIF files under `keys_dir`.
pub fn generate_vault_keys(keys_dir: &Path, network: Network, overwrite: bool) -> Result<PublicVaultKeys> {
    let secp = Secp256k1::new();
    let roles = [KeyRole::Primary, KeyRole::Override, KeyRole::Agent];
    let mut pubs = Vec::new();
    for role in roles {
        let key = VaultKey::generate(role, network);
        let path = keys_dir.join(role.filename());
        key.write_wif_file(&path, overwrite)?;
        pubs.push(key.public_key(&secp).to_string());
    }
    Ok(PublicVaultKeys {
        primary: pubs[0].clone(),
        override_key: pubs[1].clone(),
        agent: pubs[2].clone(),
    })
}

pub fn load_key(keys_dir: &Path, role: KeyRole) -> Result<VaultKey> {
    VaultKey::from_file(role, keys_dir.join(role.filename()))
}

pub fn key_path(keys_dir: &Path, role: KeyRole) -> PathBuf {
    keys_dir.join(role.filename())
}
