//! Vault key material helpers.

use crate::error::{Error, Result};
use bitcoin::secp256k1::{rand, Secp256k1, SecretKey};
use bitcoin::{Network, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

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
    fn generate(role: KeyRole, network: Network) -> Self {
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
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::key(format!(
                "refusing to read key through symlink {}",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::key(format!(
                    "key file {} must not be accessible by group or others",
                    path.display()
                )));
            }
        }
        let wif = Zeroizing::new(fs::read_to_string(path)?);
        Self::from_wif(role, &wif)
    }

    pub fn write_wif_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() {
                return Err(Error::key(format!(
                    "refusing to write key through symlink {}",
                    path.display()
                )));
            }
            return Err(Error::key(format!(
                "refusing to overwrite existing key file {}",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            let parent_existed = parent.exists();
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if !parent_existed {
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                }
                let permissions = fs::metadata(parent)?.permissions();
                if permissions.mode() & 0o077 != 0 {
                    return Err(Error::key(format!(
                        "key directory {} must have mode 0700 or stricter",
                        parent.display()
                    )));
                }
            }
        }
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true).mode(0o600);
            let mut f = opts.open(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            writeln!(f, "{}", self.inner)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            writeln!(file, "{}", self.inner)?;
            file.sync_all()?;
        }
        Ok(())
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.inner
    }

    pub fn public_key(&self, secp: &Secp256k1<bitcoin::secp256k1::All>) -> PublicKey {
        PublicKey::from_private_key(secp, &self.inner)
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
pub fn generate_vault_keys(keys_dir: &Path, network: Network) -> Result<PublicVaultKeys> {
    if !matches!(
        network,
        Network::Regtest | Network::Testnet | Network::Signet
    ) {
        return Err(Error::key(format!(
            "key generation is disabled for network {network}"
        )));
    }
    let secp = Secp256k1::new();
    let roles = [KeyRole::Primary, KeyRole::Override, KeyRole::Agent];
    for role in roles {
        let path = keys_dir.join(role.filename());
        if fs::symlink_metadata(&path).is_ok() {
            return Err(Error::key(format!(
                "refusing to replace existing key file {}; use a new empty keys_dir",
                path.display()
            )));
        }
    }
    let mut pubs = Vec::new();
    for role in roles {
        let key = VaultKey::generate(role, network);
        let path = keys_dir.join(role.filename());
        key.write_wif_file(&path)?;
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn writes_private_key_files_and_rejects_permissive_reads() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("primary.wif");
        let key = VaultKey::generate(KeyRole::Primary, Network::Regtest);

        key.write_wif_file(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        VaultKey::from_file(KeyRole::Primary, &path).unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = match VaultKey::from_file(KeyRole::Primary, &path) {
            Ok(_) => panic!("permissive key file was accepted"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("must not be accessible"));
    }

    #[test]
    fn rejects_mainnet_key_generation() {
        let temp = tempfile::tempdir().unwrap();
        let err = generate_vault_keys(temp.path(), Network::Bitcoin)
            .unwrap_err()
            .to_string();
        assert!(err.contains("disabled for network bitcoin"));
    }

    #[test]
    fn never_overwrites_existing_key_sets() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        generate_vault_keys(temp.path(), Network::Regtest).unwrap();

        let err = generate_vault_keys(temp.path(), Network::Regtest)
            .unwrap_err()
            .to_string();
        assert!(err.contains("use a new empty keys_dir"));
    }
}
