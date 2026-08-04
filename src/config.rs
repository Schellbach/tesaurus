//! Configuration for the local Tesaurus research CLI.

use crate::error::{Error, Result};
use bitcoin::Network;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bitcoin: BitcoinConfig,
    pub vault: VaultConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinConfig {
    /// Network: testnet | signet | regtest. Mainnet is intentionally disabled.
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

impl BitcoinConfig {
    pub fn network(&self) -> Result<Network> {
        if self.network.eq_ignore_ascii_case("mainnet") {
            return Ok(Network::Bitcoin);
        }
        Network::from_str(&self.network)
            .map_err(|_| Error::config(format!("invalid network '{}'", self.network)))
    }

    pub fn validate(&self) -> Result<()> {
        let network = self.network()?;
        if network == Network::Bitcoin {
            return Err(Error::config(
                "mainnet is disabled in this experimental release; use regtest, testnet, or signet",
            ));
        }
        if !matches!(
            network,
            Network::Regtest | Network::Testnet | Network::Signet
        ) {
            return Err(Error::config(format!(
                "network {network} is not enabled; use regtest, testnet, or signet"
            )));
        }
        if !is_loopback_rpc_url(&self.rpc_url) {
            return Err(Error::config(
                "bitcoin.rpc_url must use plain HTTP on 127.0.0.1 or [::1]",
            ));
        }
        if self.wallet_name.is_empty()
            || !self
                .wallet_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(Error::config(
                "bitcoin.wallet_name may contain only ASCII letters, digits, '.', '-', and '_'",
            ));
        }
        if self.rpc_user.is_some() != self.rpc_password.is_some() {
            return Err(Error::config(
                "bitcoin.rpc_user and bitcoin.rpc_password must be set together",
            ));
        }
        Ok(())
    }
}

impl Drop for BitcoinConfig {
    fn drop(&mut self) {
        if let Some(password) = &mut self.rpc_password {
            password.zeroize();
        }
    }
}

fn default_rpc_url() -> String {
    "http://127.0.0.1:18443".into()
}

fn default_wallet_name() -> String {
    "tesaurus".into()
}

fn is_loopback_rpc_url(url: &str) -> bool {
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::config(format!(
                "configuration path {} must be a regular file, not a symlink",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::config(format!(
                    "configuration file {} must not be accessible by group or others",
                    path.display()
                )));
            }
        }
        let raw = Zeroizing::new(fs::read_to_string(path)?);
        let cfg: Self = toml::from_str(&raw).map_err(|error| {
            let location = error
                .span()
                .map(|span| format!(" at byte range {}..{}", span.start, span.end))
                .unwrap_or_default();
            Error::config(format!("invalid TOML configuration{location}"))
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn network(&self) -> Result<Network> {
        self.bitcoin.network()
    }

    pub fn validate(&self) -> Result<()> {
        self.bitcoin.validate()?;
        if self.vault.csv_blocks == 0 {
            return Err(Error::config("vault.csv_blocks must be >= 1"));
        }
        if self.vault.csv_blocks > 65535 {
            return Err(Error::config(
                "vault.csv_blocks must fit in a 16-bit CSV value",
            ));
        }
        if self.vault.state_path.as_os_str().is_empty() {
            return Err(Error::config("vault.state_path must not be empty"));
        }
        if self.vault.keys_dir.as_os_str().is_empty() {
            return Err(Error::config("vault.keys_dir must not be empty"));
        }
        Ok(())
    }

    pub fn example_toml(network: &str) -> Result<String> {
        if network.eq_ignore_ascii_case("mainnet") {
            return Err(Error::config(
                "mainnet configuration generation is disabled in this experimental release",
            ));
        }
        let network = Network::from_str(network)
            .map_err(|_| Error::config(format!("invalid network '{network}'")))?;
        if network == Network::Bitcoin {
            return Err(Error::config(
                "mainnet configuration generation is disabled in this experimental release",
            ));
        }
        if !matches!(
            network,
            Network::Regtest | Network::Testnet | Network::Signet
        ) {
            return Err(Error::config(format!(
                "network {network} is not enabled; use regtest, testnet, or signet"
            )));
        }
        let rpc_port = match network {
            Network::Regtest => 18443,
            Network::Signet => 38332,
            _ => 18332,
        };
        Ok(format!(
            r#"# Tesaurus configuration

[bitcoin]
network = "{network}"
rpc_url = "http://127.0.0.1:{rpc_port}"
wallet_name = "tesaurus"
# Prefer Bitcoin Core cookie authentication:
# cookie_path = "/absolute/path/to/bitcoin/.cookie"
# Alternatively set rpc_user and rpc_password locally. Never commit real credentials.

[vault]
state_path = "./data/vault.json"
keys_dir = "./keys"
csv_blocks = 10
"#
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_mainnet() {
        let raw = Config::example_toml("regtest").unwrap();
        for alias in ["mainnet", "bitcoin"] {
            let mut cfg: Config = toml::from_str(&raw).unwrap();
            cfg.bitcoin.network = alias.into();
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("mainnet is disabled"));
            assert!(Config::example_toml(alias).is_err());
        }
    }

    #[test]
    fn rejects_unknown_security_fields() {
        let raw = format!(
            "{}\n[agent]\nbind = \"127.0.0.1:18480\"\n",
            Config::example_toml("regtest").unwrap()
        );
        assert!(toml::from_str::<Config>(&raw).is_err());
    }

    #[test]
    fn accepts_research_networks() {
        for network in ["regtest", "testnet", "signet"] {
            let raw = Config::example_toml(network).unwrap();
            let cfg: Config = toml::from_str(&raw).unwrap();
            cfg.validate().unwrap();
        }
    }

    #[test]
    fn rejects_remote_rpc_and_unsafe_wallet_names() {
        let raw = Config::example_toml("regtest").unwrap();
        let mut cfg: Config = toml::from_str(&raw).unwrap();
        cfg.bitcoin.rpc_url = "http://example.com:18443".into();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("127.0.0.1"));

        cfg.bitcoin.rpc_url = "http://127.0.0.1:18443@example.com".into();
        assert!(cfg.validate().is_err());

        cfg.bitcoin.rpc_url = "http://127.0.0.1:18443".into();
        cfg.bitcoin.wallet_name = "../other-wallet".into();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("wallet_name"));
    }

    #[cfg(unix)]
    #[test]
    fn requires_owner_only_config_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("tesaurus.toml");
        fs::write(&path, Config::example_toml("regtest").unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Config::load(&path).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        Config::load(path).unwrap();
    }
}
