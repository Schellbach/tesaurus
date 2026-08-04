//! Miniscript vault descriptor (decaying 2-of-3).

use crate::error::{Error, Result};
use bitcoin::{Address, Network, PublicKey};
use miniscript::policy::Concrete;
use miniscript::{Descriptor, Miniscript, Segwitv0};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// On-chain vault policy:
///
/// `thresh(2, pk(primary), pk(override), and(pk(agent), older(csv)))`
///
/// - Before the relative timelock: spend with **primary + override**
/// - After `csv` confirmations on a coin: any two of {primary, override, agent}
///   (typically **primary + agent** for recovery)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultDescriptor {
    pub descriptor: String,
    pub csv_blocks: u32,
    pub network: String,
    pub primary_pubkey: String,
    pub override_pubkey: String,
    pub agent_pubkey: String,
    pub receive_address: String,
}

impl VaultDescriptor {
    pub fn build(
        primary: PublicKey,
        override_key: PublicKey,
        agent: PublicKey,
        csv_blocks: u32,
        network: Network,
    ) -> Result<Self> {
        if network == Network::Bitcoin {
            return Err(Error::descriptor(
                "mainnet vault construction is disabled in this experimental release",
            ));
        }
        if !matches!(
            network,
            Network::Regtest | Network::Testnet | Network::Signet
        ) {
            return Err(Error::descriptor(format!(
                "network {network} is not enabled for vault construction"
            )));
        }
        if csv_blocks == 0 || csv_blocks > 65535 {
            return Err(Error::descriptor(
                "csv_blocks must be in 1..=65535 for relative timelocks",
            ));
        }

        let policy_str = format!(
            "thresh(2,pk({primary}),pk({override_key}),and(pk({agent}),older({csv_blocks})))"
        );
        let policy = Concrete::<PublicKey>::from_str(&policy_str)
            .map_err(|e| Error::descriptor(format!("invalid policy: {e}")))?;
        let ms: Miniscript<PublicKey, Segwitv0> = policy
            .compile()
            .map_err(|e| Error::descriptor(format!("policy compile failed: {e}")))?;
        let desc = Descriptor::new_wsh(ms)
            .map_err(|e| Error::descriptor(format!("wsh wrapper failed: {e}")))?;
        desc.sanity_check()
            .map_err(|e| Error::descriptor(format!("descriptor sanity check failed: {e}")))?;

        let address = desc
            .address(network)
            .map_err(|e| Error::descriptor(format!("address derivation failed: {e}")))?;

        Ok(Self {
            descriptor: desc.to_string(),
            csv_blocks,
            network: network.to_string(),
            primary_pubkey: primary.to_string(),
            override_pubkey: override_key.to_string(),
            agent_pubkey: agent.to_string(),
            receive_address: address.to_string(),
        })
    }

    pub fn parsed(&self) -> Result<Descriptor<PublicKey>> {
        Descriptor::<PublicKey>::from_str(&self.descriptor)
            .map_err(|e| Error::descriptor(format!("failed to parse stored descriptor: {e}")))
    }

    pub fn validate(&self) -> Result<()> {
        let parsed = self.parsed()?;
        parsed.sanity_check().map_err(|e| {
            Error::descriptor(format!("stored descriptor failed sanity check: {e}"))
        })?;

        let network = Network::from_str(&self.network)
            .map_err(|_| Error::descriptor(format!("invalid network {}", self.network)))?;
        let (primary, override_key, agent) = self.pubkeys()?;
        let canonical = Self::build(primary, override_key, agent, self.csv_blocks, network)?;

        if canonical.descriptor != self.descriptor {
            return Err(Error::descriptor(
                "stored descriptor does not match its pubkeys or csv_blocks",
            ));
        }
        if canonical.receive_address != self.receive_address {
            return Err(Error::descriptor(
                "stored receive_address does not match the descriptor",
            ));
        }
        Ok(())
    }

    pub fn require_network(&self, expected: Network) -> Result<()> {
        self.validate()?;
        let actual = Network::from_str(&self.network)
            .map_err(|_| Error::descriptor(format!("invalid network {}", self.network)))?;
        if actual != expected {
            return Err(Error::descriptor(format!(
                "vault network {actual} does not match configured network {expected}"
            )));
        }
        Ok(())
    }

    pub fn address(&self) -> Result<Address> {
        self.validate()?;
        let network = Network::from_str(&self.network)
            .map_err(|_| Error::descriptor(format!("invalid network {}", self.network)))?;
        self.parsed()?
            .address(network)
            .map_err(|e| Error::descriptor(e.to_string()))
    }

    pub fn pubkeys(&self) -> Result<(PublicKey, PublicKey, PublicKey)> {
        Ok((
            self.primary_pubkey
                .parse()
                .map_err(|e| Error::descriptor(format!("primary pubkey: {e}")))?,
            self.override_pubkey
                .parse()
                .map_err(|e| Error::descriptor(format!("override pubkey: {e}")))?,
            self.agent_pubkey
                .parse()
                .map_err(|e| Error::descriptor(format!("agent pubkey: {e}")))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn pk(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut buf = [seed; 32];
        buf[31] = seed.wrapping_add(3);
        let sk = SecretKey::from_slice(&buf).unwrap();
        PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(sk, Network::Regtest))
    }

    #[test]
    fn builds_sane_descriptor() {
        let v = VaultDescriptor::build(pk(1), pk(2), pk(3), 10, Network::Regtest).unwrap();
        assert!(v.descriptor.starts_with("wsh(thresh(2,"));
        assert!(v.receive_address.starts_with("bcrt1"));
        v.validate().unwrap();
    }

    #[test]
    fn rejects_tampered_metadata() {
        let original = VaultDescriptor::build(pk(1), pk(2), pk(3), 10, Network::Regtest).unwrap();

        let mut address_tamper = original.clone();
        address_tamper.receive_address =
            VaultDescriptor::build(pk(4), pk(5), pk(6), 10, Network::Regtest)
                .unwrap()
                .receive_address;
        assert!(address_tamper.validate().is_err());

        let mut csv_tamper = original;
        csv_tamper.csv_blocks = 11;
        assert!(csv_tamper.validate().is_err());
    }

    #[test]
    fn rejects_network_mismatch() {
        let vault = VaultDescriptor::build(pk(1), pk(2), pk(3), 10, Network::Regtest).unwrap();
        let err = vault
            .require_network(Network::Testnet)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match configured network"));
    }

    #[test]
    fn rejects_mainnet_vault_construction() {
        let err = VaultDescriptor::build(pk(1), pk(2), pk(3), 10, Network::Bitcoin)
            .unwrap_err()
            .to_string();
        assert!(err.contains("mainnet vault construction is disabled"));
    }
}
