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

    pub fn address(&self) -> Result<Address> {
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
        v.parsed().unwrap().sanity_check().unwrap();
    }
}
