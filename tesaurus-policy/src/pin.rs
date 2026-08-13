//! Pinned vault identity (`AgentPin`, protocol §5).
//!
//! The pin is the source of truth for descriptor, genesis, CSV, pubkeys,
//! velocity, confirm threshold, and wall-clock seconds. Request metadata must
//! not override these fields. Provisioning is an explicit ceremony; this crate
//! does not persist pins or load key files.

use bitcoin::constants::genesis_block;
use bitcoin::{Address, BlockHash, Network, PublicKey, ScriptBuf};
use miniscript::policy::Concrete;
use miniscript::{Descriptor, Miniscript, Segwitv0};
use std::str::FromStr;

use crate::constants::{
    SAFETY_MARGIN_BLOCKS, VELOCITY_PER_144_SATS, VELOCITY_PER_SIG_SATS,
    WALL_CLOCK_SECONDS_PER_BLOCK,
};
use crate::error::{PolicyError, PolicyErrorCode, PolicyResult};
use crate::OOB_CONFIRM_SATS;

/// Locked agent pin (protocol §5). Derived scripts are computed at provision
/// and never taken from a `SignRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPin {
    network: Network,
    genesis_hash: BlockHash,
    descriptor: String,
    csv_blocks: u32,
    primary_pubkey: PublicKey,
    override_pubkey: PublicKey,
    agent_pubkey: PublicKey,
    safety_margin: u32,
    velocity_per_sig_sats: u64,
    velocity_per_144_sats: u64,
    confirm_threshold_sats: u64,
    wall_clock_seconds_per_block: u64,
    script_pubkey: ScriptBuf,
    witness_script: ScriptBuf,
}

impl AgentPin {
    /// Provision a pin from the vault pubkeys and CSV. Locked policy constants
    /// (safety margin, velocity, confirm, wall-clock seconds) are filled from
    /// the protocol; they are not caller-tunable per request.
    pub fn provision(
        network: Network,
        primary: PublicKey,
        override_key: PublicKey,
        agent: PublicKey,
        csv_blocks: u32,
    ) -> PolicyResult<Self> {
        if network == Network::Bitcoin {
            return Err(PolicyError::new(
                PolicyErrorCode::WrongNetwork,
                "mainnet AgentPin provision is disabled (research-only)",
            ));
        }
        if !matches!(
            network,
            Network::Regtest | Network::Testnet | Network::Signet
        ) {
            return Err(PolicyError::new(
                PolicyErrorCode::WrongNetwork,
                format!("network {network} is not enabled for AgentPin"),
            ));
        }
        if csv_blocks == 0 || csv_blocks > u32::from(u16::MAX) {
            return Err(PolicyError::new(
                PolicyErrorCode::DescriptorMismatch,
                "csv_blocks must be in 1..=65535 for relative timelocks",
            ));
        }

        let descriptor = compile_vault_descriptor(primary, override_key, agent, csv_blocks)?;
        let script_pubkey = descriptor.script_pubkey();
        let witness_script = descriptor.explicit_script().map_err(|e| {
            PolicyError::new(
                PolicyErrorCode::DescriptorMismatch,
                format!("pinned descriptor has no witness script: {e}"),
            )
        })?;
        let canonical = descriptor.to_string();

        Ok(Self {
            network,
            genesis_hash: genesis_block(network).block_hash(),
            descriptor: canonical,
            csv_blocks,
            primary_pubkey: primary,
            override_pubkey: override_key,
            agent_pubkey: agent,
            safety_margin: SAFETY_MARGIN_BLOCKS,
            velocity_per_sig_sats: VELOCITY_PER_SIG_SATS,
            velocity_per_144_sats: VELOCITY_PER_144_SATS,
            confirm_threshold_sats: OOB_CONFIRM_SATS,
            wall_clock_seconds_per_block: WALL_CLOCK_SECONDS_PER_BLOCK,
            script_pubkey,
            witness_script,
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn genesis_hash(&self) -> BlockHash {
        self.genesis_hash
    }

    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }

    pub fn csv_blocks(&self) -> u32 {
        self.csv_blocks
    }

    pub fn primary_pubkey(&self) -> &PublicKey {
        &self.primary_pubkey
    }

    pub fn override_pubkey(&self) -> &PublicKey {
        &self.override_pubkey
    }

    pub fn agent_pubkey(&self) -> &PublicKey {
        &self.agent_pubkey
    }

    pub fn safety_margin(&self) -> u32 {
        self.safety_margin
    }

    pub fn velocity_per_sig_sats(&self) -> u64 {
        self.velocity_per_sig_sats
    }

    pub fn velocity_per_144_sats(&self) -> u64 {
        self.velocity_per_144_sats
    }

    pub fn confirm_threshold_sats(&self) -> u64 {
        self.confirm_threshold_sats
    }

    pub fn wall_clock_seconds_per_block(&self) -> u64 {
        self.wall_clock_seconds_per_block
    }

    /// P2WSH scriptPubKey of the pinned vault. Use this for `ReplayRecord.vault_script`.
    pub fn script_pubkey(&self) -> &ScriptBuf {
        &self.script_pubkey
    }

    pub fn witness_script(&self) -> &ScriptBuf {
        &self.witness_script
    }

    pub fn receive_address(&self) -> PolicyResult<Address> {
        Address::from_script(&self.script_pubkey, self.network).map_err(|e| {
            PolicyError::new(
                PolicyErrorCode::DescriptorMismatch,
                format!("pinned script is not a valid address: {e}"),
            )
        })
    }

    pub fn contains_pubkey(&self, pk: &PublicKey) -> bool {
        pk == &self.primary_pubkey || pk == &self.override_pubkey || pk == &self.agent_pubkey
    }
}

fn compile_vault_descriptor(
    primary: PublicKey,
    override_key: PublicKey,
    agent: PublicKey,
    csv_blocks: u32,
) -> PolicyResult<Descriptor<PublicKey>> {
    let policy_str =
        format!("thresh(2,pk({primary}),pk({override_key}),and(pk({agent}),older({csv_blocks})))");
    let policy = Concrete::<PublicKey>::from_str(&policy_str).map_err(|e| {
        PolicyError::new(
            PolicyErrorCode::DescriptorMismatch,
            format!("invalid vault policy: {e}"),
        )
    })?;
    let ms: Miniscript<PublicKey, Segwitv0> = policy.compile().map_err(|e| {
        PolicyError::new(
            PolicyErrorCode::DescriptorMismatch,
            format!("vault policy compile failed: {e}"),
        )
    })?;
    let desc = Descriptor::new_wsh(ms).map_err(|e| {
        PolicyError::new(
            PolicyErrorCode::DescriptorMismatch,
            format!("wsh wrapper failed: {e}"),
        )
    })?;
    desc.sanity_check().map_err(|e| {
        PolicyError::new(
            PolicyErrorCode::DescriptorMismatch,
            format!("descriptor sanity check failed: {e}"),
        )
    })?;
    Ok(desc)
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
    fn provision_rejects_mainnet() {
        let err = AgentPin::provision(Network::Bitcoin, pk(1), pk(2), pk(3), 4320).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::WrongNetwork);
    }

    #[test]
    fn provision_builds_canonical_wsh_and_locked_constants() {
        let pin = AgentPin::provision(Network::Regtest, pk(1), pk(2), pk(3), 10).unwrap();
        assert!(pin.descriptor().starts_with("wsh(thresh(2,"));
        assert_eq!(pin.csv_blocks(), 10);
        assert_eq!(pin.safety_margin(), SAFETY_MARGIN_BLOCKS);
        assert_eq!(pin.velocity_per_sig_sats(), VELOCITY_PER_SIG_SATS);
        assert_eq!(pin.velocity_per_144_sats(), VELOCITY_PER_144_SATS);
        assert_eq!(pin.confirm_threshold_sats(), OOB_CONFIRM_SATS);
        assert_eq!(
            pin.wall_clock_seconds_per_block(),
            WALL_CLOCK_SECONDS_PER_BLOCK
        );
        assert_eq!(
            pin.genesis_hash(),
            genesis_block(Network::Regtest).block_hash()
        );
        assert_eq!(pin.script_pubkey().len(), 34); // P2WSH
        assert!(!pin.witness_script().is_empty());
        pin.receive_address().unwrap();
    }

    #[test]
    fn provision_rejects_zero_csv() {
        let err = AgentPin::provision(Network::Regtest, pk(1), pk(2), pk(3), 0).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::DescriptorMismatch);
    }
}
