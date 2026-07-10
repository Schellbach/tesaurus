//! Transaction construction, signing, and broadcast.

use crate::descriptor::VaultDescriptor;
use crate::error::{Error, Result};
use crate::keys::{KeyRole, VaultKey};
use crate::wallet::VaultUtxo;
use bitcoin::absolute::LockTime;
use bitcoin::ecdsa;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoincore_rpc::{RpcApi, Client};
use miniscript::Satisfier;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpendPath {
    /// primary + override (always available)
    Primary,
    /// any 2-of-3 including agent after CSV maturity
    Recovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendRequest {
    pub destination: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub path: SpendPath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltSpend {
    pub tx_hex: String,
    pub txid: String,
    pub path: SpendPath,
    pub fee_sats: u64,
    pub amount_sats: u64,
    pub change_sats: u64,
    /// True if the transaction still needs the agent signature.
    pub needs_agent: bool,
    pub psbt_incomplete_hex: Option<String>,
}

struct KeySatisfier<'a> {
    sigs: &'a HashMap<PublicKey, ecdsa::Signature>,
    older_ok: bool,
}

impl<'a> Satisfier<PublicKey> for KeySatisfier<'a> {
    fn lookup_ecdsa_sig(&self, pk: &PublicKey) -> Option<ecdsa::Signature> {
        self.sigs.get(pk).copied()
    }

    fn check_older(&self, _: bitcoin::relative::LockTime) -> bool {
        self.older_ok
    }
}

pub struct SpendBuilder<'a> {
    pub vault: &'a VaultDescriptor,
    pub network: Network,
    pub secp: Secp256k1<All>,
}

impl<'a> SpendBuilder<'a> {
    pub fn new(vault: &'a VaultDescriptor, network: Network) -> Self {
        Self {
            vault,
            network,
            secp: Secp256k1::new(),
        }
    }

    pub fn build_and_sign(
        &self,
        utxos: &[VaultUtxo],
        req: &SpendRequest,
        keys: &[VaultKey],
    ) -> Result<BuiltSpend> {
        let dest: Address = Address::from_str(&req.destination)
            .map_err(|e| Error::spend(format!("invalid destination: {e}")))?
            .require_network(self.network)
            .map_err(|e| Error::spend(format!("destination network mismatch: {e}")))?;

        let selected = select_coins(utxos, req.amount_sats + req.fee_sats, req.path)?;
        let total_in: u64 = selected.iter().map(|u| u.txout.value.to_sat()).sum();
        if total_in < req.amount_sats + req.fee_sats {
            return Err(Error::spend(format!(
                "insufficient funds: have {total_in} sats, need {}",
                req.amount_sats + req.fee_sats
            )));
        }
        let change = total_in - req.amount_sats - req.fee_sats;
        let change_addr = self.vault.address()?;

        let sequence = match req.path {
            SpendPath::Primary => Sequence::ENABLE_RBF_NO_LOCKTIME,
            SpendPath::Recovery => Sequence::from_height(self.vault.csv_blocks as u16),
        };

        let mut outputs = vec![TxOut {
            value: Amount::from_sat(req.amount_sats),
            script_pubkey: dest.script_pubkey(),
        }];
        if change > 546 {
            outputs.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: change_addr.script_pubkey(),
            });
        }

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: selected
                .iter()
                .map(|u| TxIn {
                    previous_output: u.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs,
        };

        let desc = self.vault.parsed()?;
        let witness_script = desc
            .explicit_script()
            .map_err(|e| Error::spend(format!("witness script: {e}")))?;

        let older_ok = matches!(req.path, SpendPath::Recovery);

        for (vin, utxo) in selected.iter().enumerate() {
            let mut cache = SighashCache::new(&tx);
            let sighash = cache
                .p2wsh_signature_hash(
                    vin,
                    &witness_script,
                    utxo.txout.value,
                    EcdsaSighashType::All,
                )
                .map_err(|e| Error::spend(format!("sighash: {e}")))?;
            let msg = Message::from_digest(sighash.to_byte_array());

            let mut sigs = HashMap::new();
            for key in keys {
                let pk = key.public_key(&self.secp);
                let signature = self.secp.sign_ecdsa(&msg, &key.private_key().inner);
                sigs.insert(
                    pk,
                    ecdsa::Signature {
                        signature,
                        sighash_type: EcdsaSighashType::All,
                    },
                );
            }

            match desc.get_satisfaction(KeySatisfier {
                sigs: &sigs,
                older_ok,
            }) {
                Ok((witness, script_sig)) => {
                    if !script_sig.is_empty() {
                        return Err(Error::spend("unexpected non-empty script_sig for P2WSH"));
                    }
                    tx.input[vin].witness = Witness::from_slice(&witness);
                }
                Err(_) => {
                    // Not enough signatures yet — leave unsigned for agent completion.
                    if req.path != SpendPath::Recovery {
                        return Err(Error::spend(
                            "could not satisfy primary path; need primary + override keys",
                        ));
                    }
                    // Build a partial witness isn't trivial without PSBT; return unsigned tx hex
                    // and let agent_sign complete via re-sign with combined keys.
                    return Ok(BuiltSpend {
                        tx_hex: bitcoin::consensus::encode::serialize_hex(&tx),
                        txid: tx.compute_txid().to_string(),
                        path: req.path,
                        fee_sats: req.fee_sats,
                        amount_sats: req.amount_sats,
                        change_sats: change,
                        needs_agent: true,
                        psbt_incomplete_hex: Some(bitcoin::consensus::encode::serialize_hex(&tx)),
                    });
                }
            }
        }

        let needs_agent = false;
        Ok(BuiltSpend {
            tx_hex: bitcoin::consensus::encode::serialize_hex(&tx),
            txid: tx.compute_txid().to_string(),
            path: req.path,
            fee_sats: req.fee_sats,
            amount_sats: req.amount_sats,
            change_sats: change,
            needs_agent,
            psbt_incomplete_hex: None,
        })
    }
}

fn select_coins(utxos: &[VaultUtxo], need: u64, path: SpendPath) -> Result<Vec<VaultUtxo>> {
    let mut candidates: Vec<_> = utxos
        .iter()
        .filter(|u| match path {
            SpendPath::Primary => u.spendable_primary,
            SpendPath::Recovery => u.spendable_recovery,
        })
        .cloned()
        .collect();
    candidates.sort_by_key(|u| std::cmp::Reverse(u.txout.value.to_sat()));

    let mut selected = Vec::new();
    let mut total = 0u64;
    for u in candidates {
        total += u.txout.value.to_sat();
        selected.push(u);
        if total >= need {
            return Ok(selected);
        }
    }
    Err(Error::spend(format!(
        "insufficient mature coins for {path:?}: need {need} sats, available {total}"
    )))
}

/// Complete a recovery spend by combining local keys with the agent key.
pub fn sign_recovery_with_keys(
    vault: &VaultDescriptor,
    network: Network,
    utxos: &[VaultUtxo],
    req: &SpendRequest,
    keys: &[VaultKey],
) -> Result<BuiltSpend> {
    let mut req = req.clone();
    req.path = SpendPath::Recovery;
    SpendBuilder::new(vault, network).build_and_sign(utxos, &req, keys)
}

pub fn broadcast(client: &Client, tx_hex: &str) -> Result<String> {
    let raw = hex::decode(tx_hex).map_err(|e| Error::spend(format!("invalid tx hex: {e}")))?;
    let tx: Transaction = bitcoin::consensus::deserialize(&raw)
        .map_err(|e| Error::spend(format!("tx decode: {e}")))?;
    let txid = client.send_raw_transaction(&tx)?;
    Ok(txid.to_string())
}

/// Re-sign helper used by the agent service: given an unsigned/partial recovery tx template
/// rebuilt from the same request, produce a fully signed transaction.
pub fn agent_cosign(
    vault: &VaultDescriptor,
    network: Network,
    utxos: &[VaultUtxo],
    req: &SpendRequest,
    primary: &VaultKey,
    agent: &VaultKey,
) -> Result<BuiltSpend> {
    if primary.role != KeyRole::Primary || agent.role != KeyRole::Agent {
        return Err(Error::spend("agent cosign requires primary + agent keys"));
    }
    sign_recovery_with_keys(vault, network, utxos, req, &[primary.clone(), agent.clone()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyRole;
    use bitcoin::OutPoint;
    use bitcoin::secp256k1::SecretKey;

    fn key(role: KeyRole, seed: u8) -> VaultKey {
        let mut buf = [seed; 32];
        buf[31] = seed.wrapping_add(9);
        let sk = SecretKey::from_slice(&buf).unwrap();
        let pk = bitcoin::PrivateKey::new(sk, Network::Regtest);
        // Reconstruct via WIF to use public constructor path
        VaultKey::from_wif(role, &pk.to_wif()).unwrap()
    }

    #[test]
    fn primary_path_signs() {
        let secp = Secp256k1::new();
        let primary = key(KeyRole::Primary, 1);
        let override_key = key(KeyRole::Override, 2);
        let agent = key(KeyRole::Agent, 3);
        let vault = VaultDescriptor::build(
            primary.public_key(&secp),
            override_key.public_key(&secp),
            agent.public_key(&secp),
            10,
            Network::Regtest,
        )
        .unwrap();

        let utxo = VaultUtxo {
            outpoint: OutPoint::null(),
            txout: TxOut {
                value: Amount::from_sat(200_000),
                script_pubkey: vault.address().unwrap().script_pubkey(),
            },
            confirmations: 1,
            spendable_primary: true,
            spendable_recovery: false,
        };

        let dest_key = key(KeyRole::Primary, 99);
        let dest_pk = dest_key.public_key(&secp);
        let dest = Address::from_script(
            &bitcoin::ScriptBuf::new_p2wpkh(&dest_pk.wpubkey_hash().unwrap()),
            Network::Regtest,
        )
        .unwrap();

        let req = SpendRequest {
            destination: dest.to_string(),
            amount_sats: 100_000,
            fee_sats: 1_000,
            path: SpendPath::Primary,
        };

        let built = SpendBuilder::new(&vault, Network::Regtest)
            .build_and_sign(&[utxo], &req, &[primary, override_key])
            .unwrap();
        assert!(!built.needs_agent);
        assert!(!built.tx_hex.is_empty());
    }

    #[test]
    fn recovery_path_signs_with_primary_and_agent() {
        let secp = Secp256k1::new();
        let primary = key(KeyRole::Primary, 11);
        let override_key = key(KeyRole::Override, 12);
        let agent = key(KeyRole::Agent, 13);
        let vault = VaultDescriptor::build(
            primary.public_key(&secp),
            override_key.public_key(&secp),
            agent.public_key(&secp),
            10,
            Network::Regtest,
        )
        .unwrap();

        let utxo = VaultUtxo {
            outpoint: OutPoint::null(),
            txout: TxOut {
                value: Amount::from_sat(250_000),
                script_pubkey: vault.address().unwrap().script_pubkey(),
            },
            confirmations: 20,
            spendable_primary: true,
            spendable_recovery: true,
        };

        let dest_key = key(KeyRole::Primary, 77);
        let dest_pk = dest_key.public_key(&secp);
        let dest = Address::from_script(
            &bitcoin::ScriptBuf::new_p2wpkh(&dest_pk.wpubkey_hash().unwrap()),
            Network::Regtest,
        )
        .unwrap();

        let req = SpendRequest {
            destination: dest.to_string(),
            amount_sats: 100_000,
            fee_sats: 1_000,
            path: SpendPath::Recovery,
        };

        let built = SpendBuilder::new(&vault, Network::Regtest)
            .build_and_sign(&[utxo], &req, &[primary, agent])
            .unwrap();
        assert!(!built.needs_agent);
        let tx: Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&built.tx_hex).unwrap()).unwrap();
        assert_eq!(tx.input[0].sequence, Sequence::from_height(10));
        assert!(tx.input[0].witness.len() >= 3);
    }
}
