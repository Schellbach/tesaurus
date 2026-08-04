//! Transaction construction, signing, and broadcast.

use crate::descriptor::VaultDescriptor;
use crate::error::{Error, Result};
use crate::keys::VaultKey;
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
use bitcoincore_rpc::{Client, RpcApi};
use miniscript::Satisfier;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

const MAX_FEE_SATS: u64 = 1_000_000;
const MAX_FEE_RATE_SAT_PER_VB: u64 = 100;
const MAX_SELECTED_INPUTS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendPath {
    /// primary + override (always available)
    Primary,
    /// any 2-of-3 including agent after CSV maturity
    Recovery,
}

#[derive(Debug, Clone)]
pub struct SpendRequest {
    pub destination: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub path: SpendPath,
}

#[derive(Debug, Clone)]
pub struct BuiltSpend {
    pub tx_hex: String,
    pub txid: String,
    pub path: SpendPath,
    pub fee_sats: u64,
    pub amount_sats: u64,
    pub change_sats: u64,
}

struct KeySatisfier<'a> {
    sigs: &'a HashMap<PublicKey, ecdsa::Signature>,
    older_ok: bool,
}

impl Satisfier<PublicKey> for KeySatisfier<'_> {
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
        self.vault.require_network(self.network)?;
        if req.amount_sats == 0 {
            return Err(Error::spend("amount must be greater than zero"));
        }
        if req.fee_sats > MAX_FEE_SATS {
            return Err(Error::spend(format!(
                "fee {} exceeds research safety cap of {MAX_FEE_SATS} sats",
                req.fee_sats
            )));
        }
        if req.fee_sats > req.amount_sats {
            return Err(Error::spend("fee must not exceed destination amount"));
        }
        let target = req
            .amount_sats
            .checked_add(req.fee_sats)
            .ok_or_else(|| Error::spend("amount plus fee overflows u64"))?;

        let dest: Address = Address::from_str(&req.destination)
            .map_err(|e| Error::spend(format!("invalid destination: {e}")))?
            .require_network(self.network)
            .map_err(|e| Error::spend(format!("destination network mismatch: {e}")))?;
        let destination_script = dest.script_pubkey();
        let minimum_destination = destination_script.minimal_non_dust().to_sat();
        if req.amount_sats < minimum_destination {
            return Err(Error::spend(format!(
                "destination amount {} is below the {minimum_destination}-sat dust threshold",
                req.amount_sats
            )));
        }

        let selected = select_coins(utxos, target, req.path)?;
        let total_in = selected.iter().try_fold(0u64, |total, utxo| {
            total
                .checked_add(utxo.txout.value.to_sat())
                .ok_or_else(|| Error::spend("selected input total overflows u64"))
        })?;
        if total_in < target {
            return Err(Error::spend(format!(
                "insufficient funds: have {total_in} sats, need {target}"
            )));
        }
        let change = total_in
            .checked_sub(target)
            .ok_or_else(|| Error::spend("selected input total is below amount plus fee"))?;
        let change_addr = self.vault.address()?;
        let change_script = change_addr.script_pubkey();
        let minimum_change = change_script.minimal_non_dust().to_sat();
        if change > 0 && change < minimum_change {
            return Err(Error::spend(format!(
                "change of {change} sats is below the {minimum_change}-sat dust threshold; \
                 adjust amount or fee"
            )));
        }

        let sequence = match req.path {
            SpendPath::Primary => Sequence::ENABLE_RBF_NO_LOCKTIME,
            SpendPath::Recovery => Sequence::from_height(self.vault.csv_blocks as u16),
        };

        let mut outputs = vec![TxOut {
            value: Amount::from_sat(req.amount_sats),
            script_pubkey: destination_script,
        }];
        if change > 0 {
            outputs.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: change_script,
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
                    let required = match req.path {
                        SpendPath::Primary => "primary + override",
                        SpendPath::Recovery => "two local recovery-path keys",
                    };
                    return Err(Error::spend(format!(
                        "could not satisfy {0:?} path; need {required}; network co-signing is disabled",
                        req.path
                    )));
                }
            }
        }

        let maximum_fee = u64::try_from(tx.vsize())
            .ok()
            .and_then(|vsize| vsize.checked_mul(MAX_FEE_RATE_SAT_PER_VB))
            .ok_or_else(|| Error::spend("transaction fee-rate calculation overflowed"))?;
        if req.fee_sats > maximum_fee {
            return Err(Error::spend(format!(
                "fee {} exceeds research cap of {MAX_FEE_RATE_SAT_PER_VB} sat/vB for this transaction",
                req.fee_sats
            )));
        }

        Ok(BuiltSpend {
            tx_hex: bitcoin::consensus::encode::serialize_hex(&tx),
            txid: tx.compute_txid().to_string(),
            path: req.path,
            fee_sats: req.fee_sats,
            amount_sats: req.amount_sats,
            change_sats: change,
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
        total = total
            .checked_add(u.txout.value.to_sat())
            .ok_or_else(|| Error::spend("available input total overflows u64"))?;
        selected.push(u);
        if selected.len() > MAX_SELECTED_INPUTS {
            return Err(Error::spend(format!(
                "spend requires more than {MAX_SELECTED_INPUTS} inputs"
            )));
        }
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

pub fn validate_built_spend(
    built: &BuiltSpend,
    vault: &VaultDescriptor,
    network: Network,
    available_utxos: &[VaultUtxo],
    req: &SpendRequest,
) -> Result<Transaction> {
    vault.require_network(network)?;
    if req.amount_sats == 0 || req.fee_sats > MAX_FEE_SATS || req.fee_sats > req.amount_sats {
        return Err(Error::spend(
            "requested amount or fee violates research safety limits",
        ));
    }
    if built.path != req.path
        || built.amount_sats != req.amount_sats
        || built.fee_sats != req.fee_sats
    {
        return Err(Error::spend(
            "built transaction metadata does not match the requested spend",
        ));
    }

    let raw =
        hex::decode(&built.tx_hex).map_err(|e| Error::spend(format!("invalid tx hex: {e}")))?;
    let tx: Transaction = bitcoin::consensus::deserialize(&raw)
        .map_err(|e| Error::spend(format!("tx decode: {e}")))?;
    if tx.compute_txid().to_string() != built.txid {
        return Err(Error::spend("reported txid does not match transaction"));
    }
    if tx.input.is_empty() {
        return Err(Error::spend("transaction has no inputs"));
    }
    if tx.input.len() > MAX_SELECTED_INPUTS {
        return Err(Error::spend(
            "transaction exceeds the input-count safety limit",
        ));
    }
    if tx.version != Version::TWO || tx.lock_time != LockTime::ZERO {
        return Err(Error::spend(
            "transaction version or lock time does not match the builder",
        ));
    }
    let maximum_fee = u64::try_from(tx.vsize())
        .ok()
        .and_then(|vsize| vsize.checked_mul(MAX_FEE_RATE_SAT_PER_VB))
        .ok_or_else(|| Error::spend("transaction fee-rate calculation overflowed"))?;
    if req.fee_sats > maximum_fee {
        return Err(Error::spend(
            "transaction exceeds the fee-rate safety limit",
        ));
    }

    let vault_script = vault.address()?.script_pubkey();
    let available: HashMap<_, _> = available_utxos
        .iter()
        .map(|utxo| (utxo.outpoint, utxo))
        .collect();
    let expected_sequence = match req.path {
        SpendPath::Primary => Sequence::ENABLE_RBF_NO_LOCKTIME,
        SpendPath::Recovery => Sequence::from_height(vault.csv_blocks as u16),
    };
    let mut seen = HashSet::new();
    let mut total_in = 0u64;
    for input in &tx.input {
        if !seen.insert(input.previous_output) {
            return Err(Error::spend("transaction contains a duplicate input"));
        }
        let utxo = available
            .get(&input.previous_output)
            .ok_or_else(|| Error::spend("transaction contains an unknown input"))?;
        if utxo.txout.script_pubkey != vault_script {
            return Err(Error::spend(
                "input does not belong to the configured vault",
            ));
        }
        let spendable = match req.path {
            SpendPath::Primary => utxo.spendable_primary,
            SpendPath::Recovery => utxo.spendable_recovery,
        };
        if !spendable {
            return Err(Error::spend("input is not spendable on the requested path"));
        }
        if input.sequence != expected_sequence {
            return Err(Error::spend(
                "input sequence does not match the requested path",
            ));
        }
        if input.witness.is_empty() {
            return Err(Error::spend("transaction input is missing a witness"));
        }
        total_in = total_in
            .checked_add(utxo.txout.value.to_sat())
            .ok_or_else(|| Error::spend("transaction input total overflows u64"))?;
    }

    let destination = Address::from_str(&req.destination)
        .map_err(|e| Error::spend(format!("invalid destination: {e}")))?
        .require_network(network)
        .map_err(|e| Error::spend(format!("destination network mismatch: {e}")))?;
    let destination_script = destination.script_pubkey();
    if req.amount_sats < destination_script.minimal_non_dust().to_sat() {
        return Err(Error::spend("destination output is dust"));
    }
    let expected_output_count = if built.change_sats > 0 { 2 } else { 1 };
    if tx.output.len() != expected_output_count {
        return Err(Error::spend("transaction has unexpected outputs"));
    }
    if tx.output[0].value.to_sat() != req.amount_sats
        || tx.output[0].script_pubkey != destination_script
    {
        return Err(Error::spend(
            "transaction destination output does not match the request",
        ));
    }
    if built.change_sats > 0
        && (built.change_sats < vault_script.minimal_non_dust().to_sat()
            || tx.output[1].value.to_sat() != built.change_sats
            || tx.output[1].script_pubkey != vault_script)
    {
        return Err(Error::spend(
            "transaction change output does not return to the configured vault",
        ));
    }

    let total_out = tx.output.iter().try_fold(0u64, |total, output| {
        total
            .checked_add(output.value.to_sat())
            .ok_or_else(|| Error::spend("transaction output total overflows u64"))
    })?;
    let actual_fee = total_in
        .checked_sub(total_out)
        .ok_or_else(|| Error::spend("transaction outputs exceed its known inputs"))?;
    if actual_fee != req.fee_sats {
        return Err(Error::spend(format!(
            "transaction fee {actual_fee} does not match requested fee {}",
            req.fee_sats
        )));
    }
    let expected_change = total_in
        .checked_sub(
            req.amount_sats
                .checked_add(req.fee_sats)
                .ok_or_else(|| Error::spend("amount plus fee overflows u64"))?,
        )
        .ok_or_else(|| Error::spend("known inputs are below amount plus fee"))?;
    if built.change_sats != expected_change {
        return Err(Error::spend(
            "reported change does not match known inputs and outputs",
        ));
    }

    Ok(tx)
}

pub fn broadcast(client: &Client, tx: &Transaction) -> Result<String> {
    let results = client.test_mempool_accept(&[tx])?;
    if results.len() != 1 {
        return Err(Error::spend(format!(
            "Bitcoin Core returned {} mempool-acceptance results for one transaction",
            results.len()
        )));
    }
    let result = results
        .first()
        .ok_or_else(|| Error::spend("Bitcoin Core returned no mempool-acceptance result"))?;
    if result.txid != tx.compute_txid() {
        return Err(Error::spend(
            "Bitcoin Core returned a mismatched transaction ID",
        ));
    }
    if !result.allowed {
        return Err(Error::spend(format!(
            "Bitcoin Core rejected transaction before broadcast: {}",
            result.reject_reason.as_deref().unwrap_or("unknown reason")
        )));
    }
    let txid = client.send_raw_transaction(tx)?;
    Ok(txid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyRole;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::OutPoint;

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

        let utxos = [utxo];
        let built = SpendBuilder::new(&vault, Network::Regtest)
            .build_and_sign(&utxos, &req, &[primary, override_key])
            .unwrap();
        assert!(!built.tx_hex.is_empty());
        validate_built_spend(&built, &vault, Network::Regtest, &utxos, &req).unwrap();

        let mut tampered = built;
        tampered.txid = "00".into();
        assert!(validate_built_spend(&tampered, &vault, Network::Regtest, &utxos, &req).is_err());
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

        let utxos = [utxo];
        let built = SpendBuilder::new(&vault, Network::Regtest)
            .build_and_sign(&utxos, &req, &[primary, agent])
            .unwrap();
        let tx: Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&built.tx_hex).unwrap()).unwrap();
        assert_eq!(tx.input[0].sequence, Sequence::from_height(10));
        assert!(tx.input[0].witness.len() >= 3);
        validate_built_spend(&built, &vault, Network::Regtest, &utxos, &req).unwrap();
    }

    #[test]
    fn recovery_with_one_key_fails_instead_of_returning_partial_tx() {
        let secp = Secp256k1::new();
        let primary = key(KeyRole::Primary, 31);
        let vault = VaultDescriptor::build(
            primary.public_key(&secp),
            key(KeyRole::Override, 32).public_key(&secp),
            key(KeyRole::Agent, 33).public_key(&secp),
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
        let req = SpendRequest {
            destination: vault.receive_address.clone(),
            amount_sats: 100_000,
            fee_sats: 1_000,
            path: SpendPath::Recovery,
        };

        let err = SpendBuilder::new(&vault, Network::Regtest)
            .build_and_sign(&[utxo], &req, &[primary])
            .unwrap_err()
            .to_string();
        assert!(err.contains("two local recovery-path keys"));
        assert!(err.contains("network co-signing is disabled"));
    }

    #[test]
    fn rejects_arithmetic_overflow_before_coin_selection() {
        let secp = Secp256k1::new();
        let primary = key(KeyRole::Primary, 21);
        let override_key = key(KeyRole::Override, 22);
        let vault = VaultDescriptor::build(
            primary.public_key(&secp),
            override_key.public_key(&secp),
            key(KeyRole::Agent, 23).public_key(&secp),
            10,
            Network::Regtest,
        )
        .unwrap();
        let req = SpendRequest {
            destination: vault.receive_address.clone(),
            amount_sats: u64::MAX,
            fee_sats: 1,
            path: SpendPath::Primary,
        };

        let err = SpendBuilder::new(&vault, Network::Regtest)
            .build_and_sign(&[], &req, &[primary, override_key])
            .unwrap_err()
            .to_string();
        assert!(err.contains("overflows u64"));
    }
}
