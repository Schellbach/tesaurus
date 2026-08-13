//! §6 validation state machine (pure; Core B facts are caller-supplied inputs).
//!
//! Does **not** sign, talk to bitcoind, or load keys. `tesaurus-agent` remains
//! fail-closed. Follow-up: agent-key signing behind a reviewed `--via-agent`
//! unlock. Core B RPC mapping lives in `tesaurus-agent`, not here.
//!
//! [`PolicyOutcome::ValidatedUnsigned`] is **not** a co-sign: the replay payload
//! is [`crate::replay::ReplayPayload::Unsigned`]. Only
//! [`PolicyOutcome::Idempotent`] returns a cached signed PSBT. Callers must
//! sign, [`ReplayRecord::attach_signed`], then `commit`.
//!
//! [`ChainView`] / [`AgentAuth`]: tests may lie via `from_test_facts` /
//! `for_test_*`. Production must not; there is no public struct-literal and no
//! `from_core_b` on this crate. `tesaurus-agent` is the TCB that builds the view.
//!
//! Normative order (protocol §6): AUTH → parse v0 → durable replay (D4/D5 store
//! shape) → remaining structure → pin/witness match → foreign inputs →
//! recovery path → CSV/wall-clock (from facts) → amounts → velocity → confirm.
//! A D5 fee-bump is **not** privileged: `ReplayVerdict::FeeBump` still runs
//! every later stage, plus explicit vault-change-only / no-E-increase checks.

use bitcoin::psbt::Psbt;
use bitcoin::transaction::Version;
use bitcoin::{ScriptBuf, Transaction, TxOut};

use crate::confirm::{
    genesis_internal_bytes, txid_display_bytes, verify_confirm_token, ConfirmBinding,
};
use crate::constants::MAX_POLICY_FEE_SATS;
use crate::constants::MAX_POLICY_INPUTS;
use crate::csv::check_csv_maturity;
use crate::error::{PolicyError, PolicyErrorCode, PolicyResult};
use crate::facts::{AgentAuth, ChainView};
use crate::pin::AgentPin;
use crate::replay::{
    is_vault_change_only, outpoints_identical, ReplayRecord, ReplayStore, ReplayVerdict,
};
use crate::structure::{
    parse_psbt_v0, require_locktime_zero, require_no_unknown_psbt_fields,
    require_recovery_sequence, require_sighash_all_on_psbt,
};
use crate::velocity::{check_velocity_cap, check_velocity_window_capped, VelocitySample};

/// SignRequest fields used by policy. Not an auth oracle: pass [`AgentAuth`]
/// separately. There is no `auth_ok: bool` here (a future agent must not
/// forward a coordinator flag).
#[derive(Debug, Clone)]
pub struct PolicyRequest<'a> {
    pub request_id: [u8; 16],
    pub psbt_bytes: &'a [u8],
    pub confirm_token: Option<&'a [u8]>,
    pub claimed_external_sats: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmountBreakdown {
    pub external_sats: u64,
    pub external_script: ScriptBuf,
    pub change_sats: u64,
    pub fee_sats: u64,
    pub input_sats: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyOutcome {
    /// Same `request_id` + `replay_id`: return the cached **signed** payload.
    /// This is the only evaluate path that yields bytes that may be broadcast
    /// (they were signed on a previous success). Do not re-sign.
    Idempotent { cached_signed_psbt: Vec<u8> },
    /// Passed the full §6 machine. **Not signed. Not a co-sign. Do not broadcast.**
    /// Sign (future agent), [`ReplayRecord::attach_signed`], then `commit`.
    ValidatedUnsigned {
        verdict: ReplayVerdict,
        record: Box<ReplayRecord>,
        amounts: AmountBreakdown,
    },
}

pub fn evaluate(
    pin: &AgentPin,
    request: &PolicyRequest<'_>,
    auth: AgentAuth,
    chain: &ChainView,
    store: &ReplayStore,
    velocity_samples: &[VelocitySample],
) -> PolicyResult<PolicyOutcome> {
    // 6.1.1 Authentication — sealed mark, not a request bool
    if !auth.is_ok() {
        return Err(PolicyError::new(
            PolicyErrorCode::Auth,
            "request authentication failed",
        ));
    }

    // 6.2.1 Parse PSBT v0 (required to compute replay_id)
    let psbt = parse_psbt_v0(request.psbt_bytes)?;
    require_no_unknown_psbt_fields(&psbt)?;

    // 6.1 durable replay — vault_script from pin; payload always Unsigned
    let candidate = ReplayRecord::from_pin(pin, request.request_id, &psbt, request.psbt_bytes)?;
    let verdict = store.preflight(&candidate)?;
    if let ReplayVerdict::Idempotent {
        signed_psbt_or_partial,
    } = verdict
    {
        return Ok(PolicyOutcome::Idempotent {
            cached_signed_psbt: signed_psbt_or_partial,
        });
    }

    // 6.2 remaining structure
    require_locktime_zero(psbt.unsigned_tx.lock_time)?;
    if psbt.unsigned_tx.version != Version::TWO {
        return Err(PolicyError::new(
            PolicyErrorCode::NotRecoveryPath,
            format!(
                "transaction version must be 2 for BIP68 CSV, got {}",
                psbt.unsigned_tx.version
            ),
        ));
    }
    if psbt.inputs.len() > MAX_POLICY_INPUTS {
        return Err(PolicyError::new(
            PolicyErrorCode::Fee,
            format!(
                "PSBT has {} inputs; cap is {MAX_POLICY_INPUTS} (anti-DoS bound; no dedicated enumerable code)",
                psbt.inputs.len()
            ),
        ));
    }
    require_sighash_all_on_psbt(&psbt)?;

    let prevouts = collect_prevouts(&psbt)?;
    let amounts = classify_amounts(pin, &psbt.unsigned_tx, &prevouts)?;
    if amounts.fee_sats > MAX_POLICY_FEE_SATS {
        return Err(PolicyError::new(
            PolicyErrorCode::Fee,
            format!(
                "fee {} exceeds policy cap {MAX_POLICY_FEE_SATS}",
                amounts.fee_sats
            ),
        ));
    }
    if amounts.fee_sats == 0 {
        return Err(PolicyError::new(
            PolicyErrorCode::Fee,
            "fee must be positive",
        ));
    }

    // 6.3 / 6.3b / 6.3c keys, foreign inputs, recovery path
    check_inputs_against_pin(pin, &psbt, &prevouts)?;
    check_chain_prevouts(pin, chain, &psbt, &prevouts)?;
    check_recovery_path(pin, &psbt)?;

    // 6.4 Core B CSV + wall-clock (facts only; no RPC)
    if chain.genesis_hash() != pin.genesis_hash() {
        return Err(PolicyError::new(
            PolicyErrorCode::WrongGenesis,
            "chain genesis does not match AgentPin",
        ));
    }
    check_csv_for_inputs(pin, chain, &psbt)?;

    // 6.5 claimed external + dust
    if request.claimed_external_sats != amounts.external_sats {
        return Err(PolicyError::new(
            PolicyErrorCode::Fee,
            format!(
                "claimed_external_sats {} != policy-computed E {}",
                request.claimed_external_sats, amounts.external_sats
            ),
        ));
    }
    check_dust(pin, &amounts)?;

    // D5 explicit policy (not a privileged skip) when the store carved out a bump
    if matches!(verdict, ReplayVerdict::FeeBump) {
        enforce_fee_bump_policy(store, &candidate, amounts.external_sats)?;
    }

    // 6.6 Velocity — pin caps; fee-bumps that do not increase E do not double-charge
    check_velocity_cap(amounts.external_sats, pin.velocity_per_sig_sats())?;
    let charged = if matches!(verdict, ReplayVerdict::FeeBump) {
        0
    } else {
        amounts.external_sats
    };
    check_velocity_window_capped(
        velocity_samples,
        chain.tip_height(),
        charged,
        pin.velocity_per_sig_sats(),
        pin.velocity_per_144_sats(),
    )?;

    // 6.6b Confirm — external-only E; token rebound to this request_id + txid
    check_confirm(pin, request, &psbt, amounts.external_sats)?;

    Ok(PolicyOutcome::ValidatedUnsigned {
        verdict,
        record: Box::new(candidate),
        amounts,
    })
}

fn collect_prevouts(psbt: &Psbt) -> PolicyResult<Vec<TxOut>> {
    let mut out = Vec::with_capacity(psbt.inputs.len());
    for (i, input) in psbt.inputs.iter().enumerate() {
        let txin = &psbt.unsigned_tx.input[i];
        if let Some(utxo) = &input.witness_utxo {
            if let Some(prev_tx) = &input.non_witness_utxo {
                if prev_tx.compute_txid() != txin.previous_output.txid {
                    return Err(PolicyError::new(
                        PolicyErrorCode::PrevoutMismatch,
                        format!("input {i} non_witness_utxo txid does not match outpoint"),
                    ));
                }
                let vout = txin.previous_output.vout as usize;
                let from_tx = prev_tx.output.get(vout).ok_or_else(|| {
                    PolicyError::new(
                        PolicyErrorCode::PrevoutMissing,
                        format!("input {i} non_witness_utxo missing vout {vout}"),
                    )
                })?;
                if from_tx != utxo {
                    return Err(PolicyError::new(
                        PolicyErrorCode::PrevoutMismatch,
                        format!("input {i} witness_utxo does not match non_witness_utxo"),
                    ));
                }
            }
            out.push(utxo.clone());
            continue;
        }
        if let Some(prev_tx) = &input.non_witness_utxo {
            if prev_tx.compute_txid() != txin.previous_output.txid {
                return Err(PolicyError::new(
                    PolicyErrorCode::PrevoutMismatch,
                    format!("input {i} non_witness_utxo txid does not match outpoint"),
                ));
            }
            let vout = txin.previous_output.vout as usize;
            let txout = prev_tx.output.get(vout).cloned().ok_or_else(|| {
                PolicyError::new(
                    PolicyErrorCode::PrevoutMissing,
                    format!("input {i} non_witness_utxo missing vout {vout}"),
                )
            })?;
            out.push(txout);
            continue;
        }
        return Err(PolicyError::new(
            PolicyErrorCode::PrevoutMissing,
            format!("input {i} has no witness_utxo or non_witness_utxo"),
        ));
    }
    Ok(out)
}

fn classify_amounts(
    pin: &AgentPin,
    tx: &Transaction,
    prevouts: &[TxOut],
) -> PolicyResult<AmountBreakdown> {
    let mut input_sats = 0u64;
    for prev in prevouts {
        input_sats = input_sats.checked_add(prev.value.to_sat()).ok_or_else(|| {
            PolicyError::new(PolicyErrorCode::Fee, "input amount sum overflows u64")
        })?;
    }
    let mut output_sats = 0u64;
    let mut externals = Vec::new();
    let mut changes = Vec::new();
    for output in &tx.output {
        output_sats = output_sats
            .checked_add(output.value.to_sat())
            .ok_or_else(|| {
                PolicyError::new(PolicyErrorCode::Fee, "output amount sum overflows u64")
            })?;
        if output.script_pubkey == *pin.script_pubkey() {
            changes.push(output);
        } else {
            externals.push(output);
        }
    }
    if externals.len() != 1 {
        return Err(PolicyError::new(
            PolicyErrorCode::Change,
            format!(
                "expected exactly one external output, found {}",
                externals.len()
            ),
        ));
    }
    if changes.len() > 1 {
        return Err(PolicyError::new(
            PolicyErrorCode::Change,
            "at most one vault change output is allowed",
        ));
    }
    let fee_sats = input_sats.checked_sub(output_sats).ok_or_else(|| {
        PolicyError::new(PolicyErrorCode::Fee, "outputs exceed inputs (negative fee)")
    })?;
    Ok(AmountBreakdown {
        external_sats: externals[0].value.to_sat(),
        external_script: externals[0].script_pubkey.clone(),
        change_sats: changes.first().map(|c| c.value.to_sat()).unwrap_or(0),
        fee_sats,
        input_sats,
    })
}

fn check_dust(pin: &AgentPin, amounts: &AmountBreakdown) -> PolicyResult<()> {
    let external_dust = amounts.external_script.minimal_non_dust().to_sat();
    if amounts.external_sats < external_dust {
        return Err(PolicyError::new(
            PolicyErrorCode::Dust,
            format!(
                "external {} is below dust {}",
                amounts.external_sats, external_dust
            ),
        ));
    }
    if amounts.change_sats > 0 {
        let change_dust = pin.script_pubkey().minimal_non_dust().to_sat();
        if amounts.change_sats < change_dust {
            return Err(PolicyError::new(
                PolicyErrorCode::Dust,
                format!(
                    "vault change {} is below dust {}",
                    amounts.change_sats, change_dust
                ),
            ));
        }
    }
    Ok(())
}

fn check_inputs_against_pin(pin: &AgentPin, psbt: &Psbt, prevouts: &[TxOut]) -> PolicyResult<()> {
    for (i, (input, prevout)) in psbt.inputs.iter().zip(prevouts.iter()).enumerate() {
        if prevout.script_pubkey != *pin.script_pubkey() {
            return Err(PolicyError::new(
                PolicyErrorCode::ForeignInput,
                format!("input {i} does not pay the pinned vault script"),
            ));
        }
        match &input.witness_script {
            Some(ws) if ws.as_bytes() == pin.witness_script().as_bytes() => {}
            Some(_) => {
                return Err(PolicyError::new(
                    PolicyErrorCode::DescriptorMismatch,
                    format!("input {i} witness script does not match AgentPin"),
                ));
            }
            None => {
                return Err(PolicyError::new(
                    PolicyErrorCode::DescriptorMismatch,
                    format!("input {i} is missing the pinned witness script"),
                ));
            }
        }
        if input.redeem_script.is_some() {
            return Err(PolicyError::new(
                PolicyErrorCode::DescriptorMismatch,
                format!("input {i} must not have a redeem script (native P2WSH pin)"),
            ));
        }
        for pk in input.partial_sigs.keys() {
            if !pin.contains_pubkey(pk) {
                return Err(PolicyError::new(
                    PolicyErrorCode::KeySubstitution,
                    format!("input {i} partial sig uses a key that is not in AgentPin"),
                ));
            }
        }
        for pk in input.bip32_derivation.keys() {
            let wrapped = bitcoin::PublicKey::new(*pk);
            if !pin.contains_pubkey(&wrapped) {
                return Err(PolicyError::new(
                    PolicyErrorCode::KeySubstitution,
                    format!("input {i} bip32 key is not in AgentPin"),
                ));
            }
        }
    }
    Ok(())
}

fn check_chain_prevouts(
    pin: &AgentPin,
    chain: &ChainView,
    psbt: &Psbt,
    prevouts: &[TxOut],
) -> PolicyResult<()> {
    for (i, (txin, prevout)) in psbt
        .unsigned_tx
        .input
        .iter()
        .zip(prevouts.iter())
        .enumerate()
    {
        let fact = chain
            .prevouts()
            .iter()
            .find(|f| f.outpoint() == txin.previous_output)
            .ok_or_else(|| {
                PolicyError::new(
                    PolicyErrorCode::PrevoutMissing,
                    format!("input {i} outpoint is not visible on Core B facts"),
                )
            })?;
        if !fact.visible_unspent() {
            return Err(PolicyError::new(
                PolicyErrorCode::ForeignInput,
                format!("input {i} is not independently unspent on Core B"),
            ));
        }
        if fact.script_pubkey() != &prevout.script_pubkey || fact.value() != prevout.value {
            return Err(PolicyError::new(
                PolicyErrorCode::PrevoutMismatch,
                format!("input {i} Core B prevout does not match PSBT"),
            ));
        }
        if fact.script_pubkey() != pin.script_pubkey() {
            return Err(PolicyError::new(
                PolicyErrorCode::ForeignInput,
                format!("input {i} Core B script is not the pinned vault"),
            ));
        }
    }
    Ok(())
}

fn check_recovery_path(pin: &AgentPin, psbt: &Psbt) -> PolicyResult<()> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
            return Err(PolicyError::new(
                PolicyErrorCode::NotRecoveryPath,
                format!("input {i} is already finalized; agent signs recovery PSBTs only"),
            ));
        }
        let sequence = psbt.unsigned_tx.input[i].sequence;
        require_recovery_sequence(sequence, pin.csv_blocks())?;

        let has_primary = input.partial_sigs.contains_key(pin.primary_pubkey());
        let has_override = input.partial_sigs.contains_key(pin.override_pubkey());
        if has_primary && has_override {
            return Err(PolicyError::new(
                PolicyErrorCode::NotRecoveryPath,
                format!(
                    "input {i} already has primary+override partial sigs (always-available path)"
                ),
            ));
        }
    }
    Ok(())
}

fn check_csv_for_inputs(pin: &AgentPin, chain: &ChainView, psbt: &Psbt) -> PolicyResult<()> {
    for (i, txin) in psbt.unsigned_tx.input.iter().enumerate() {
        let fact = chain
            .prevouts()
            .iter()
            .find(|f| f.outpoint() == txin.previous_output)
            .expect("chain facts already required");
        check_csv_maturity(
            chain.tip_height(),
            fact.confirm_height(),
            chain.now_unix(),
            fact.header_time_unix(),
            pin.csv_blocks(),
            pin.safety_margin(),
        )
        .map_err(|e| PolicyError::new(e.code, format!("input {i}: {}", e.message)))?;
        if pin.wall_clock_seconds_per_block() != crate::constants::WALL_CLOCK_SECONDS_PER_BLOCK {
            return Err(PolicyError::new(
                PolicyErrorCode::CsvImmatureWallclock,
                "pin wall_clock_seconds_per_block disagrees with locked protocol constant",
            ));
        }
    }
    Ok(())
}

fn check_confirm(
    pin: &AgentPin,
    request: &PolicyRequest<'_>,
    psbt: &Psbt,
    external_sats: u64,
) -> PolicyResult<()> {
    // Threshold is pin-sourced and external-only (never E+C).
    if external_sats < pin.confirm_threshold_sats() {
        return Ok(());
    }
    let token = request.confirm_token.ok_or_else(|| {
        PolicyError::new(
            PolicyErrorCode::ConfirmRequired,
            format!("external {external_sats} requires confirm_token"),
        )
    })?;
    let binding = ConfirmBinding {
        request_id: request.request_id,
        txid_display: txid_display_bytes(psbt.unsigned_tx.compute_txid()),
        external_amount_sats: external_sats,
        genesis_internal: genesis_internal_bytes(pin.genesis_hash()),
    };
    verify_confirm_token(token, &binding, pin.override_pubkey())
}

/// §8 D5: identical outpoints, vault-change-only, no external increase.
pub fn enforce_fee_bump_policy(
    store: &ReplayStore,
    candidate: &ReplayRecord,
    candidate_external_sats: u64,
) -> PolicyResult<()> {
    let mut matched = false;
    for previous in store.records() {
        if !outpoints_identical(&previous.outpoints, &candidate.outpoints) {
            if previous
                .outpoints
                .iter()
                .any(|op| candidate.outpoints.contains(op))
            {
                return Err(PolicyError::new(
                    PolicyErrorCode::Replay,
                    "fee-bump must not add or drop inputs",
                ));
            }
            continue;
        }
        matched = true;
        if !is_vault_change_only(previous, candidate) {
            return Err(PolicyError::new(
                PolicyErrorCode::FeeBumpInvalid,
                "replacement is not a vault-change-only fee bump",
            ));
        }
        let prev_e = previous
            .outputs
            .iter()
            .find(|o| o.script_pubkey != previous.vault_script)
            .map(|o| o.value.to_sat())
            .unwrap_or(0);
        if candidate_external_sats > prev_e {
            return Err(PolicyError::new(
                PolicyErrorCode::FeeBumpInvalid,
                "fee-bump must not increase external amount E",
            ));
        }
    }
    if !matched {
        return Err(PolicyError::new(
            PolicyErrorCode::FeeBumpInvalid,
            "fee-bump verdict without an identical-outpoint predecessor",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::PrevoutFact;
    use crate::replay::ReplayPayload;
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::{Psbt, PsbtSighashType};
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::EcdsaSighashType;
    use bitcoin::{absolute::LockTime, Network, PublicKey, Sequence, TxIn, Txid, Witness};
    use bitcoin::{Address, Amount, CompressedPublicKey, OutPoint, PrivateKey};

    struct Keys {
        secp: Secp256k1<bitcoin::secp256k1::All>,
        primary: SecretKey,
        override_sk: SecretKey,
        agent: SecretKey,
    }

    impl Keys {
        fn new() -> Self {
            Self {
                secp: Secp256k1::new(),
                primary: sk(1),
                override_sk: sk(2),
                agent: sk(3),
            }
        }

        fn pin(&self) -> AgentPin {
            AgentPin::provision(
                Network::Regtest,
                self.pk(&self.primary),
                self.pk(&self.override_sk),
                self.pk(&self.agent),
                10,
            )
            .unwrap()
        }

        fn pk(&self, sk: &SecretKey) -> PublicKey {
            PublicKey::from_private_key(&self.secp, &PrivateKey::new(*sk, Network::Regtest))
        }

        fn sign_confirm(&self, binding: &ConfirmBinding) -> [u8; 64] {
            let msg =
                Message::from_digest(crate::confirm::confirm_message(binding).to_byte_array());
            self.secp
                .sign_ecdsa(&msg, &self.override_sk)
                .serialize_compact()
        }
    }

    fn sk(seed: u8) -> SecretKey {
        let mut buf = [seed; 32];
        buf[31] = seed.wrapping_add(3);
        SecretKey::from_slice(&buf).unwrap()
    }

    fn dest_script() -> ScriptBuf {
        let pk = PublicKey::from_private_key(
            &Secp256k1::new(),
            &PrivateKey::new(sk(9), Network::Regtest),
        );
        let cpk = CompressedPublicKey::try_from(pk).unwrap();
        Address::p2wpkh(&cpk, Network::Regtest).script_pubkey()
    }

    fn outpoint(n: u8) -> OutPoint {
        let mut txid = [0u8; 32];
        txid[0] = n;
        OutPoint {
            txid: Txid::from_byte_array(txid),
            vout: 0,
        }
    }

    fn rid(n: u8) -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = n;
        id
    }

    #[derive(Clone)]
    struct SpendParts {
        value: u64,
        ops: Vec<OutPoint>,
        external: u64,
        change: u64,
        fee: u64,
    }

    fn default_spend() -> SpendParts {
        // 1 input: 20_000_000; E=1_000_000; fee=1000; change=rest. Under confirm.
        SpendParts {
            value: 20_000_000,
            ops: vec![outpoint(7)],
            external: 1_000_000,
            change: 18_999_000,
            fee: 1000,
        }
    }

    fn build_psbt(
        pin: &AgentPin,
        parts: &SpendParts,
        sequence: Sequence,
        locktime: LockTime,
        sighash: Option<EcdsaSighashType>,
    ) -> (Psbt, Vec<u8>) {
        let mut outputs = vec![TxOut {
            value: Amount::from_sat(parts.external),
            script_pubkey: dest_script(),
        }];
        if parts.change > 0 {
            outputs.push(TxOut {
                value: Amount::from_sat(parts.change),
                script_pubkey: pin.script_pubkey().clone(),
            });
        }
        let tx = Transaction {
            version: Version::TWO,
            lock_time: locktime,
            input: parts
                .ops
                .iter()
                .map(|op| TxIn {
                    previous_output: *op,
                    script_sig: ScriptBuf::new(),
                    sequence,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for input in &mut psbt.inputs {
            input.witness_utxo = Some(TxOut {
                value: Amount::from_sat(parts.value),
                script_pubkey: pin.script_pubkey().clone(),
            });
            input.witness_script = Some(pin.witness_script().clone());
            if let Some(ty) = sighash {
                input.sighash_type = Some(PsbtSighashType::from(ty));
            }
        }
        let bytes = psbt.serialize();
        (psbt, bytes)
    }

    fn mature_chain(pin: &AgentPin, parts: &SpendParts) -> ChainView {
        let need = pin.csv_blocks() + pin.safety_margin();
        let confirm_height = 1;
        let tip = confirm_height + need - 1;
        let t0 = 1_700_000_000_u64;
        let now = t0 + u64::from(need) * pin.wall_clock_seconds_per_block();
        ChainView::from_test_facts(
            pin.genesis_hash(),
            tip,
            now,
            parts
                .ops
                .iter()
                .map(|op| {
                    PrevoutFact::from_test_facts(
                        *op,
                        Amount::from_sat(parts.value),
                        pin.script_pubkey().clone(),
                        confirm_height,
                        t0,
                        true,
                    )
                })
                .collect(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_ok(
        pin: &AgentPin,
        bytes: &[u8],
        request_id: [u8; 16],
        claimed: u64,
        chain: &ChainView,
        store: &ReplayStore,
        token: Option<&[u8]>,
        samples: &[VelocitySample],
    ) -> PolicyOutcome {
        evaluate(
            pin,
            &PolicyRequest {
                request_id,
                psbt_bytes: bytes,
                confirm_token: token,
                claimed_external_sats: claimed,
            },
            AgentAuth::for_test_verified(),
            chain,
            store,
            samples,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_err(
        pin: &AgentPin,
        bytes: &[u8],
        request_id: [u8; 16],
        claimed: u64,
        chain: &ChainView,
        store: &ReplayStore,
        token: Option<&[u8]>,
    ) -> PolicyError {
        evaluate(
            pin,
            &PolicyRequest {
                request_id,
                psbt_bytes: bytes,
                confirm_token: token,
                claimed_external_sats: claimed,
            },
            AgentAuth::for_test_verified(),
            chain,
            store,
            &[],
        )
        .unwrap_err()
    }

    fn commit_validated(store: &mut ReplayStore, outcome: PolicyOutcome, payload: &[u8]) {
        match outcome {
            PolicyOutcome::ValidatedUnsigned { record, .. } => {
                let signed = (*record).attach_signed(payload.to_vec()).unwrap();
                store.commit(signed).unwrap();
            }
            other => panic!("expected ValidatedUnsigned, got {other:?}"),
        }
    }

    #[test]
    fn happy_path_fresh_spend() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (_psbt, bytes) = build_psbt(
            &pin,
            &parts,
            Sequence::from_height(pin.csv_blocks() as u16),
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let chain = mature_chain(&pin, &parts);
        let out = eval_ok(
            &pin,
            &bytes,
            rid(1),
            parts.external,
            &chain,
            &store,
            None,
            &[],
        );
        match out {
            PolicyOutcome::ValidatedUnsigned {
                verdict,
                record,
                amounts,
            } => {
                assert_eq!(verdict, ReplayVerdict::Fresh);
                assert_eq!(record.vault_script, *pin.script_pubkey());
                assert_eq!(record.payload(), &ReplayPayload::Unsigned);
                assert!(record.signed_bytes().is_none());
                let empty = record.clone().attach_signed(Vec::new()).unwrap_err();
                assert_eq!(empty.code, PolicyErrorCode::Internal);
                let signed = record.clone().attach_signed(b"partial".to_vec()).unwrap();
                assert_eq!(
                    signed.payload(),
                    &ReplayPayload::Signed(b"partial".to_vec())
                );
                assert_eq!(signed.signed_bytes(), Some(b"partial".as_slice()));
                assert_eq!(amounts.external_sats, parts.external);
                assert_eq!(amounts.change_sats, parts.change);
                assert_eq!(amounts.fee_sats, parts.fee);
            }
            PolicyOutcome::Idempotent { .. } => panic!("unexpected idempotent"),
        }
    }

    #[test]
    fn auth_fails_before_parse() {
        let keys = Keys::new();
        let pin = keys.pin();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let chain = mature_chain(&pin, &default_spend());
        let err = evaluate(
            &pin,
            &PolicyRequest {
                request_id: rid(1),
                psbt_bytes: b"not-a-psbt",
                confirm_token: None,
                claimed_external_sats: 1,
            },
            AgentAuth::for_test_rejected(),
            &chain,
            &store,
            &[],
        )
        .unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::Auth);
    }

    #[test]
    fn malformed_psbt_is_psbt_parse() {
        let keys = Keys::new();
        let pin = keys.pin();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let chain = mature_chain(&pin, &default_spend());
        let err = eval_err(&pin, b"not-a-psbt", rid(1), 1, &chain, &store, None);
        assert_eq!(err.code, PolicyErrorCode::PsbtParse);
    }

    #[test]
    fn non_v0_psbt_is_psbt_parse() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (mut psbt, _) = build_psbt(
            &pin,
            &parts,
            Sequence::from_height(pin.csv_blocks() as u16),
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        psbt.version = 2;
        let chain = mature_chain(&pin, &parts);
        let err = eval_err(
            &pin,
            &psbt.serialize(),
            rid(1),
            parts.external,
            &chain,
            &store,
            None,
        );
        assert_eq!(err.code, PolicyErrorCode::PsbtParse);
    }

    #[test]
    fn sighash_missing_rejected() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (_psbt, bytes) = build_psbt(
            &pin,
            &parts,
            Sequence::from_height(pin.csv_blocks() as u16),
            LockTime::ZERO,
            None,
        );
        let chain = mature_chain(&pin, &parts);
        let err = eval_err(&pin, &bytes, rid(1), parts.external, &chain, &store, None);
        assert_eq!(err.code, PolicyErrorCode::Sighash);
    }

    #[test]
    fn locktime_nonzero_rejected() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (_psbt, bytes) = build_psbt(
            &pin,
            &parts,
            Sequence::from_height(pin.csv_blocks() as u16),
            LockTime::from_consensus(1),
            Some(EcdsaSighashType::All),
        );
        let chain = mature_chain(&pin, &parts);
        let err = eval_err(&pin, &bytes, rid(1), parts.external, &chain, &store, None);
        assert_eq!(err.code, PolicyErrorCode::Locktime);
    }

    #[test]
    fn sighash_not_all_rejected() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (_psbt, bytes) = build_psbt(
            &pin,
            &parts,
            Sequence::from_height(pin.csv_blocks() as u16),
            LockTime::ZERO,
            Some(EcdsaSighashType::None),
        );
        let chain = mature_chain(&pin, &parts);
        let err = eval_err(&pin, &bytes, rid(1), parts.external, &chain, &store, None);
        assert_eq!(err.code, PolicyErrorCode::Sighash);
    }

    #[test]
    fn foreign_input_rejected() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (mut psbt, _) = build_psbt(
            &pin,
            &parts,
            Sequence::from_height(pin.csv_blocks() as u16),
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let foreign = dest_script();
        psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = foreign.clone();
        let chain = mature_chain(&pin, &parts).with_test_prevout_script(0, foreign);
        let err = eval_err(
            &pin,
            &psbt.serialize(),
            rid(1),
            parts.external,
            &chain,
            &store,
            None,
        );
        assert_eq!(err.code, PolicyErrorCode::ForeignInput);
    }

    #[test]
    fn witness_script_mismatch_is_descriptor_mismatch() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (mut psbt, _) = build_psbt(
            &pin,
            &parts,
            Sequence::from_height(pin.csv_blocks() as u16),
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        psbt.inputs[0].witness_script = Some(bitcoin::script::Builder::new().into_script());
        let chain = mature_chain(&pin, &parts);
        let err = eval_err(
            &pin,
            &psbt.serialize(),
            rid(1),
            parts.external,
            &chain,
            &store,
            None,
        );
        assert_eq!(err.code, PolicyErrorCode::DescriptorMismatch);
    }

    #[test]
    fn not_recovery_path_bad_sequence() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (_psbt, bytes) = build_psbt(
            &pin,
            &parts,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let chain = mature_chain(&pin, &parts);
        let err = eval_err(&pin, &bytes, rid(1), parts.external, &chain, &store, None);
        assert_eq!(err.code, PolicyErrorCode::NotRecoveryPath);
    }

    #[test]
    fn confirm_external_only_and_rebound_txid() {
        let keys = Keys::new();
        let pin = keys.pin();
        let mut parts = default_spend();
        parts.external = 5_000_000;
        parts.change = 14_999_000;
        let tmp = tempfile::tempdir().unwrap();
        let mut store = ReplayStore::init(tmp.path()).unwrap();
        let (psbt, bytes) = build_psbt(
            &pin,
            &parts,
            Sequence::from_height(pin.csv_blocks() as u16),
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let chain = mature_chain(&pin, &parts);
        let err = eval_err(&pin, &bytes, rid(1), parts.external, &chain, &store, None);
        assert_eq!(err.code, PolicyErrorCode::ConfirmRequired);

        let binding = ConfirmBinding {
            request_id: rid(1),
            txid_display: txid_display_bytes(psbt.unsigned_tx.compute_txid()),
            external_amount_sats: parts.external,
            genesis_internal: genesis_internal_bytes(pin.genesis_hash()),
        };
        let token = keys.sign_confirm(&binding);
        let out = eval_ok(
            &pin,
            &bytes,
            rid(1),
            parts.external,
            &chain,
            &store,
            Some(&token),
            &[],
        );
        commit_validated(&mut store, out, b"signed-1");

        // Below-threshold external with huge change must not require confirm.
        let mut small = default_spend();
        small.ops = vec![outpoint(8)];
        small.external = 4_999_999;
        small.change = 15_000_001 - 1000;
        let (_p2, bytes2) = build_psbt(
            &pin,
            &small,
            Sequence::from_height(pin.csv_blocks() as u16),
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let chain2 = mature_chain(&pin, &small);
        eval_ok(
            &pin,
            &bytes2,
            rid(2),
            small.external,
            &chain2,
            &store,
            None,
            &[],
        );
    }

    #[test]
    fn d5_vault_change_only_is_feebump_and_runs_full_policy() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let mut store = ReplayStore::init(tmp.path()).unwrap();
        let seq = Sequence::from_height(pin.csv_blocks() as u16);
        let (_p, bytes) = build_psbt(
            &pin,
            &parts,
            seq,
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let chain = mature_chain(&pin, &parts);
        let out = eval_ok(
            &pin,
            &bytes,
            rid(1),
            parts.external,
            &chain,
            &store,
            None,
            &[],
        );
        commit_validated(&mut store, out, b"orig");

        let mut bump = parts.clone();
        bump.change = parts.change - 500;
        bump.fee = parts.fee + 500;
        let (_pb, bump_bytes) = build_psbt(
            &pin,
            &bump,
            seq,
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let samples = [VelocitySample {
            tip_height: chain.tip_height(),
            external_sats: parts.external,
        }];
        let outcome = eval_ok(
            &pin,
            &bump_bytes,
            rid(2),
            bump.external,
            &chain,
            &store,
            None,
            &samples,
        );
        match &outcome {
            PolicyOutcome::ValidatedUnsigned {
                verdict, amounts, ..
            } => {
                assert_eq!(*verdict, ReplayVerdict::FeeBump);
                assert_eq!(amounts.external_sats, parts.external);
                assert!(amounts.fee_sats > parts.fee);
            }
            PolicyOutcome::Idempotent { .. } => panic!("bump must not be idempotent"),
        }
        commit_validated(&mut store, outcome, b"bump");
    }

    #[test]
    fn d5_added_or_dropped_input_is_replay() {
        let keys = Keys::new();
        let pin = keys.pin();
        let mut parts = default_spend();
        parts.ops = vec![outpoint(7), outpoint(8)];
        parts.value = 10_000_000;
        parts.change = 18_999_000; // 2*10M - E - fee
        let tmp = tempfile::tempdir().unwrap();
        let mut store = ReplayStore::init(tmp.path()).unwrap();
        let seq = Sequence::from_height(pin.csv_blocks() as u16);
        let (_p, bytes) = build_psbt(
            &pin,
            &parts,
            seq,
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let chain = mature_chain(&pin, &parts);
        let out = eval_ok(
            &pin,
            &bytes,
            rid(1),
            parts.external,
            &chain,
            &store,
            None,
            &[],
        );
        commit_validated(&mut store, out, b"orig");

        let mut dropped = parts.clone();
        dropped.ops = vec![outpoint(7)];
        dropped.value = 10_000_000;
        dropped.change = 8_999_000;
        let chain_drop = mature_chain(&pin, &dropped);
        let (_pd, drop_bytes) = build_psbt(
            &pin,
            &dropped,
            seq,
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let err = eval_err(
            &pin,
            &drop_bytes,
            rid(2),
            dropped.external,
            &chain_drop,
            &store,
            None,
        );
        assert_eq!(err.code, PolicyErrorCode::Replay);

        let mut added = parts.clone();
        added.ops = vec![outpoint(7), outpoint(8), outpoint(9)];
        added.value = 10_000_000;
        added.change = 28_999_000;
        let chain_add = mature_chain(&pin, &added);
        let (_pa, add_bytes) = build_psbt(
            &pin,
            &added,
            seq,
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let err = eval_err(
            &pin,
            &add_bytes,
            rid(3),
            added.external,
            &chain_add,
            &store,
            None,
        );
        assert_eq!(err.code, PolicyErrorCode::Replay);
    }

    #[test]
    fn d5_external_diversion_or_e_increase_or_change_increase_is_replay() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let mut store = ReplayStore::init(tmp.path()).unwrap();
        let seq = Sequence::from_height(pin.csv_blocks() as u16);
        let (_p, bytes) = build_psbt(
            &pin,
            &parts,
            seq,
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let chain = mature_chain(&pin, &parts);
        let orig = eval_ok(
            &pin,
            &bytes,
            rid(1),
            parts.external,
            &chain,
            &store,
            None,
            &[],
        );
        commit_validated(&mut store, orig, b"orig");

        let mut more_e = parts.clone();
        more_e.external = parts.external + 1;
        more_e.change = parts.change - 1;
        let (_pe, e_bytes) = build_psbt(
            &pin,
            &more_e,
            seq,
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        assert_eq!(
            eval_err(
                &pin,
                &e_bytes,
                rid(2),
                more_e.external,
                &chain,
                &store,
                None
            )
            .code,
            PolicyErrorCode::Replay
        );

        let mut more_c = parts.clone();
        more_c.change = parts.change + 1;
        more_c.fee = parts.fee - 1;
        // fee would be 999 still positive; input unchanged so outputs must still sum.
        // original: E + C + fee = value. increasing C by 1 requires fee 999.
        let (_pc, c_bytes) = build_psbt(
            &pin,
            &more_c,
            seq,
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        assert_eq!(
            eval_err(
                &pin,
                &c_bytes,
                rid(3),
                more_c.external,
                &chain,
                &store,
                None
            )
            .code,
            PolicyErrorCode::Replay
        );

        let (mut diverted, _) = build_psbt(
            &pin,
            &parts,
            seq,
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let mut other = vec![0x00, 0x14];
        other.extend_from_slice(&[0xcd; 20]);
        diverted.unsigned_tx.output[0].script_pubkey = ScriptBuf::from_bytes(other);
        assert_eq!(
            eval_err(
                &pin,
                &diverted.serialize(),
                rid(4),
                parts.external,
                &chain,
                &store,
                None
            )
            .code,
            PolicyErrorCode::Replay
        );
    }

    #[test]
    fn d5_confirm_token_must_rebind_new_request_and_txid() {
        let keys = Keys::new();
        let pin = keys.pin();
        let mut parts = default_spend();
        parts.external = 5_000_000;
        parts.change = 14_999_000;
        let tmp = tempfile::tempdir().unwrap();
        let mut store = ReplayStore::init(tmp.path()).unwrap();
        let seq = Sequence::from_height(pin.csv_blocks() as u16);
        let (psbt, bytes) = build_psbt(
            &pin,
            &parts,
            seq,
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let chain = mature_chain(&pin, &parts);
        let token1 = keys.sign_confirm(&ConfirmBinding {
            request_id: rid(1),
            txid_display: txid_display_bytes(psbt.unsigned_tx.compute_txid()),
            external_amount_sats: parts.external,
            genesis_internal: genesis_internal_bytes(pin.genesis_hash()),
        });
        let orig = eval_ok(
            &pin,
            &bytes,
            rid(1),
            parts.external,
            &chain,
            &store,
            Some(&token1),
            &[],
        );
        commit_validated(&mut store, orig, b"orig");

        let mut bump = parts.clone();
        bump.change = parts.change - 500;
        bump.fee = parts.fee + 500;
        let (bump_psbt, bump_bytes) = build_psbt(
            &pin,
            &bump,
            seq,
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        // Reused token from the original request/txid must not authorize the bump.
        let err = eval_err(
            &pin,
            &bump_bytes,
            rid(2),
            bump.external,
            &chain,
            &store,
            Some(&token1),
        );
        assert_eq!(err.code, PolicyErrorCode::ConfirmInvalid);

        let token2 = keys.sign_confirm(&ConfirmBinding {
            request_id: rid(2),
            txid_display: txid_display_bytes(bump_psbt.unsigned_tx.compute_txid()),
            external_amount_sats: bump.external,
            genesis_internal: genesis_internal_bytes(pin.genesis_hash()),
        });
        let samples = [VelocitySample {
            tip_height: chain.tip_height(),
            external_sats: parts.external,
        }];
        let outcome = eval_ok(
            &pin,
            &bump_bytes,
            rid(2),
            bump.external,
            &chain,
            &store,
            Some(&token2),
            &samples,
        );
        match outcome {
            PolicyOutcome::ValidatedUnsigned { verdict, .. } => {
                assert_eq!(verdict, ReplayVerdict::FeeBump);
            }
            PolicyOutcome::Idempotent { .. } => panic!("expected fee bump"),
        }
    }

    #[test]
    fn csv_immature_depth_from_chain_facts() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (_p, bytes) = build_psbt(
            &pin,
            &parts,
            Sequence::from_height(pin.csv_blocks() as u16),
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let chain = mature_chain(&pin, &parts).with_test_tip_height(10);
        let err = eval_err(&pin, &bytes, rid(1), parts.external, &chain, &store, None);
        assert_eq!(err.code, PolicyErrorCode::CsvImmatureDepth);
    }

    #[test]
    fn vault_change_below_dust_is_rejected() {
        let keys = Keys::new();
        let pin = keys.pin();
        let mut parts = default_spend();
        parts.change = 1;
        parts.external = parts.value - parts.change - parts.fee;
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (_p, bytes) = build_psbt(
            &pin,
            &parts,
            Sequence::from_height(pin.csv_blocks() as u16),
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let chain = mature_chain(&pin, &parts);
        let err = eval_err(&pin, &bytes, rid(1), parts.external, &chain, &store, None);
        assert_eq!(err.code, PolicyErrorCode::Dust);
        assert!(err.message.contains("vault change"));
    }

    #[test]
    fn attach_signed_from_outside_replay_module_requires_non_empty() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (_psbt, bytes) = build_psbt(
            &pin,
            &parts,
            Sequence::from_height(pin.csv_blocks() as u16),
            LockTime::ZERO,
            Some(EcdsaSighashType::All),
        );
        let chain = mature_chain(&pin, &parts);
        let out = eval_ok(
            &pin,
            &bytes,
            rid(1),
            parts.external,
            &chain,
            &store,
            None,
            &[],
        );
        let PolicyOutcome::ValidatedUnsigned { record, .. } = out else {
            panic!("expected ValidatedUnsigned");
        };
        // evaluate.rs is outside replay.rs: no field assignment; only attach_signed.
        assert_eq!(record.payload(), &ReplayPayload::Unsigned);
        assert_eq!(
            record.clone().attach_signed(Vec::new()).unwrap_err().code,
            PolicyErrorCode::Internal
        );
        let signed = record.attach_signed(b"agent-partial".to_vec()).unwrap();
        assert_eq!(
            signed.payload(),
            &ReplayPayload::Signed(b"agent-partial".to_vec())
        );
    }
}
