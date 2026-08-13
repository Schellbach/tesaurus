//! Structural helpers (PSBT v0 parse, locktime, sighash, foreign inputs, recovery).
//!
//! PSBT v0 only. Unknown maps, taproot fields, and non-empty proprietary keys
//! are rejected (`UNKNOWN_FIELD`). Descriptor / witness matching lives in
//! `evaluate` so `AgentPin` is the sole script source.

use bitcoin::blockdata::script::Script;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{absolute::LockTime, Sequence};

use crate::error::{PolicyError, PolicyErrorCode, PolicyResult};

/// Parse a BIP174 PSBT and require version 0. Malformed or non-v0 → `PSBT_PARSE`.
pub fn parse_psbt_v0(bytes: &[u8]) -> PolicyResult<Psbt> {
    let psbt = Psbt::deserialize(bytes).map_err(|e| {
        PolicyError::new(PolicyErrorCode::PsbtParse, format!("malformed PSBT: {e}"))
    })?;
    if psbt.version != 0 {
        return Err(PolicyError::new(
            PolicyErrorCode::PsbtParse,
            format!("PSBT version {} is not v0", psbt.version),
        ));
    }
    if psbt.inputs.len() != psbt.unsigned_tx.input.len()
        || psbt.outputs.len() != psbt.unsigned_tx.output.len()
    {
        return Err(PolicyError::new(
            PolicyErrorCode::PsbtParse,
            "PSBT input/output count does not match unsigned tx",
        ));
    }
    if psbt.unsigned_tx.input.is_empty() {
        return Err(PolicyError::new(
            PolicyErrorCode::PsbtParse,
            "PSBT has no inputs",
        ));
    }
    if psbt.unsigned_tx.output.is_empty() {
        return Err(PolicyError::new(
            PolicyErrorCode::PsbtParse,
            "PSBT has no outputs",
        ));
    }
    Ok(psbt)
}

/// Reject unknown / proprietary / taproot / hash-preimage maps (fail closed).
pub fn require_no_unknown_psbt_fields(psbt: &Psbt) -> PolicyResult<()> {
    if !psbt.unknown.is_empty() || !psbt.proprietary.is_empty() || !psbt.xpub.is_empty() {
        return Err(PolicyError::new(
            PolicyErrorCode::UnknownField,
            "PSBT global unknown, proprietary, or xpub map is not empty",
        ));
    }
    for (i, input) in psbt.inputs.iter().enumerate() {
        if !input.unknown.is_empty()
            || !input.proprietary.is_empty()
            || !input.ripemd160_preimages.is_empty()
            || !input.sha256_preimages.is_empty()
            || !input.hash160_preimages.is_empty()
            || !input.hash256_preimages.is_empty()
            || input.tap_key_sig.is_some()
            || !input.tap_script_sigs.is_empty()
            || !input.tap_scripts.is_empty()
            || !input.tap_key_origins.is_empty()
            || input.tap_internal_key.is_some()
            || input.tap_merkle_root.is_some()
        {
            return Err(PolicyError::new(
                PolicyErrorCode::UnknownField,
                format!("PSBT input {i} has unknown, proprietary, preimage, or taproot fields"),
            ));
        }
    }
    for (i, output) in psbt.outputs.iter().enumerate() {
        if !output.unknown.is_empty()
            || !output.proprietary.is_empty()
            || output.tap_internal_key.is_some()
            || output.tap_tree.is_some()
            || !output.tap_key_origins.is_empty()
        {
            return Err(PolicyError::new(
                PolicyErrorCode::UnknownField,
                format!("PSBT output {i} has unknown, proprietary, or taproot fields"),
            ));
        }
    }
    Ok(())
}

pub fn require_locktime_zero(locktime: LockTime) -> PolicyResult<()> {
    if locktime != LockTime::ZERO {
        return Err(PolicyError::new(
            PolicyErrorCode::Locktime,
            format!("nLockTime must be 0, got {locktime}"),
        ));
    }
    Ok(())
}

pub fn require_sighash_all(sighash: EcdsaSighashType) -> PolicyResult<()> {
    if sighash != EcdsaSighashType::All {
        return Err(PolicyError::new(
            PolicyErrorCode::Sighash,
            format!("sighash must be SIGHASH_ALL, got {sighash}"),
        ));
    }
    Ok(())
}

/// Every input must *present* sighash type `SIGHASH_ALL` (missing is not defaulted).
pub fn require_sighash_all_on_psbt(psbt: &Psbt) -> PolicyResult<()> {
    let all = PsbtSighashType::from(EcdsaSighashType::All);
    for (i, input) in psbt.inputs.iter().enumerate() {
        match input.sighash_type {
            Some(ty) if ty == all => {}
            Some(ty) => {
                return Err(PolicyError::new(
                    PolicyErrorCode::Sighash,
                    format!("input {i} sighash must be SIGHASH_ALL, got {ty}"),
                ));
            }
            None => {
                return Err(PolicyError::new(
                    PolicyErrorCode::Sighash,
                    format!("input {i} is missing sighash type (SIGHASH_ALL required)"),
                ));
            }
        }
        for (pk, sig) in &input.partial_sigs {
            require_sighash_all(sig.sighash_type).map_err(|e| {
                PolicyError::new(
                    e.code,
                    format!("input {i} partial sig for {pk} is not SIGHASH_ALL"),
                )
            })?;
        }
    }
    Ok(())
}

/// Every input scriptPubKey must equal the pinned vault script.
pub fn require_all_vault_input_scripts<I, S>(
    input_scripts: I,
    vault_script: &Script,
) -> PolicyResult<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<Script>,
{
    for (i, script) in input_scripts.into_iter().enumerate() {
        if script.as_ref().as_bytes() != vault_script.as_bytes() {
            return Err(PolicyError::new(
                PolicyErrorCode::ForeignInput,
                format!("input {i} does not pay the pinned vault script"),
            ));
        }
    }
    Ok(())
}

/// Recovery-path nSequence must enable BIP68 height CSV of at least `csv_blocks`.
pub fn require_recovery_sequence(sequence: Sequence, csv_blocks: u32) -> PolicyResult<()> {
    if sequence_satisfies_older_csv(sequence, csv_blocks) {
        Ok(())
    } else {
        Err(PolicyError::new(
            PolicyErrorCode::NotRecoveryPath,
            format!("nSequence {sequence} does not satisfy older({csv_blocks})"),
        ))
    }
}

pub fn sequence_satisfies_older_csv(sequence: Sequence, csv_blocks: u32) -> bool {
    if csv_blocks == 0 || csv_blocks > u32::from(u16::MAX) {
        return false;
    }
    match sequence.to_relative_lock_time() {
        Some(bitcoin::relative::LockTime::Blocks(height)) => {
            u32::from(height.value()) >= csv_blocks
        }
        Some(bitcoin::relative::LockTime::Time(_)) | None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::opcodes;
    use bitcoin::script::Builder;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness};

    fn dummy_tx(locktime: LockTime, sequence: Sequence) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: locktime,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: Builder::new().push_opcode(opcodes::OP_TRUE).into_script(),
            }],
        }
    }

    fn psbt_from_tx(tx: Transaction) -> Psbt {
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned");
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(2000),
            script_pubkey: Builder::new().push_opcode(opcodes::OP_TRUE).into_script(),
        });
        psbt
    }

    #[test]
    fn parse_psbt_v0_success() {
        let psbt = psbt_from_tx(dummy_tx(LockTime::ZERO, Sequence::from_height(10)));
        let bytes = psbt.serialize();
        let parsed = parse_psbt_v0(&bytes).unwrap();
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.unsigned_tx.input.len(), 1);
    }

    #[test]
    fn parse_rejects_malformed() {
        let err = parse_psbt_v0(b"not-a-psbt").unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::PsbtParse);
    }

    #[test]
    fn parse_rejects_non_v0() {
        let mut psbt = psbt_from_tx(dummy_tx(LockTime::ZERO, Sequence::from_height(10)));
        psbt.version = 2;
        let err = parse_psbt_v0(&psbt.serialize()).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::PsbtParse);
        assert!(err.message.contains("version"));
    }

    #[test]
    fn locktime_must_be_zero() {
        require_locktime_zero(LockTime::ZERO).unwrap();
        let err = require_locktime_zero(LockTime::from_consensus(1)).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::Locktime);
        let err = require_locktime_zero(LockTime::from_consensus(500_000_000)).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::Locktime);
    }

    #[test]
    fn sighash_all_only() {
        require_sighash_all(EcdsaSighashType::All).unwrap();
        for ty in [
            EcdsaSighashType::None,
            EcdsaSighashType::Single,
            EcdsaSighashType::AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        ] {
            let err = require_sighash_all(ty).unwrap_err();
            assert_eq!(err.code, PolicyErrorCode::Sighash, "{ty}");
        }
    }

    #[test]
    fn sighash_missing_on_psbt_is_rejected() {
        let mut psbt = psbt_from_tx(dummy_tx(LockTime::ZERO, Sequence::from_height(10)));
        psbt.inputs[0].sighash_type = None;
        let err = require_sighash_all_on_psbt(&psbt).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::Sighash);
    }

    #[test]
    fn sighash_none_on_psbt_is_rejected() {
        let mut psbt = psbt_from_tx(dummy_tx(LockTime::ZERO, Sequence::from_height(10)));
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::None));
        let err = require_sighash_all_on_psbt(&psbt).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::Sighash);
    }

    #[test]
    fn foreign_input_rejected() {
        let vault = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
        let other = Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .into_script();
        require_all_vault_input_scripts([&vault, &vault], vault.as_script()).unwrap();
        let err = require_all_vault_input_scripts([&vault, &other], vault.as_script()).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::ForeignInput);
    }

    #[test]
    fn recovery_sequence_must_cover_csv() {
        let csv = 4320_u32;
        require_recovery_sequence(Sequence::from_height(csv as u16), csv).unwrap();
        require_recovery_sequence(Sequence::from_height(csv as u16 + 1), csv).unwrap();
        let err =
            require_recovery_sequence(Sequence::from_height(csv as u16 - 1), csv).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::NotRecoveryPath);
        let err = require_recovery_sequence(Sequence::MAX, csv).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::NotRecoveryPath);
        let time_locked = Sequence::from_512_second_intervals(csv as u16);
        let err = require_recovery_sequence(time_locked, csv).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::NotRecoveryPath);
    }
}
