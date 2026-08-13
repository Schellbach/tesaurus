//! Structural helpers (locktime, sighash, foreign inputs, recovery nSequence).
//!
//! TODO(gate-2): parse PSBT v0 (`PSBT_PARSE` / `UNKNOWN_FIELD`), pin descriptor
//! matching (`DESCRIPTOR_MISMATCH`), prevout checks, and D5 fee-bump
//! (`FEE_BUMP_INVALID`). See `docs/PSBT_AGENT_PROTOCOL.md` §6.2–§8.

use bitcoin::blockdata::script::Script;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{absolute::LockTime, Sequence};

use crate::error::{PolicyError, PolicyErrorCode, PolicyResult};

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
