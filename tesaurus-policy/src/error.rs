//! Stable, enumerable policy reject codes.
//!
//! These strings are part of the SignResponse contract. Do not rename without
//! an explicit protocol revision.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

pub type PolicyResult<T> = Result<T, PolicyError>;

/// Enumerable reject / failure codes for agent policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyErrorCode {
    PsbtParse,
    UnknownField,
    Sighash,
    DescriptorMismatch,
    KeySubstitution,
    WrongNetwork,
    WrongGenesis,
    InputScript,
    ForeignInput,
    NotRecoveryPath,
    PrevoutMissing,
    PrevoutMismatch,
    CsvImmatureDepth,
    CsvImmatureWallclock,
    Sequence,
    Change,
    Fee,
    Dust,
    Locktime,
    Velocity,
    Replay,
    ReplayConflict,
    ConfirmRequired,
    ConfirmInvalid,
    Auth,
    Internal,
    FeeBumpInvalid,
}

impl PolicyErrorCode {
    /// Complete stable set (order is part of the enumerable surface).
    pub const ALL: &'static [Self] = &[
        Self::PsbtParse,
        Self::UnknownField,
        Self::Sighash,
        Self::DescriptorMismatch,
        Self::KeySubstitution,
        Self::WrongNetwork,
        Self::WrongGenesis,
        Self::InputScript,
        Self::ForeignInput,
        Self::NotRecoveryPath,
        Self::PrevoutMissing,
        Self::PrevoutMismatch,
        Self::CsvImmatureDepth,
        Self::CsvImmatureWallclock,
        Self::Sequence,
        Self::Change,
        Self::Fee,
        Self::Dust,
        Self::Locktime,
        Self::Velocity,
        Self::Replay,
        Self::ReplayConflict,
        Self::ConfirmRequired,
        Self::ConfirmInvalid,
        Self::Auth,
        Self::Internal,
        Self::FeeBumpInvalid,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PsbtParse => "PSBT_PARSE",
            Self::UnknownField => "UNKNOWN_FIELD",
            Self::Sighash => "SIGHASH",
            Self::DescriptorMismatch => "DESCRIPTOR_MISMATCH",
            Self::KeySubstitution => "KEY_SUBSTITUTION",
            Self::WrongNetwork => "WRONG_NETWORK",
            Self::WrongGenesis => "WRONG_GENESIS",
            Self::InputScript => "INPUT_SCRIPT",
            Self::ForeignInput => "FOREIGN_INPUT",
            Self::NotRecoveryPath => "NOT_RECOVERY_PATH",
            Self::PrevoutMissing => "PREVOUT_MISSING",
            Self::PrevoutMismatch => "PREVOUT_MISMATCH",
            Self::CsvImmatureDepth => "CSV_IMMATURE_DEPTH",
            Self::CsvImmatureWallclock => "CSV_IMMATURE_WALLCLOCK",
            Self::Sequence => "SEQUENCE",
            Self::Change => "CHANGE",
            Self::Fee => "FEE",
            Self::Dust => "DUST",
            Self::Locktime => "LOCKTIME",
            Self::Velocity => "VELOCITY",
            Self::Replay => "REPLAY",
            Self::ReplayConflict => "REPLAY_CONFLICT",
            Self::ConfirmRequired => "CONFIRM_REQUIRED",
            Self::ConfirmInvalid => "CONFIRM_INVALID",
            Self::Auth => "AUTH",
            Self::Internal => "INTERNAL",
            Self::FeeBumpInvalid => "FEE_BUMP_INVALID",
        }
    }
}

impl fmt::Display for PolicyErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PolicyErrorCode {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for code in Self::ALL {
            if code.as_str() == s {
                return Ok(*code);
            }
        }
        Err(PolicyError::new(
            PolicyErrorCode::Internal,
            format!("unknown policy error code {s}"),
        ))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct PolicyError {
    pub code: PolicyErrorCode,
    pub message: String,
}

impl PolicyError {
    pub fn new(code: PolicyErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn from_code(code: PolicyErrorCode) -> Self {
        Self::new(code, code.as_str())
    }
}

impl From<PolicyErrorCode> for PolicyError {
    fn from(code: PolicyErrorCode) -> Self {
        Self::from_code(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn error_codes_are_stable_and_enumerable() {
        assert_eq!(PolicyErrorCode::ALL.len(), 27);
        let mut seen = HashSet::new();
        for code in PolicyErrorCode::ALL {
            assert!(seen.insert(code.as_str()), "duplicate {}", code.as_str());
            assert_eq!(code.as_str().parse::<PolicyErrorCode>().unwrap(), *code);
        }
        for required in [
            "PSBT_PARSE",
            "UNKNOWN_FIELD",
            "SIGHASH",
            "DESCRIPTOR_MISMATCH",
            "KEY_SUBSTITUTION",
            "WRONG_NETWORK",
            "WRONG_GENESIS",
            "INPUT_SCRIPT",
            "FOREIGN_INPUT",
            "NOT_RECOVERY_PATH",
            "PREVOUT_MISSING",
            "PREVOUT_MISMATCH",
            "CSV_IMMATURE_DEPTH",
            "CSV_IMMATURE_WALLCLOCK",
            "SEQUENCE",
            "CHANGE",
            "FEE",
            "DUST",
            "LOCKTIME",
            "VELOCITY",
            "REPLAY",
            "REPLAY_CONFLICT",
            "CONFIRM_REQUIRED",
            "CONFIRM_INVALID",
            "AUTH",
            "INTERNAL",
            "FEE_BUMP_INVALID",
        ] {
            assert!(seen.contains(required), "missing required code {required}");
        }
    }
}
