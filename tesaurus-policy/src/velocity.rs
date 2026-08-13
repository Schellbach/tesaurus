//! Velocity caps (external value only).

use crate::constants::{VELOCITY_PER_144_SATS, VELOCITY_PER_SIG_SATS, VELOCITY_WINDOW_BLOCKS};
use crate::error::{PolicyError, PolicyErrorCode, PolicyResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VelocitySample {
    /// Core B tip height at the time of a previous successful signature.
    /// Production: record this from the agent's local store, not coordinator metadata.
    pub tip_height: u32,
    pub external_sats: u64,
}

pub fn check_velocity_per_signature(external_sats: u64) -> PolicyResult<()> {
    check_velocity_cap(external_sats, VELOCITY_PER_SIG_SATS)
}

pub fn check_velocity_cap(external_sats: u64, cap: u64) -> PolicyResult<()> {
    if external_sats > cap {
        return Err(PolicyError::new(
            PolicyErrorCode::Velocity,
            format!("external {external_sats} exceeds per-signature cap {cap}"),
        ));
    }
    Ok(())
}

/// Sum of in-window previous externals plus `this_external` must be `<= 50_000_000`.
///
/// The window is the trailing `VELOCITY_WINDOW_BLOCKS` (144) heights ending at
/// `tip_height`, i.e. `tip_height.saturating_sub(143) ..= tip_height`.
pub fn check_velocity_window(
    samples: &[VelocitySample],
    tip_height: u32,
    this_external: u64,
) -> PolicyResult<()> {
    check_velocity_window_capped(
        samples,
        tip_height,
        this_external,
        VELOCITY_PER_SIG_SATS,
        VELOCITY_PER_144_SATS,
    )
}

/// Same as [`check_velocity_window`], with caps taken from `AgentPin`.
pub fn check_velocity_window_capped(
    samples: &[VelocitySample],
    tip_height: u32,
    this_external: u64,
    per_sig_sats: u64,
    per_window_sats: u64,
) -> PolicyResult<()> {
    check_velocity_cap(this_external, per_sig_sats)?;
    let window_start = tip_height.saturating_sub(VELOCITY_WINDOW_BLOCKS.saturating_sub(1));
    let mut total = this_external;
    for sample in samples {
        if sample.tip_height >= window_start && sample.tip_height <= tip_height {
            total = total.checked_add(sample.external_sats).ok_or_else(|| {
                PolicyError::new(
                    PolicyErrorCode::Velocity,
                    "velocity window sum overflows u64",
                )
            })?;
        }
    }
    if total > per_window_sats {
        return Err(PolicyError::new(
            PolicyErrorCode::Velocity,
            format!(
                "window total {total} exceeds {per_window_sats} over {VELOCITY_WINDOW_BLOCKS} blocks"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_signature_boundary() {
        check_velocity_per_signature(VELOCITY_PER_SIG_SATS).unwrap();
        check_velocity_per_signature(0).unwrap();
        let err = check_velocity_per_signature(VELOCITY_PER_SIG_SATS + 1).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::Velocity);
    }

    #[test]
    fn window_includes_this_external_and_trailing_144() {
        let tip = 10_000;
        let in_window = VelocitySample {
            tip_height: tip - 143,
            external_sats: 40_000_000,
        };
        check_velocity_window(&[in_window], tip, 10_000_000).unwrap();
        let err = check_velocity_window(&[in_window], tip, 10_000_001).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::Velocity);
    }

    #[test]
    fn samples_before_window_are_ignored() {
        let tip = 10_000;
        let old = VelocitySample {
            tip_height: tip - 144,
            external_sats: 50_000_000,
        };
        check_velocity_window(&[old], tip, 10_000_000).unwrap();
    }

    #[test]
    fn exact_50m_window_is_allowed() {
        let tip = 200;
        let samples = [
            VelocitySample {
                tip_height: tip,
                external_sats: 20_000_000,
            },
            VelocitySample {
                tip_height: tip - 10,
                external_sats: 20_000_000,
            },
        ];
        check_velocity_window(&samples, tip, 10_000_000).unwrap();
    }
}
