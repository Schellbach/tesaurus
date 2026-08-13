//! CSV depth and wall-clock maturity (pure functions).
//!
//! Depth: `tip_height - confirm_height + 1` must be `>= csv_blocks + safety_margin`.
//! Wall-clock: `now_utc >= t_confirm + (csv_blocks + safety_margin) * WALL_CLOCK_SECONDS_PER_BLOCK`.
//!
//! Locked bound: `(4320 + 1008) * 600 = 3_196_800` seconds = **37 days**.
//! Independent failure: fast fake blocks → depth OK, wall-clock short; slow
//! real chain → wall-clock OK, depth short. See `docs/THREAT_MODEL.md` invariant 6.

use crate::constants::WALL_CLOCK_SECONDS_PER_BLOCK;
use crate::error::{PolicyError, PolicyErrorCode, PolicyResult};

/// Confirmations-style depth: the confirming block counts as 1.
pub fn csv_depth(tip_height: u32, confirm_height: u32) -> PolicyResult<u32> {
    tip_height
        .checked_sub(confirm_height)
        .and_then(|delta| delta.checked_add(1))
        .ok_or_else(|| {
            PolicyError::new(
                PolicyErrorCode::CsvImmatureDepth,
                format!("confirm_height {confirm_height} is after tip {tip_height}"),
            )
        })
}

pub fn csv_depth_is_mature(depth: u32, csv_blocks: u32, safety_margin: u32) -> bool {
    match csv_blocks.checked_add(safety_margin) {
        Some(need) => depth >= need,
        None => false,
    }
}

pub fn wall_clock_deadline_unix(
    t_confirm_unix: u64,
    csv_blocks: u32,
    safety_margin: u32,
) -> PolicyResult<u64> {
    let blocks = csv_blocks.checked_add(safety_margin).ok_or_else(|| {
        PolicyError::new(
            PolicyErrorCode::CsvImmatureWallclock,
            "csv_blocks + safety_margin overflow",
        )
    })?;
    let delta = u64::from(blocks)
        .checked_mul(WALL_CLOCK_SECONDS_PER_BLOCK)
        .ok_or_else(|| {
            PolicyError::new(
                PolicyErrorCode::CsvImmatureWallclock,
                "wall-clock duration overflow",
            )
        })?;
    t_confirm_unix.checked_add(delta).ok_or_else(|| {
        PolicyError::new(
            PolicyErrorCode::CsvImmatureWallclock,
            "wall-clock deadline overflow",
        )
    })
}

pub fn wall_clock_is_mature(
    now_unix: u64,
    t_confirm_unix: u64,
    csv_blocks: u32,
    safety_margin: u32,
) -> PolicyResult<bool> {
    let deadline = wall_clock_deadline_unix(t_confirm_unix, csv_blocks, safety_margin)?;
    Ok(now_unix >= deadline)
}

/// Both depth and wall-clock must pass `(csv_blocks + safety_margin)` units.
pub fn check_csv_maturity(
    tip_height: u32,
    confirm_height: u32,
    now_unix: u64,
    t_confirm_unix: u64,
    csv_blocks: u32,
    safety_margin: u32,
) -> PolicyResult<()> {
    let depth = csv_depth(tip_height, confirm_height)?;
    if !csv_depth_is_mature(depth, csv_blocks, safety_margin) {
        return Err(PolicyError::new(
            PolicyErrorCode::CsvImmatureDepth,
            format!("depth {depth} < csv {csv_blocks} + margin {safety_margin}"),
        ));
    }
    if !wall_clock_is_mature(now_unix, t_confirm_unix, csv_blocks, safety_margin)? {
        return Err(PolicyError::new(
            PolicyErrorCode::CsvImmatureWallclock,
            format!(
                "now {now_unix} < t_confirm {t_confirm_unix} + (csv {csv_blocks} + margin {safety_margin}) * {WALL_CLOCK_SECONDS_PER_BLOCK}"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{CSV_BLOCKS_DEFAULT, SAFETY_MARGIN_BLOCKS};

    const CSV: u32 = CSV_BLOCKS_DEFAULT;
    const MARGIN: u32 = SAFETY_MARGIN_BLOCKS;
    const NEED_DEPTH: u32 = CSV + MARGIN; // 5328
    const NEED_SECS: u64 = (CSV as u64 + MARGIN as u64) * WALL_CLOCK_SECONDS_PER_BLOCK; // 3_196_800

    #[test]
    fn depth_off_by_one() {
        assert_eq!(csv_depth(100, 100).unwrap(), 1);
        assert_eq!(csv_depth(100, 99).unwrap(), 2);
        assert!(csv_depth(100, 101).is_err());

        assert!(!csv_depth_is_mature(NEED_DEPTH - 1, CSV, MARGIN));
        assert!(csv_depth_is_mature(NEED_DEPTH, CSV, MARGIN));
        assert!(csv_depth_is_mature(NEED_DEPTH + 1, CSV, MARGIN));
    }

    #[test]
    fn wall_clock_off_by_one() {
        let t0 = 1_700_000_000_u64;
        assert!(!wall_clock_is_mature(t0 + NEED_SECS - 1, t0, CSV, MARGIN).unwrap());
        assert!(wall_clock_is_mature(t0 + NEED_SECS, t0, CSV, MARGIN).unwrap());
        assert!(wall_clock_is_mature(t0 + NEED_SECS + 1, t0, CSV, MARGIN).unwrap());
    }

    #[test]
    fn depth_ok_wall_clock_fail() {
        // Fast fake blocks: depth includes margin, wall-clock still short of 37d.
        let confirm_height = 1;
        let tip = confirm_height + NEED_DEPTH - 1; // depth == 5328
        let t_confirm = 1_700_000_000_u64;
        let now = t_confirm + NEED_SECS - 1;
        let err = check_csv_maturity(tip, confirm_height, now, t_confirm, CSV, MARGIN).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::CsvImmatureWallclock);
        assert!(csv_depth_is_mature(
            csv_depth(tip, confirm_height).unwrap(),
            CSV,
            MARGIN
        ));
    }

    #[test]
    fn wall_clock_ok_depth_fail() {
        // Slow real chain: 37d+ wall-clock elapsed, depth one short of csv+margin.
        let confirm_height = 10;
        let tip = confirm_height + (NEED_DEPTH - 1) - 1; // depth == 5327
        let t_confirm = 1_700_000_000_u64;
        let now = t_confirm + NEED_SECS + 86_400;
        let err = check_csv_maturity(tip, confirm_height, now, t_confirm, CSV, MARGIN).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::CsvImmatureDepth);
        assert!(wall_clock_is_mature(now, t_confirm, CSV, MARGIN).unwrap());
    }

    #[test]
    fn both_ok_at_exact_thresholds() {
        let confirm_height = 50;
        let tip = confirm_height + NEED_DEPTH - 1;
        let t_confirm = 1_800_000_000_u64;
        let now = t_confirm + NEED_SECS;
        check_csv_maturity(tip, confirm_height, now, t_confirm, CSV, MARGIN).unwrap();
    }

    #[test]
    fn thirty_seven_day_ux_bound() {
        let seconds = (u64::from(CSV) + u64::from(MARGIN)) * WALL_CLOCK_SECONDS_PER_BLOCK;
        assert_eq!(seconds, 3_196_800);
        assert_eq!(seconds / 86_400, 37);
        assert_eq!(NEED_SECS, 3_196_800);
        assert_eq!(wall_clock_deadline_unix(0, CSV, MARGIN).unwrap(), 3_196_800);
    }
}
