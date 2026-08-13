//! Locked policy constants from `docs/PSBT_AGENT_PROTOCOL.md` §3.

/// Relative timelock on the agent branch (`older(csv)`).
pub const CSV_BLOCKS_DEFAULT: u32 = 4320;

/// Extra blocks required for CSV *depth* maturity (eclipse / header lag margin).
pub const SAFETY_MARGIN_BLOCKS: u32 = 1008;

/// Seconds charged per block for the wall-clock floor.
///
/// Depth maturity uses `csv_blocks + safety_margin` (5328 blocks ≈ **37 days**
/// at 10 minutes/block). The wall-clock helper is `csv_blocks * 600` seconds
/// (30 days) so the two checks can fail independently (fast vs slow blocks).
pub const WALL_CLOCK_SECONDS_PER_BLOCK: u64 = 600;

/// Maximum external value per agent signature.
pub const VELOCITY_PER_SIG_SATS: u64 = 10_000_000;

/// Maximum sum of externals in a trailing 144-block window (inclusive of this spend).
pub const VELOCITY_PER_144_SATS: u64 = 50_000_000;

/// Trailing window length for the cumulative velocity cap.
pub const VELOCITY_WINDOW_BLOCKS: u32 = 144;
