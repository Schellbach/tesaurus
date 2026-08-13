//! Locked policy constants from `docs/PSBT_AGENT_PROTOCOL.md` §3.

/// Relative timelock on the agent branch (`older(csv)`).
pub const CSV_BLOCKS_DEFAULT: u32 = 4320;

/// Extra blocks for CSV depth **and** the wall-clock eclipse bound.
pub const SAFETY_MARGIN_BLOCKS: u32 = 1008;

/// Seconds charged per block for the wall-clock floor.
///
/// Both checks use `csv_blocks + safety_margin` (5328). Depth counts blocks;
/// wall-clock counts `(csv_blocks + safety_margin) * 600` seconds (**37 days**).
/// They still fail independently: fast fake blocks can satisfy depth while
/// wall-clock is short; a slow real chain can satisfy wall-clock first.
pub const WALL_CLOCK_SECONDS_PER_BLOCK: u64 = 600;

/// Maximum external value per agent signature.
pub const VELOCITY_PER_SIG_SATS: u64 = 10_000_000;

/// Maximum sum of externals in a trailing 144-block window (inclusive of this spend).
pub const VELOCITY_PER_144_SATS: u64 = 50_000_000;

/// Trailing window length for the cumulative velocity cap.
pub const VELOCITY_WINDOW_BLOCKS: u32 = 144;

/// Absolute fee cap for agent-path PSBTs (anti-DoS; coordinator may be stricter).
pub const MAX_POLICY_FEE_SATS: u64 = 1_000_000;

/// Maximum inputs on an agent-path PSBT (anti-DoS).
pub const MAX_POLICY_INPUTS: usize = 100;
