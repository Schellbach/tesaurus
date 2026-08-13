//! Tesaurus agent policy helpers (gate 2, in progress).
//!
//! Pure validation and crash-safe replay: **no WIF / key-file I/O**, no RPC, and
//! no network co-signing. `tesaurus-agent` and `--via-agent` remain fail-closed.
//!
//! TODO(gate-2): full PSBT v0 + miniscript descriptor matching, Core B wiring,
//! and D5 fee-bump revalidation per `docs/PSBT_AGENT_PROTOCOL.md` §6 / §8.

pub mod confirm;
pub mod constants;
pub mod csv;
pub mod error;
pub mod replay;
pub mod structure;
pub mod velocity;

pub use confirm::{
    confirm_message, confirm_preimage, confirm_required, genesis_internal_bytes,
    txid_display_bytes, verify_confirm_token, ConfirmBinding, OOB_CONFIRM_SATS,
};
pub use constants::{
    CSV_BLOCKS_DEFAULT, SAFETY_MARGIN_BLOCKS, VELOCITY_PER_144_SATS, VELOCITY_PER_SIG_SATS,
    VELOCITY_WINDOW_BLOCKS, WALL_CLOCK_SECONDS_PER_BLOCK,
};
pub use csv::{
    check_csv_maturity, csv_depth, csv_depth_is_mature, wall_clock_deadline_unix,
    wall_clock_is_mature,
};
pub use error::{PolicyError, PolicyErrorCode, PolicyResult};
pub use replay::{
    outputs_commitment, psbt_content_hash, replay_id, ReplayRecord, ReplayStore, ReplayVerdict,
};
pub use structure::{
    require_all_vault_input_scripts, require_locktime_zero, require_recovery_sequence,
    require_sighash_all,
};
pub use velocity::{check_velocity_per_signature, check_velocity_window, VelocitySample};

#[cfg(test)]
mod isolation_tests {
    use std::fs;
    use std::path::Path;

    #[test]
    fn policy_sources_do_not_name_coordinator_wif_files() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let needles = coordinator_wif_needles();
        walk_assert_no_needles(root, &needles);
    }

    fn coordinator_wif_needles() -> [String; 2] {
        ["primary", "override"].map(|role| format!("{role}.{}", "wif"))
    }

    fn walk_assert_no_needles(path: &Path, needles: &[String; 2]) {
        if path.is_dir() {
            for entry in fs::read_dir(path).expect("read dir") {
                let entry = entry.expect("dir entry");
                let child = entry.path();
                let name = child.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name == "target" {
                    continue;
                }
                walk_assert_no_needles(&child, needles);
            }
            return;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.ends_with(".rs") || name == "Cargo.toml" {
            let text = fs::read_to_string(path).expect("read source");
            for needle in needles {
                assert!(
                    !text.contains(needle),
                    "{} must not mention coordinator key filenames",
                    path.display()
                );
            }
        }
    }
}
