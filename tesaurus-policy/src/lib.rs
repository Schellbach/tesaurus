//! Tesaurus agent policy helpers (gate 2, in progress).
//!
//! Pure validation and crash-safe replay: **no WIF / key-file I/O**, no RPC, and
//! no network co-signing. `tesaurus-agent` and `--via-agent` remain fail-closed.
//!
//! Landed here: PSBT v0 parse, `AgentPin` + miniscript descriptor matching, §6
//! stages that take Core B facts as inputs, and §8 D5 fee-bump **policy**.
//!
//! Production [`ChainView`] / [`AgentAuth`] construction is **not** in this crate:
//! `tesaurus-agent` maps Core B RPC into the sealed types via the `agent-tcb`
//! assembler (absent from this crate's tests). There is no public struct-literal
//! and no `ChainView::from_core_b` here that anyone can call with fake facts.
//!
//! Leftover: agent-key signing, transport MAC verification, CI-18, `--via-agent`
//! unlock. Do **not** unlock `--via-agent`. `evaluate` returning
//! `ValidatedUnsigned` is not a co-sign.

pub mod confirm;
pub mod constants;
pub mod csv;
pub mod error;
pub mod evaluate;
pub mod facts;
pub mod pin;
pub mod replay;
pub mod structure;
pub mod velocity;

pub use confirm::{
    confirm_message, confirm_preimage, confirm_required, genesis_internal_bytes,
    txid_display_bytes, verify_confirm_token, ConfirmBinding, OOB_CONFIRM_SATS,
};
pub use constants::{
    CSV_BLOCKS_DEFAULT, MAX_POLICY_FEE_SATS, MAX_POLICY_INPUTS, SAFETY_MARGIN_BLOCKS,
    VELOCITY_PER_144_SATS, VELOCITY_PER_SIG_SATS, VELOCITY_WINDOW_BLOCKS,
    WALL_CLOCK_SECONDS_PER_BLOCK,
};
pub use csv::{
    check_csv_maturity, csv_depth, csv_depth_is_mature, wall_clock_deadline_unix,
    wall_clock_is_mature,
};
pub use error::{PolicyError, PolicyErrorCode, PolicyResult};
pub use evaluate::{
    enforce_fee_bump_policy, evaluate, AmountBreakdown, PolicyOutcome, PolicyRequest,
};
pub use facts::{AgentAuth, ChainView, PrevoutFact};
pub use pin::AgentPin;
pub use replay::{
    is_vault_change_only, outpoints_identical, outputs_commitment, psbt_content_hash, replay_id,
    ReplayPayload, ReplayRecord, ReplayStore, ReplayVerdict,
};
pub use structure::{
    parse_psbt_v0, require_all_vault_input_scripts, require_locktime_zero,
    require_no_unknown_psbt_fields, require_recovery_sequence, require_sighash_all,
    require_sighash_all_on_psbt,
};
pub use velocity::{
    check_velocity_cap, check_velocity_per_signature, check_velocity_window,
    check_velocity_window_capped, VelocitySample,
};

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
