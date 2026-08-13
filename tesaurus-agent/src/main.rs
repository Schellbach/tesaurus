//! Disabled network co-signer placeholder.
//! Production PSBT-only design: docs/PSBT_AGENT_PROTOCOL.md (not unlocked here).
//!
//! The agent library can assemble a Core B `ChainView`; this binary still exits
//! non-zero and does not listen or sign.

use anyhow::{bail, Result};
use clap::Parser;
use tesaurus_agent::disabled_message;

#[derive(Parser, Debug)]
#[command(
    name = "tesaurus-agent",
    version,
    about = "Disabled pending a reviewed PSBT-only co-signing protocol"
)]
struct Cli {}

fn main() -> Result<()> {
    let _ = Cli::parse();
    bail!("{}", disabled_message())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tesaurus_policy::PolicyErrorCode;

    #[test]
    fn explains_fail_closed_state() {
        assert!(disabled_message().contains("disabled"));
        assert!(disabled_message().contains("PSBT-only"));
    }

    #[test]
    fn agent_package_can_use_policy_without_wif_loaders() {
        assert!(PolicyErrorCode::ALL
            .iter()
            .any(|c| c.as_str() == "REPLAY_CONFLICT"));
        assert!(PolicyErrorCode::ALL
            .iter()
            .any(|c| c.as_str() == "CONFIRM_REQUIRED"));
    }

    #[test]
    fn agent_sources_do_not_mention_coordinator_wif_files() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let needles = ["primary", "override"].map(|role| format!("{role}.{}", "wif"));
        walk_assert_no_needles(root, &needles);
    }

    #[test]
    fn agent_manifest_does_not_depend_on_coordinator_crate() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let text = fs::read_to_string(manifest).expect("read Cargo.toml");
        assert!(
            !text
                .lines()
                .any(|line| line.trim_start().starts_with("tesaurus ")
                    || line.trim_start().starts_with("tesaurus=")),
            "tesaurus-agent must not depend on the tesaurus WIF-loading crate"
        );
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
