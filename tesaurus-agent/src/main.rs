//! Disabled network co-signer placeholder.
//! Production PSBT-only design: docs/PSBT_AGENT_PROTOCOL.md (not unlocked here).

use anyhow::{bail, Result};
use clap::Parser;

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

fn disabled_message() -> &'static str {
    "tesaurus-agent is disabled: the legacy HTTP protocol could expose primary key material; \
     use only local regtest/testnet signing until a reviewed PSBT-only protocol ships"
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
