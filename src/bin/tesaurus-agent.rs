//! Disabled network co-signer placeholder.

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

    #[test]
    fn explains_fail_closed_state() {
        assert!(disabled_message().contains("disabled"));
        assert!(disabled_message().contains("PSBT-only"));
    }
}
