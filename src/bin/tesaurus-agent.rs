//! Tesaurus agent co-signer daemon.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tesaurus::agent::run_agent_server;
use tesaurus::config::Config;

#[derive(Parser, Debug)]
#[command(name = "tesaurus-agent", version, about = "Local agent recovery co-signer")]
struct Cli {
    #[arg(short, long, default_value = "config/tesaurus.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let cfg = Config::load(&cli.config).context("load config")?;
    run_agent_server(cfg).await?;
    Ok(())
}
