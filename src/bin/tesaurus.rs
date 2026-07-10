//! Tesaurus CLI — vault lifecycle, sync, and spends.

use anyhow::{bail, Context, Result};
use bitcoin::Network;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tesaurus::config::Config;
use tesaurus::descriptor::VaultDescriptor;
use tesaurus::keys::{generate_vault_keys, load_key, KeyRole};
use tesaurus::rpc::BitcoinRpc;
use tesaurus::spend::{broadcast, SpendBuilder, SpendPath, SpendRequest};
use tesaurus::wallet::{VaultState, VaultWallet};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "tesaurus", version, about = "Sovereign Bitcoin vault with agent recovery")]
struct Cli {
    /// Path to tesaurus.toml
    #[arg(short, long, global = true, default_value = "config/tesaurus.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Write an example config file
    InitConfig {
        #[arg(long, default_value = "config/tesaurus.toml")]
        path: PathBuf,
        #[arg(long, default_value = "testnet")]
        network: String,
        #[arg(long)]
        force: bool,
    },
    /// Generate primary / override / agent WIF keys
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Create vault descriptor + state from existing keys
    InitVault {
        #[arg(long)]
        force: bool,
    },
    /// Show receive address and descriptor
    Address,
    /// Import watch-only descriptor into Bitcoin Core
    ImportWatch,
    /// Show balances / UTXOs
    Status,
    /// Create, sign, and optionally broadcast a spend
    Spend {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_sats: u64,
        #[arg(long, default_value_t = 500)]
        fee_sats: u64,
        #[arg(long, value_enum, default_value_t = PathArg::Primary)]
        path: PathArg,
        #[arg(long)]
        broadcast: bool,
        /// Ask local agent to co-sign (recovery path)
        #[arg(long)]
        via_agent: bool,
    },
}

#[derive(Subcommand, Debug)]
enum KeysCmd {
    Generate {
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum PathArg {
    Primary,
    Recovery,
}

impl From<PathArg> for SpendPath {
    fn from(p: PathArg) -> Self {
        match p {
            PathArg::Primary => SpendPath::Primary,
            PathArg::Recovery => SpendPath::Recovery,
        }
    }
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
    match cli.command {
        Commands::InitConfig { path, network, force } => {
            if path.exists() && !force {
                bail!("{} exists (pass --force to overwrite)", path.display());
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, Config::example_toml(&network))?;
            println!("wrote {}", path.display());
        }
        Commands::Keys { cmd } => {
            let cfg = Config::load(&cli.config).context("load config")?;
            let network = cfg.network()?;
            match cmd {
                KeysCmd::Generate { force } => {
                    let pubs = generate_vault_keys(&cfg.vault.keys_dir, network, force)?;
                    println!("generated keys in {}", cfg.vault.keys_dir.display());
                    println!("primary:  {}", pubs.primary);
                    println!("override: {}", pubs.override_key);
                    println!("agent:    {}", pubs.agent);
                    println!("WARNING: back up WIF files offline; loss = loss of funds");
                }
            }
        }
        Commands::InitVault { force } => {
            let cfg = Config::load(&cli.config)?;
            if cfg.vault.state_path.exists() && !force {
                bail!(
                    "{} exists (pass --force to overwrite)",
                    cfg.vault.state_path.display()
                );
            }
            let network = cfg.network()?;
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let primary = load_key(&cfg.vault.keys_dir, KeyRole::Primary)?;
            let override_key = load_key(&cfg.vault.keys_dir, KeyRole::Override)?;
            let agent = load_key(&cfg.vault.keys_dir, KeyRole::Agent)?;
            let vault = VaultDescriptor::build(
                primary.public_key(&secp),
                override_key.public_key(&secp),
                agent.public_key(&secp),
                cfg.vault.csv_blocks,
                network,
            )?;
            let state = VaultState::new(vault.clone());
            state.save(&cfg.vault.state_path)?;
            println!("vault initialized");
            println!("address:    {}", vault.receive_address);
            println!("descriptor: {}", vault.descriptor);
            println!("state:      {}", cfg.vault.state_path.display());
            println!("csv:        {} blocks", vault.csv_blocks);
        }
        Commands::Address => {
            let cfg = Config::load(&cli.config)?;
            let state = VaultState::load(&cfg.vault.state_path)?;
            println!("{}", state.vault.receive_address);
            println!("{}", state.vault.descriptor);
        }
        Commands::ImportWatch => {
            let cfg = Config::load(&cli.config)?;
            let state = VaultState::load(&cfg.vault.state_path)?;
            let rpc = BitcoinRpc::connect(&cfg.bitcoin)?;
            let wallet = VaultWallet::open(state, rpc);
            wallet.import_watch_only()?;
            println!("imported watch-only descriptor into wallet '{}'", cfg.bitcoin.wallet_name);
        }
        Commands::Status => {
            let cfg = Config::load(&cli.config)?;
            let state = VaultState::load(&cfg.vault.state_path)?;
            let rpc = BitcoinRpc::connect(&cfg.bitcoin)?;
            let tip = rpc.block_count()?;
            let wallet = VaultWallet::open(state.clone(), rpc);
            let utxos = wallet.list_utxos()?;
            let balance: u64 = utxos.iter().map(|u| u.txout.value.to_sat()).sum();
            let recoverable: u64 = utxos
                .iter()
                .filter(|u| u.spendable_recovery)
                .map(|u| u.txout.value.to_sat())
                .sum();
            println!("network:     {}", cfg.bitcoin.network);
            println!("tip:         {tip}");
            println!("address:     {}", state.vault.receive_address);
            println!("csv_blocks:  {}", state.vault.csv_blocks);
            println!("balance:     {balance} sats");
            println!("recoverable: {recoverable} sats (CSV mature)");
            println!("utxos:       {}", utxos.len());
            for u in utxos {
                println!(
                    "  {} conf={} primary={} recovery={} value={}",
                    u.outpoint,
                    u.confirmations,
                    u.spendable_primary,
                    u.spendable_recovery,
                    u.txout.value
                );
            }
        }
        Commands::Spend {
            to,
            amount_sats,
            fee_sats,
            path,
            broadcast: do_broadcast,
            via_agent,
        } => {
            let cfg = Config::load(&cli.config)?;
            let network = cfg.network()?;
            let state = VaultState::load(&cfg.vault.state_path)?;
            let rpc = BitcoinRpc::connect(&cfg.bitcoin)?;
            let wallet = VaultWallet::open(state.clone(), rpc);
            let utxos = wallet.list_utxos()?;

            let spend_path = SpendPath::from(path);
            let req = SpendRequest {
                destination: to,
                amount_sats,
                fee_sats,
                path: spend_path,
            };

            let built = if via_agent || spend_path == SpendPath::Recovery {
                spend_via_agent_or_local(&cfg, network, &state, &utxos, &req, via_agent).await?
            } else {
                let primary = load_key(&cfg.vault.keys_dir, KeyRole::Primary)?;
                let override_key = load_key(&cfg.vault.keys_dir, KeyRole::Override)?;
                SpendBuilder::new(&state.vault, network).build_and_sign(
                    &utxos,
                    &req,
                    &[primary, override_key],
                )?
            };

            println!("txid:   {}", built.txid);
            println!("path:   {:?}", built.path);
            println!("fee:    {} sats", built.fee_sats);
            println!("change: {} sats", built.change_sats);
            println!("tx:     {}", built.tx_hex);

            if do_broadcast {
                if built.needs_agent {
                    bail!("transaction still needs agent signature; not broadcasting");
                }
                let rpc = BitcoinRpc::connect(&cfg.bitcoin)?;
                let txid = broadcast(rpc.client(), &built.tx_hex)?;
                println!("broadcast: {txid}");
            }
        }
    }
    Ok(())
}

async fn spend_via_agent_or_local(
    cfg: &Config,
    network: Network,
    state: &VaultState,
    utxos: &[tesaurus::wallet::VaultUtxo],
    req: &SpendRequest,
    via_agent: bool,
) -> Result<tesaurus::spend::BuiltSpend> {
    if via_agent {
        let agent_url = cfg
            .daemon
            .agent_url
            .clone()
            .unwrap_or_else(|| format!("http://{}", cfg.agent.bind));
        return request_agent_sign(cfg, &agent_url, state, utxos, req).await;
    }

    // Local recovery: primary + agent keys on this machine
    let primary = load_key(&cfg.vault.keys_dir, KeyRole::Primary)?;
    let agent = load_key(&cfg.vault.keys_dir, KeyRole::Agent)?;
    Ok(SpendBuilder::new(&state.vault, network).build_and_sign(
        utxos,
        &SpendRequest {
            path: SpendPath::Recovery,
            ..req.clone()
        },
        &[primary, agent],
    )?)
}

async fn request_agent_sign(
    cfg: &Config,
    agent_url: &str,
    state: &VaultState,
    utxos: &[tesaurus::wallet::VaultUtxo],
    req: &SpendRequest,
) -> Result<tesaurus::spend::BuiltSpend> {
    let primary = load_key(&cfg.vault.keys_dir, KeyRole::Primary)?;
    let body = serde_json::json!({
        "vault": state.vault,
        "spend": {
            "destination": req.destination,
            "amount_sats": req.amount_sats,
            "fee_sats": req.fee_sats,
            "path": "recovery",
        },
        "primary_wif": primary.wif(),
        "utxos": utxos.iter().map(|u| serde_json::json!({
            "txid": u.outpoint.txid.to_string(),
            "vout": u.outpoint.vout,
            "amount_sats": u.txout.value.to_sat(),
            "confirmations": u.confirmations,
        })).collect::<Vec<_>>(),
    });

    let url = format!("{}/v1/sign", agent_url.trim_end_matches('/'));
    info!("requesting agent co-sign at {url}");

    let mut req_builder = reqwest::Client::new().post(&url).json(&body);
    if let Some(token) = &cfg.agent.api_token {
        req_builder = req_builder.header("authorization", format!("Bearer {token}"));
    }
    let resp = req_builder.send().await.context("agent HTTP request")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        bail!("agent rejected co-sign ({status}): {text}");
    }
    let signed: tesaurus::agent::SignResponse = resp.json().await.context("agent response")?;
    let total_in: u64 = utxos.iter().map(|u| u.txout.value.to_sat()).sum();
    let change_sats = total_in.saturating_sub(req.amount_sats + signed.fee_sats);
    Ok(tesaurus::spend::BuiltSpend {
        tx_hex: signed.tx_hex,
        txid: signed.txid,
        path: SpendPath::Recovery,
        fee_sats: signed.fee_sats,
        amount_sats: req.amount_sats,
        change_sats,
        needs_agent: false,
        psbt_incomplete_hex: None,
    })
}
