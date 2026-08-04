//! Tesaurus CLI — vault lifecycle, sync, and spends.

use anyhow::{bail, Context, Result};
use bitcoin::Network;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tesaurus::config::Config;
use tesaurus::descriptor::VaultDescriptor;
use tesaurus::keys::{generate_vault_keys, load_key, KeyRole};
use tesaurus::rpc::BitcoinRpc;
use tesaurus::spend::{broadcast, validate_built_spend, SpendBuilder, SpendPath, SpendRequest};
use tesaurus::wallet::{VaultState, VaultWallet};

#[derive(Parser, Debug)]
#[command(
    name = "tesaurus",
    version,
    about = "Experimental Bitcoin vault research (mainnet and network co-signing disabled)"
)]
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
        /// Print signed transaction hex (may reveal payment metadata)
        #[arg(long)]
        show_transaction: bool,
        /// Disabled until the agent uses a reviewed PSBT-only protocol
        #[arg(long)]
        via_agent: bool,
    },
}

#[derive(Subcommand, Debug)]
enum KeysCmd {
    Generate,
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::InitConfig {
            path,
            network,
            force,
        } => {
            let contents = Config::example_toml(&network)?;
            write_private_file(&path, &contents, force)?;
            println!("wrote {}", path.display());
        }
        Commands::Keys { cmd } => {
            let cfg = Config::load(&cli.config).context("load config")?;
            let network = cfg.network()?;
            match cmd {
                KeysCmd::Generate => {
                    let pubs = generate_vault_keys(&cfg.vault.keys_dir, network)?;
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
            let network = cfg.network()?;
            let state = load_state(&cfg, network)?;
            println!("{}", state.vault.receive_address);
            println!("{}", state.vault.descriptor);
        }
        Commands::ImportWatch => {
            let cfg = Config::load(&cli.config)?;
            let network = cfg.network()?;
            let state = load_state(&cfg, network)?;
            let rpc = BitcoinRpc::connect(&cfg.bitcoin)?;
            let wallet = VaultWallet::open(state, rpc);
            wallet.import_watch_only()?;
            println!(
                "imported watch-only descriptor into wallet '{}'",
                cfg.bitcoin.wallet_name
            );
        }
        Commands::Status => {
            let cfg = Config::load(&cli.config)?;
            let network = cfg.network()?;
            let state = load_state(&cfg, network)?;
            let rpc = BitcoinRpc::connect(&cfg.bitcoin)?;
            let tip = rpc.block_count()?;
            let wallet = VaultWallet::open(state.clone(), rpc);
            let utxos = wallet.list_utxos()?;
            let balance = utxos.iter().try_fold(0u64, |total, utxo| {
                total
                    .checked_add(utxo.txout.value.to_sat())
                    .context("wallet balance overflows u64")
            })?;
            let recoverable =
                utxos
                    .iter()
                    .filter(|u| u.spendable_recovery)
                    .try_fold(0u64, |total, utxo| {
                        total
                            .checked_add(utxo.txout.value.to_sat())
                            .context("recoverable balance overflows u64")
                    })?;
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
            show_transaction,
            via_agent,
        } => {
            ensure_network_agent_disabled(via_agent)?;
            let cfg = Config::load(&cli.config)?;
            let network = cfg.network()?;
            let state = load_state(&cfg, network)?;
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

            let built = if spend_path == SpendPath::Recovery {
                spend_local_recovery(&cfg, network, &state, &utxos, &req)?
            } else {
                let primary = load_key(&cfg.vault.keys_dir, KeyRole::Primary)?;
                let override_key = load_key(&cfg.vault.keys_dir, KeyRole::Override)?;
                SpendBuilder::new(&state.vault, network).build_and_sign(
                    &utxos,
                    &req,
                    &[primary, override_key],
                )?
            };
            let tx = validate_built_spend(&built, &state.vault, network, &utxos, &req)?;

            println!("txid:   {}", built.txid);
            println!("path:   {:?}", built.path);
            println!("fee:    {} sats", built.fee_sats);
            println!("change: {} sats", built.change_sats);
            if show_transaction {
                println!("tx:     {}", built.tx_hex);
            } else {
                println!("tx:     [hidden; pass --show-transaction to print signed hex]");
            }

            if do_broadcast {
                let rpc = BitcoinRpc::connect(&cfg.bitcoin)?;
                let txid = broadcast(rpc.client(), &tx)?;
                println!("broadcast: {txid}");
            }
        }
    }
    Ok(())
}

fn ensure_network_agent_disabled(via_agent: bool) -> Result<()> {
    if via_agent {
        bail!(
            "--via-agent is disabled: the legacy HTTP flow exposed primary key material; \
             use local regtest/testnet recovery until a reviewed PSBT-only protocol ships"
        );
    }
    Ok(())
}

fn load_state(cfg: &Config, network: Network) -> Result<VaultState> {
    let state = VaultState::load(&cfg.vault.state_path)?;
    state.vault.require_network(network)?;
    Ok(state)
}

fn spend_local_recovery(
    cfg: &Config,
    network: Network,
    state: &VaultState,
    utxos: &[tesaurus::wallet::VaultUtxo],
    req: &SpendRequest,
) -> Result<tesaurus::spend::BuiltSpend> {
    // Research-only local recovery: both required keys stay in this process.
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

fn write_private_file(path: &std::path::Path, contents: &str, overwrite: bool) -> Result<()> {
    if path.exists() && !overwrite {
        bail!("{} exists (pass --force to overwrite)", path.display());
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            bail!(
                "refusing to write configuration through symlink {}",
                path.display()
            );
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut options = std::fs::OpenOptions::new();
        options.write(true).mode(0o600);
        if overwrite {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        let mut file = options.open(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        if overwrite {
            std::fs::write(path, contents)?;
        } else {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_agent_is_fail_closed() {
        ensure_network_agent_disabled(false).unwrap();
        let err = ensure_network_agent_disabled(true).unwrap_err().to_string();
        assert!(err.contains("--via-agent is disabled"));
        assert!(err.contains("PSBT-only"));
    }
}
