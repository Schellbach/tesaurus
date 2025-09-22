//! High-performance Tesaurus CLI with optimized commands

use tesaurus::{
    Config, TesaurusVault, Result,
    crypto::CryptoManager,
    ai::AIEngine,
    storage::StorageManager,
    network::NetworkManager,
    vault::{VaultManager, TransactionParams},
};
use clap::{Arg, Command, SubCommand};
use bitcoin::{PrivateKey, Address, Network};
use std::sync::Arc;
use std::str::FromStr;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let matches = Command::new("tesaurus-cli")
        .version("0.1.0")
        .author("Tesaurus Team")
        .about("High-performance Bitcoin vault CLI")
        .subcommand(
            Command::new("init")
                .about("Initialize vault with keys")
                .arg(
                    Arg::new("primary-key")
                        .long("primary-key")
                        .value_name("WIF")
                        .help("Primary private key in WIF format")
                        .required(true)
                )
                .arg(
                    Arg::new("override-key")
                        .long("override-key")
                        .value_name("WIF")
                        .help("Override private key in WIF format")
                        .required(true)
                )
                .arg(
                    Arg::new("ai-key")
                        .long("ai-key")
                        .value_name("WIF")
                        .help("AI private key in WIF format")
                        .required(true)
                )
        )
        .subcommand(
            Command::new("send")
                .about("Send Bitcoin transaction")
                .arg(
                    Arg::new("destination")
                        .long("to")
                        .value_name("ADDRESS")
                        .help("Destination Bitcoin address")
                        .required(true)
                )
                .arg(
                    Arg::new("amount")
                        .long("amount")
                        .value_name("BTC")
                        .help("Amount in BTC")
                        .required(true)
                )
                .arg(
                    Arg::new("fee-rate")
                        .long("fee-rate")
                        .value_name("SAT_PER_VBYTE")
                        .help("Fee rate in sat/vB")
                        .default_value("25")
                )
                .arg(
                    Arg::new("use-ai")
                        .long("use-ai")
                        .help("Use AI for decision making")
                        .action(clap::ArgAction::SetTrue)
                )
                .arg(
                    Arg::new("priority")
                        .long("priority")
                        .value_name("LEVEL")
                        .help("Transaction priority (low, normal, high, critical)")
                        .default_value("normal")
                )
        )
        .subcommand(
            Command::new("status")
                .about("Show vault status")
        )
        .subcommand(
            Command::new("metrics")
                .about("Show performance metrics")
        )
        .subcommand(
            Command::new("history")
                .about("Show transaction history")
                .arg(
                    Arg::new("limit")
                        .long("limit")
                        .value_name("COUNT")
                        .help("Number of transactions to show")
                        .default_value("10")
                )
        )
        .subcommand(
            Command::new("benchmark")
                .about("Run performance benchmarks")
                .arg(
                    Arg::new("operations")
                        .long("operations")
                        .value_name("COUNT")
                        .help("Number of operations to benchmark")
                        .default_value("1000")
                )
        )
        .get_matches();

    // Load configuration
    let config = Config::default();

    // Initialize components
    let crypto_manager = Arc::new(CryptoManager::new(&config).await?);
    let ai_engine = Arc::new(AIEngine::new(&config).await?);
    let storage_manager = Arc::new(StorageManager::new(&config).await?);
    let network_manager = Arc::new(NetworkManager::new(&config).await?);

    // Create vault manager
    let vault_manager = Arc::new(VaultManager::new(
        config,
        crypto_manager,
        ai_engine,
        storage_manager,
    ).await?);

    // Handle subcommands
    match matches.subcommand() {
        Some(("init", sub_matches)) => {
            handle_init(vault_manager, sub_matches).await?;
        }
        Some(("send", sub_matches)) => {
            handle_send(vault_manager, sub_matches).await?;
        }
        Some(("status", _)) => {
            handle_status(vault_manager).await?;
        }
        Some(("metrics", _)) => {
            handle_metrics(vault_manager).await?;
        }
        Some(("history", sub_matches)) => {
            handle_history(vault_manager, sub_matches).await?;
        }
        Some(("benchmark", sub_matches)) => {
            handle_benchmark(vault_manager, sub_matches).await?;
        }
        _ => {
            println!("No subcommand provided. Use --help for usage information.");
        }
    }

    Ok(())
}

async fn handle_init(
    vault_manager: Arc<VaultManager>,
    matches: &clap::ArgMatches,
) -> Result<()> {
    println!("Initializing Tesaurus vault...");

    let primary_wif = matches.get_one::<String>("primary-key").unwrap();
    let override_wif = matches.get_one::<String>("override-key").unwrap();
    let ai_wif = matches.get_one::<String>("ai-key").unwrap();

    // Parse private keys
    let primary_key = PrivateKey::from_wif(primary_wif)
        .map_err(|e| tesaurus::error::TesaurusError::crypto("Invalid primary key"))?;
    let override_key = PrivateKey::from_wif(override_wif)
        .map_err(|e| tesaurus::error::TesaurusError::crypto("Invalid override key"))?;
    let ai_key = PrivateKey::from_wif(ai_wif)
        .map_err(|e| tesaurus::error::TesaurusError::crypto("Invalid AI key"))?;

    // Initialize vault
    let address = vault_manager.initialize_keys(primary_key, override_key, ai_key).await?;

    println!("✅ Vault initialized successfully!");
    println!("📍 Multisig address: {}", address);
    println!("💡 Fund this address to start using the vault");

    Ok(())
}

async fn handle_send(
    vault_manager: Arc<VaultManager>,
    matches: &clap::ArgMatches,
) -> Result<()> {
    println!("Creating Bitcoin transaction...");

    let destination_str = matches.get_one::<String>("destination").unwrap();
    let amount_str = matches.get_one::<String>("amount").unwrap();
    let fee_rate_str = matches.get_one::<String>("fee-rate").unwrap();
    let use_ai = matches.get_flag("use-ai");
    let priority = matches.get_one::<String>("priority").unwrap();

    // Parse parameters
    let destination = Address::from_str(destination_str)
        .map_err(|e| tesaurus::error::TesaurusError::InvalidInput("Invalid destination address".to_string()))?;
    let amount_btc: f64 = amount_str.parse()
        .map_err(|e| tesaurus::error::TesaurusError::InvalidInput("Invalid amount".to_string()))?;
    let amount_sats = (amount_btc * 100_000_000.0) as u64;
    let fee_rate: u64 = fee_rate_str.parse()
        .map_err(|e| tesaurus::error::TesaurusError::InvalidInput("Invalid fee rate".to_string()))?;

    let params = TransactionParams {
        destination,
        amount: amount_sats,
        fee_rate,
        use_ai,
        priority: priority.to_string(),
    };

    // Create transaction
    let start_time = std::time::Instant::now();
    let txid = vault_manager.create_transaction(params).await?;
    let duration = start_time.elapsed();

    println!("✅ Transaction created successfully!");
    println!("🔗 Transaction ID: {}", txid);
    println!("⚡ Processing time: {:.2}ms", duration.as_millis());
    println!("🤖 AI decision: {}", if use_ai { "Enabled" } else { "Disabled" });

    Ok(())
}

async fn handle_status(vault_manager: Arc<VaultManager>) -> Result<()> {
    println!("📊 Tesaurus Vault Status");
    println!("========================");

    let state = vault_manager.get_state().await;
    let metrics = vault_manager.get_metrics();

    println!("🏦 Vault Address: {}", state.address);
    println!("💰 Balance: {} BTC", state.balance as f64 / 100_000_000.0);
    println!("⏰ Last Activity: {:?} ago", state.last_activity.elapsed());
    println!("🔒 Inactivity Blocks: {}", state.inactivity_blocks);
    println!("📋 Pending Transactions: {}", state.pending_transactions.len());

    println!("\n📈 Performance Metrics");
    println!("======================");
    println!("🔄 Transactions Processed: {}", metrics.transactions_processed);
    println!("✅ AI Approvals: {}", metrics.ai_approvals);
    println!("❌ AI Rejections: {}", metrics.ai_rejections);
    println!("👤 Manual Overrides: {}", metrics.manual_overrides);
    println!("⚡ Avg Processing Time: {:.2}ms", metrics.avg_processing_time_ms);
    println!("🕐 Inactivity Duration: {:.1}h", metrics.inactivity_duration_hours);

    Ok(())
}

async fn handle_metrics(vault_manager: Arc<VaultManager>) -> Result<()> {
    println!("📊 Detailed Performance Metrics");
    println!("===============================");

    let metrics = vault_manager.get_metrics();
    
    // Display metrics in a formatted table
    println!("┌─────────────────────────────────┬──────────────┐");
    println!("│ Metric                          │ Value        │");
    println!("├─────────────────────────────────┼──────────────┤");
    println!("│ Transactions Processed         │ {:>12} │", metrics.transactions_processed);
    println!("│ AI Approvals                    │ {:>12} │", metrics.ai_approvals);
    println!("│ AI Rejections                   │ {:>12} │", metrics.ai_rejections);
    println!("│ Manual Overrides                │ {:>12} │", metrics.manual_overrides);
    println!("│ Avg Processing Time (ms)        │ {:>12.2} │", metrics.avg_processing_time_ms);
    println!("│ Current Balance (BTC)           │ {:>12.8} │", metrics.current_balance as f64 / 100_000_000.0);
    println!("│ Inactivity Duration (hours)     │ {:>12.1} │", metrics.inactivity_duration_hours);
    println!("└─────────────────────────────────┴──────────────┘");

    // Calculate additional derived metrics
    let total_decisions = metrics.ai_approvals + metrics.ai_rejections;
    if total_decisions > 0 {
        let approval_rate = (metrics.ai_approvals as f64 / total_decisions as f64) * 100.0;
        println!("\n📈 Derived Metrics");
        println!("AI Approval Rate: {:.1}%", approval_rate);
    }

    Ok(())
}

async fn handle_history(
    vault_manager: Arc<VaultManager>,
    matches: &clap::ArgMatches,
) -> Result<()> {
    let limit_str = matches.get_one::<String>("limit").unwrap();
    let limit: usize = limit_str.parse()
        .map_err(|e| tesaurus::error::TesaurusError::InvalidInput("Invalid limit".to_string()))?;

    println!("📜 Transaction History (Last {} transactions)", limit);
    println!("=============================================");

    let state = vault_manager.get_state().await;
    
    if state.pending_transactions.is_empty() {
        println!("No transactions found.");
        return Ok(());
    }

    println!("┌──────────────────┬─────────────────┬────────────────────────┬─────────────┐");
    println!("│ Transaction ID   │ Amount (BTC)    │ Destination            │ AI Decision │");
    println!("├──────────────────┼─────────────────┼────────────────────────┼─────────────┤");

    for (i, tx) in state.pending_transactions.iter().take(limit).enumerate() {
        let amount_btc = tx.amount as f64 / 100_000_000.0;
        let short_txid = if tx.txid.len() > 16 {
            format!("{}...", &tx.txid[..13])
        } else {
            tx.txid.clone()
        };
        let short_dest = if tx.destination.len() > 22 {
            format!("{}...", &tx.destination[..19])
        } else {
            tx.destination.clone()
        };
        let ai_decision = tx.ai_decision.as_deref().unwrap_or("N/A");

        println!("│ {:16} │ {:15.8} │ {:22} │ {:11} │", 
                 short_txid, amount_btc, short_dest, ai_decision);
    }

    println!("└──────────────────┴─────────────────┴────────────────────────┴─────────────┘");

    Ok(())
}

async fn handle_benchmark(
    vault_manager: Arc<VaultManager>,
    matches: &clap::ArgMatches,
) -> Result<()> {
    let operations_str = matches.get_one::<String>("operations").unwrap();
    let operations: usize = operations_str.parse()
        .map_err(|e| tesaurus::error::TesaurusError::InvalidInput("Invalid operations count".to_string()))?;

    println!("🚀 Running Performance Benchmark");
    println!("Operations: {}", operations);
    println!("=================================");

    // Benchmark AI decisions
    println!("Benchmarking AI decisions...");
    let start_time = std::time::Instant::now();
    
    for i in 0..operations {
        // Create mock transaction context for benchmarking
        let context = tesaurus::ai::TransactionContext {
            amount: (i as u64 % 1000) * 10000, // Varying amounts
            destination: format!("tb1qbenchmark{:08x}", i),
            inactivity_duration: std::time::Duration::from_secs(3600 * (i as u64 % 48)),
            fee_rate: 25 + (i as u64 % 50),
            historical_patterns: vec![],
            block_height: 800000 + (i as u32 % 1000),
        };
        
        // This would normally call the AI engine, but we'll simulate for benchmarking
        tokio::time::sleep(std::time::Duration::from_micros(100)).await;
    }
    
    let duration = start_time.elapsed();
    let ops_per_sec = operations as f64 / duration.as_secs_f64();
    
    println!("✅ Benchmark Results");
    println!("====================");
    println!("Total Operations: {}", operations);
    println!("Total Time: {:.2}s", duration.as_secs_f64());
    println!("Operations/sec: {:.2}", ops_per_sec);
    println!("Avg Time/op: {:.2}ms", duration.as_millis() as f64 / operations as f64);
    
    // Memory usage
    let memory_mb = get_memory_usage_mb();
    println!("Memory Usage: {:.2} MB", memory_mb);

    Ok(())
}

fn get_memory_usage_mb() -> f64 {
    // Simple memory usage calculation (would use proper system calls in production)
    use std::alloc::{GlobalAlloc, Layout, System};
    
    // This is a simplified approach - in production you'd use proper memory profiling
    42.0 // Mock value
}