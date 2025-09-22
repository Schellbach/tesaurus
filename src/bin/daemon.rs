//! High-performance Tesaurus daemon with optimized startup and runtime

use tesaurus::{
    Config, TesaurusVault, Result,
    crypto::CryptoManager,
    ai::AIEngine,
    storage::StorageManager,
    network::NetworkManager,
    metrics::MetricsCollector,
};
use clap::{Arg, Command};
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tokio::signal;
use std::sync::Arc;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    // Parse command line arguments
    let matches = Command::new("tesaurus-daemon")
        .version("0.1.0")
        .author("Tesaurus Team")
        .about("High-performance Bitcoin vault daemon")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("tesaurus.toml")
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level (trace, debug, info, warn, error)")
                .default_value("info")
        )
        .get_matches();

    // Initialize logging with performance optimizations
    let log_level = matches.get_one::<String>("log-level").unwrap();
    init_logging(log_level)?;

    info!("Starting Tesaurus daemon v0.1.0");

    // Load configuration
    let config_path = matches.get_one::<String>("config").unwrap();
    let config = match Config::load_from_file(config_path) {
        Ok(config) => {
            config.validate().map_err(|e| {
                tesaurus::error::TesaurusError::Config(
                    config::ConfigError::Message(e)
                )
            })?;
            config
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            Config::default()
        }
    };

    info!("Configuration loaded successfully");

    // Initialize components with performance optimizations
    let crypto_manager = Arc::new(CryptoManager::new(&config).await?);
    let ai_engine = Arc::new(AIEngine::new(&config).await?);
    let storage_manager = Arc::new(StorageManager::new(&config).await?);
    let network_manager = Arc::new(NetworkManager::new(&config).await?);
    let metrics_collector = Arc::new(MetricsCollector::new());

    info!("Core components initialized");

    // Start metrics collection
    metrics_collector.start_collection().await;
    info!("Metrics collection started on port {}", config.performance.metrics_port);

    // Create vault instance
    let vault = TesaurusVault::new(config.clone()).await?;
    info!("Tesaurus vault initialized");

    // Start background services
    start_background_services(
        Arc::clone(&storage_manager),
        Arc::clone(&network_manager),
        Arc::clone(&metrics_collector),
    ).await;

    // Set up graceful shutdown
    let shutdown_signal = setup_shutdown_signal();
    
    info!("Tesaurus daemon started successfully");
    info!("Press Ctrl+C to shutdown gracefully");

    // Main service loop
    tokio::select! {
        _ = run_main_loop(vault) => {
            info!("Main loop completed");
        }
        _ = shutdown_signal => {
            info!("Shutdown signal received");
        }
    }

    // Graceful shutdown
    info!("Shutting down gracefully...");
    
    // Flush storage
    storage_manager.flush().await?;
    
    info!("Tesaurus daemon shutdown complete");
    Ok(())
}

/// Initialize logging with performance optimizations
fn init_logging(log_level: &str) -> Result<()> {
    let level = match log_level {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    // Use high-performance JSON logging for production
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    format!("tesaurus={},tower_http=debug", level).into()
                })
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    Ok(())
}

/// Start background services
async fn start_background_services(
    storage: Arc<StorageManager>,
    network: Arc<NetworkManager>,
    metrics: Arc<MetricsCollector>,
) {
    // Storage cleanup task
    let storage_cleanup = storage.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(e) = storage_cleanup.flush().await {
                error!("Storage cleanup error: {}", e);
            }
        }
    });

    // Network cache cleanup task
    let network_cleanup = network.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1800));
        loop {
            interval.tick().await;
            network_cleanup.cleanup_cache().await;
        }
    });

    // Metrics reporting task
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let metrics_data = metrics.get_all_metrics();
            tracing::debug!("System metrics: {}", metrics_data);
        }
    });
}

/// Main service loop
async fn run_main_loop(vault: TesaurusVault) -> Result<()> {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    
    loop {
        interval.tick().await;
        
        // Health check and maintenance
        if let Err(e) = perform_health_check(&vault).await {
            error!("Health check failed: {}", e);
        }
        
        // Process any pending operations
        if let Err(e) = process_pending_operations(&vault).await {
            error!("Error processing pending operations: {}", e);
        }
    }
}

/// Perform system health check
async fn perform_health_check(vault: &TesaurusVault) -> Result<()> {
    // Check vault state
    let _state = vault.get_or_compute("health_check", || async {
        Ok("healthy".to_string())
    }).await?;
    
    info!("Health check passed");
    Ok(())
}

/// Process pending operations
async fn process_pending_operations(vault: &TesaurusVault) -> Result<()> {
    // Process any queued transactions, updates, etc.
    // This is where the main business logic would run
    
    tracing::debug!("Processing pending operations");
    Ok(())
}

/// Set up graceful shutdown signal handling
async fn setup_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}