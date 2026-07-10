//! Configuration management with performance optimizations

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Bitcoin network configuration
    pub bitcoin: BitcoinConfig,
    /// AI engine configuration
    pub ai: AIConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Network configuration
    pub network: NetworkConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinConfig {
    /// Bitcoin network (testnet, mainnet)
    pub network: String,
    /// RPC endpoint
    pub rpc_url: String,
    /// RPC username
    pub rpc_user: String,
    /// RPC password
    pub rpc_password: String,
    /// Number of confirmations required
    pub confirmations: u32,
    /// Inactivity threshold in blocks
    pub inactivity_blocks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIConfig {
    /// AI model path
    pub model_path: PathBuf,
    /// Inference timeout
    pub inference_timeout: Duration,
    /// Batch size for inference
    pub batch_size: usize,
    /// Number of threads for AI processing
    pub threads: usize,
    /// Enable GPU acceleration if available
    pub use_gpu: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Database path
    pub db_path: PathBuf,
    /// Cache size in MB
    pub cache_size_mb: usize,
    /// Enable compression
    pub compression: bool,
    /// Backup interval in seconds
    pub backup_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// HTTP client timeout
    pub timeout: Duration,
    /// Connection pool size
    pub pool_size: usize,
    /// Keep-alive duration
    pub keep_alive: Duration,
    /// Enable HTTP/2
    pub http2: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Number of worker threads
    pub worker_threads: usize,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Metrics port
    pub metrics_port: u16,
    /// Memory cache size in MB
    pub memory_cache_mb: usize,
    /// Enable SIMD optimizations
    pub enable_simd: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    /// Log file path
    pub file_path: Option<PathBuf>,
    /// Enable structured logging
    pub structured: bool,
    /// Enable performance logging
    pub performance: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bitcoin: BitcoinConfig {
                network: "testnet".to_string(),
                rpc_url: "http://127.0.0.1:18332".to_string(),
                rpc_user: "testuser".to_string(),
                rpc_password: "testpass".to_string(),
                confirmations: 1,
                inactivity_blocks: 10,
            },
            ai: AIConfig {
                model_path: PathBuf::from("./models/tesaurus_ai.bin"),
                inference_timeout: Duration::from_secs(5),
                batch_size: 32,
                threads: num_cpus::get(),
                use_gpu: false,
            },
            storage: StorageConfig {
                db_path: PathBuf::from("./data/tesaurus.db"),
                cache_size_mb: 256,
                compression: true,
                backup_interval: 3600, // 1 hour
            },
            network: NetworkConfig {
                timeout: Duration::from_secs(30),
                pool_size: 10,
                keep_alive: Duration::from_secs(90),
                http2: true,
            },
            performance: PerformanceConfig {
                worker_threads: num_cpus::get(),
                enable_metrics: true,
                metrics_port: 9090,
                memory_cache_mb: 128,
                enable_simd: true,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_path: Some(PathBuf::from("./logs/tesaurus.log")),
                structured: true,
                performance: true,
            },
        }
    }
}

impl Config {
    /// Load configuration from file with performance optimizations
    pub fn load_from_file(path: &str) -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name(path))
            .add_source(config::Environment::with_prefix("TESAURUS"))
            .build()?;
        
        settings.try_deserialize()
    }
    
    /// Validate configuration for performance issues
    pub fn validate(&self) -> Result<(), String> {
        if self.performance.worker_threads == 0 {
            return Err("Worker threads must be greater than 0".to_string());
        }
        
        if self.storage.cache_size_mb == 0 {
            return Err("Cache size must be greater than 0".to_string());
        }
        
        if self.ai.batch_size == 0 {
            return Err("AI batch size must be greater than 0".to_string());
        }
        
        Ok(())
    }
}