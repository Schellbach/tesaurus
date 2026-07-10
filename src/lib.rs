//! Tesaurus - Performance-Optimized Bitcoin Vault
//! 
//! A high-performance Bitcoin vault implementation with agent recovery capabilities.
//! Optimized for minimal latency, efficient memory usage, and fast transaction processing.

pub mod config;
pub mod crypto;
pub mod vault;
pub mod agent;
pub mod storage;
pub mod network;
pub mod metrics;
pub mod error;

use std::sync::Arc;
use tokio::sync::RwLock;
use dashmap::DashMap;

/// Global performance metrics
pub static METRICS: once_cell::sync::Lazy<metrics::Registry> = 
    once_cell::sync::Lazy::new(metrics::Registry::new);

/// High-performance shared state using concurrent data structures
pub type SharedState<T> = Arc<RwLock<T>>;
pub type ConcurrentMap<K, V> = Arc<DashMap<K, V>>;

/// Performance-optimized result type
pub type Result<T> = std::result::Result<T, error::TesaurusError>;

/// Core vault manager with performance optimizations
pub struct TesaurusVault {
    /// Configuration loaded once and cached
    config: Arc<config::Config>,
    /// Crypto operations handler with hardware acceleration when available
    crypto: Arc<crypto::CryptoManager>,
    /// agent decision engine with optimized inference
    agent_engine: Arc<agent::AgentEngine>,
    /// High-performance storage backend
    storage: Arc<storage::StorageManager>,
    /// Network manager with connection pooling
    network: Arc<network::NetworkManager>,
    /// Performance metrics collector
    metrics: Arc<metrics::MetricsCollector>,
    /// In-memory cache for frequently accessed data
    cache: ConcurrentMap<String, Vec<u8>>,
}

impl TesaurusVault {
    /// Create a new vault instance with performance optimizations
    pub async fn new(config: config::Config) -> Result<Self> {
        let config = Arc::new(config);
        
        // Initialize components with performance focus
        let crypto = Arc::new(crypto::CryptoManager::new(&config).await?);
        let agent_engine = Arc::new(agent::AgentEngine::new(&config).await?);
        let storage = Arc::new(storage::StorageManager::new(&config).await?);
        let network = Arc::new(network::NetworkManager::new(&config).await?);
        let metrics = Arc::new(metrics::MetricsCollector::new());
        let cache = Arc::new(DashMap::new());

        Ok(Self {
            config,
            crypto,
            agent_engine,
            storage,
            network,
            metrics,
            cache,
        })
    }

    /// Get cached data or compute if not present
    pub async fn get_or_compute<F, Fut, T>(&self, key: &str, compute: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        // Check cache first
        if let Some(cached) = self.cache.get(key) {
            if let Ok(value) = bincode::deserialize(&cached) {
                return Ok(value);
            }
        }

        // Compute and cache
        let value = compute().await?;
        if let Ok(serialized) = bincode::serialize(&value) {
            self.cache.insert(key.to_string(), serialized);
        }
        
        Ok(value)
    }
}

// Re-export commonly used types for convenience
pub use config::Config;
pub use error::TesaurusError;
pub use vault::{VaultState, Transaction};