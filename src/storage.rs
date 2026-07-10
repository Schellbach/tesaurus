//! High-performance storage backend with caching and optimization

use crate::{config::Config, error::TesaurusError, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use parking_lot::Mutex;
use dashmap::DashMap;
use std::time::{Duration, Instant};
use std::path::PathBuf;

/// Storage manager with multiple backends and caching
pub struct StorageManager {
    /// Configuration
    config: Arc<Config>,
    /// Embedded key-value store for high-performance operations
    kv_store: Arc<sled::Db>,
    /// SQLite for complex queries
    sql_db: Arc<Mutex<rusqlite::Connection>>,
    /// In-memory cache for frequently accessed data
    cache: DashMap<String, CacheEntry>,
    /// Write-ahead log for durability
    wal: Arc<RwLock<WriteAheadLog>>,
    /// Performance metrics
    metrics: Arc<Mutex<StorageMetrics>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    data: Vec<u8>,
    timestamp: Instant,
    access_count: u64,
}

#[derive(Debug, Default)]
struct WriteAheadLog {
    entries: Vec<WALEntry>,
    last_checkpoint: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WALEntry {
    operation: String,
    key: String,
    value: Option<Vec<u8>>,
    timestamp: Instant,
}

#[derive(Debug, Default, Clone)]
pub struct StorageMetrics {
    pub reads: u64,
    pub writes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub avg_read_time_us: f64,
    pub avg_write_time_us: f64,
    pub disk_usage_bytes: u64,
    pub cache_size_bytes: u64,
}

/// Vault state that needs to be persisted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultState {
    pub address: String,
    pub balance: u64,
    pub last_activity: Instant,
    pub inactivity_blocks: u32,
    pub pending_transactions: Vec<PendingTransaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransaction {
    pub txid: String,
    pub amount: u64,
    pub destination: String,
    pub created_at: Instant,
    pub agent_decision: Option<String>,
}

impl StorageManager {
    /// Create a new storage manager with performance optimizations
    pub async fn new(config: &Config) -> Result<Self> {
        // Create data directory if it doesn't exist
        if let Some(parent) = config.storage.db_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| TesaurusError::Storage(sled::Error::Io(e)))?;
        }

        // Initialize sled database with performance optimizations
        let sled_config = sled::Config::default()
            .path(&config.storage.db_path)
            .cache_capacity(config.storage.cache_size_mb * 1024 * 1024)
            .use_compression(config.storage.compression)
            .flush_every_ms(Some(1000)); // Flush every second for durability

        let kv_store = Arc::new(sled_config.open()
            .map_err(TesaurusError::Storage)?);

        // Initialize SQLite with performance optimizations
        let sql_path = config.storage.db_path.with_extension("sqlite");
        let sql_conn = rusqlite::Connection::open(&sql_path)?;
        
        // Configure SQLite for performance
        sql_conn.execute_batch(r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -262144; -- 256MB cache
            PRAGMA temp_store = MEMORY;
            PRAGMA mmap_size = 1073741824; -- 1GB mmap
        "#)?;

        // Create tables
        sql_conn.execute(r#"
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txid TEXT UNIQUE NOT NULL,
                amount INTEGER NOT NULL,
                destination TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                agent_decision TEXT,
                status TEXT NOT NULL DEFAULT 'pending'
            )
        "#, [])?;

        sql_conn.execute(r#"
            CREATE INDEX IF NOT EXISTS idx_transactions_txid ON transactions(txid);
            CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
            CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at);
        "#, [])?;

        let manager = Self {
            config: Arc::new(config.clone()),
            kv_store,
            sql_db: Arc::new(Mutex::new(sql_conn)),
            cache: DashMap::new(),
            wal: Arc::new(RwLock::new(WriteAheadLog::default())),
            metrics: Arc::new(Mutex::new(StorageMetrics::default())),
        };

        // Start background tasks
        manager.start_background_tasks().await;

        Ok(manager)
    }

    /// Start background maintenance tasks
    async fn start_background_tasks(&self) {
        let manager = self.clone();
        tokio::spawn(async move {
            manager.background_maintenance().await;
        });
    }

    /// Background maintenance loop
    async fn background_maintenance(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            // Cleanup expired cache entries
            self.cleanup_cache().await;
            
            // Checkpoint WAL if needed
            self.checkpoint_wal().await;
            
            // Update metrics
            self.update_disk_usage_metrics().await;
        }
    }

    /// Store data with caching and WAL
    pub async fn store<T>(&self, key: &str, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        let start_time = Instant::now();
        
        // Serialize data
        let serialized = bincode::serialize(value)?;
        
        // Write to WAL first
        {
            let mut wal = self.wal.write().await;
            wal.entries.push(WALEntry {
                operation: "store".to_string(),
                key: key.to_string(),
                value: Some(serialized.clone()),
                timestamp: Instant::now(),
            });
        }
        
        // Store in KV store
        self.kv_store.insert(key, serialized.clone())
            .map_err(TesaurusError::Storage)?;
        
        // Update cache
        self.cache.insert(key.to_string(), CacheEntry {
            data: serialized,
            timestamp: Instant::now(),
            access_count: 0,
        });
        
        // Update metrics
        let duration = start_time.elapsed();
        self.update_write_metrics(duration);
        
        Ok(())
    }

    /// Retrieve data with caching
    pub async fn retrieve<T>(&self, key: &str) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let start_time = Instant::now();
        
        // Check cache first
        if let Some(mut entry) = self.cache.get_mut(key) {
            entry.access_count += 1;
            let data = bincode::deserialize(&entry.data)?;
            self.update_read_metrics(start_time.elapsed(), true);
            return Ok(Some(data));
        }
        
        // Retrieve from KV store
        let result = self.kv_store.get(key)
            .map_err(TesaurusError::Storage)?;
        
        if let Some(serialized) = result {
            let data: T = bincode::deserialize(&serialized)?;
            
            // Cache the result
            self.cache.insert(key.to_string(), CacheEntry {
                data: serialized.to_vec(),
                timestamp: Instant::now(),
                access_count: 1,
            });
            
            self.update_read_metrics(start_time.elapsed(), false);
            Ok(Some(data))
        } else {
            self.update_read_metrics(start_time.elapsed(), false);
            Ok(None)
        }
    }

    /// Store transaction in SQL database for complex queries
    pub async fn store_transaction(&self, tx: &PendingTransaction) -> Result<()> {
        let conn = self.sql_db.lock();
        
        conn.execute(
            r#"INSERT OR REPLACE INTO transactions 
               (txid, amount, destination, created_at, agent_decision) 
               VALUES (?1, ?2, ?3, ?4, ?5)"#,
            rusqlite::params![
                tx.txid,
                tx.amount as i64,
                tx.destination,
                tx.created_at.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
                tx.agent_decision.as_deref()
            ]
        )?;
        
        Ok(())
    }

    /// Query transactions with pagination and filtering
    pub async fn query_transactions(
        &self,
        limit: usize,
        offset: usize,
        status_filter: Option<&str>,
    ) -> Result<Vec<PendingTransaction>> {
        let conn = self.sql_db.lock();
        
        let query = if let Some(status) = status_filter {
            "SELECT txid, amount, destination, created_at, agent_decision 
             FROM transactions WHERE status = ?1 
             ORDER BY created_at DESC LIMIT ?2 OFFSET ?3"
        } else {
            "SELECT txid, amount, destination, created_at, agent_decision 
             FROM transactions 
             ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
        };
        
        let mut stmt = conn.prepare(query)?;
        
        let rows = if let Some(status) = status_filter {
            stmt.query_map(rusqlite::params![status, limit, offset], |row| {
                Ok(PendingTransaction {
                    txid: row.get(0)?,
                    amount: row.get::<_, i64>(1)? as u64,
                    destination: row.get(2)?,
                    created_at: std::time::UNIX_EPOCH + Duration::from_secs(row.get::<_, i64>(3)? as u64),
                    agent_decision: row.get(4)?,
                })
            })?
        } else {
            stmt.query_map(rusqlite::params![limit, offset], |row| {
                Ok(PendingTransaction {
                    txid: row.get(0)?,
                    amount: row.get::<_, i64>(1)? as u64,
                    destination: row.get(2)?,
                    created_at: std::time::UNIX_EPOCH + Duration::from_secs(row.get::<_, i64>(3)? as u64),
                    agent_decision: row.get(4)?,
                })
            })?
        };
        
        let mut transactions = Vec::new();
        for row in rows {
            transactions.push(row?);
        }
        
        Ok(transactions)
    }

    /// Batch store multiple items for better performance
    pub async fn batch_store<T>(&self, items: &[(&str, &T)]) -> Result<()>
    where
        T: Serialize,
    {
        let start_time = Instant::now();
        
        // Use a transaction for atomic batch operations
        let mut batch = sled::Batch::default();
        let mut cache_updates = Vec::new();
        
        for (key, value) in items {
            let serialized = bincode::serialize(value)?;
            batch.insert(key.as_bytes(), serialized.clone());
            cache_updates.push((key.to_string(), serialized));
        }
        
        // Apply batch to KV store
        self.kv_store.apply_batch(batch)
            .map_err(TesaurusError::Storage)?;
        
        // Update cache
        for (key, data) in cache_updates {
            self.cache.insert(key, CacheEntry {
                data,
                timestamp: Instant::now(),
                access_count: 0,
            });
        }
        
        // Update metrics
        let duration = start_time.elapsed();
        for _ in items {
            self.update_write_metrics(duration);
        }
        
        Ok(())
    }

    /// Cleanup expired cache entries
    async fn cleanup_cache(&self) {
        let now = Instant::now();
        let cache_ttl = Duration::from_secs(3600); // 1 hour TTL
        
        self.cache.retain(|_, entry| {
            now.duration_since(entry.timestamp) < cache_ttl
        });
    }

    /// Checkpoint WAL to disk
    async fn checkpoint_wal(&self) {
        let mut wal = self.wal.write().await;
        
        if wal.last_checkpoint.elapsed() > Duration::from_secs(300) { // 5 minutes
            // In a real implementation, this would write WAL entries to stable storage
            wal.entries.clear();
            wal.last_checkpoint = Instant::now();
        }
    }

    /// Update disk usage metrics
    async fn update_disk_usage_metrics(&self) {
        if let Ok(size) = self.kv_store.size_on_disk() {
            let mut metrics = self.metrics.lock();
            metrics.disk_usage_bytes = size;
            metrics.cache_size_bytes = self.cache.len() as u64 * 1024; // Rough estimate
        }
    }

    /// Update read metrics
    fn update_read_metrics(&self, duration: Duration, cache_hit: bool) {
        let mut metrics = self.metrics.lock();
        metrics.reads += 1;
        
        if cache_hit {
            metrics.cache_hits += 1;
        } else {
            metrics.cache_misses += 1;
        }
        
        let duration_us = duration.as_micros() as f64;
        metrics.avg_read_time_us = 
            (metrics.avg_read_time_us * (metrics.reads - 1) as f64 + duration_us) 
            / metrics.reads as f64;
    }

    /// Update write metrics
    fn update_write_metrics(&self, duration: Duration) {
        let mut metrics = self.metrics.lock();
        metrics.writes += 1;
        
        let duration_us = duration.as_micros() as f64;
        metrics.avg_write_time_us = 
            (metrics.avg_write_time_us * (metrics.writes - 1) as f64 + duration_us) 
            / metrics.writes as f64;
    }

    /// Get storage metrics
    pub fn get_metrics(&self) -> StorageMetrics {
        self.metrics.lock().clone()
    }

    /// Flush all pending writes to disk
    pub async fn flush(&self) -> Result<()> {
        self.kv_store.flush_async().await
            .map_err(TesaurusError::Storage)?;
        Ok(())
    }
}

impl Clone for StorageManager {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            kv_store: Arc::clone(&self.kv_store),
            sql_db: Arc::clone(&self.sql_db),
            cache: self.cache.clone(),
            wal: Arc::clone(&self.wal),
            metrics: Arc::clone(&self.metrics),
        }
    }
}