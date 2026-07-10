//! Core vault functionality with performance optimizations

use crate::{
    config::Config, 
    crypto::CryptoManager, 
    ai::{AIEngine, AIDecision, TransactionContext},
    storage::{StorageManager, VaultState, PendingTransaction},
    error::TesaurusError, 
    Result
};
use bitcoin::{Transaction, TxOut, Address, PublicKey, PrivateKey};
use std::sync::Arc;
use tokio::sync::RwLock;
use parking_lot::Mutex;
use dashmap::DashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// High-performance vault manager
pub struct VaultManager {
    /// Configuration
    config: Arc<Config>,
    /// Cryptographic operations
    crypto: Arc<CryptoManager>,
    /// AI decision engine
    ai_engine: Arc<AIEngine>,
    /// Storage backend
    storage: Arc<StorageManager>,
    /// Current vault state
    state: Arc<RwLock<VaultState>>,
    /// Transaction pool for pending operations
    tx_pool: DashMap<String, PooledTransaction>,
    /// Performance metrics
    metrics: Arc<Mutex<VaultMetrics>>,
    /// Key management
    keys: Arc<RwLock<KeyManager>>,
}

#[derive(Debug, Clone)]
struct PooledTransaction {
    transaction: PendingTransaction,
    priority: TransactionPriority,
    retry_count: u32,
    last_attempt: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TransactionPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

#[derive(Debug, Default, Clone)]
pub struct VaultMetrics {
    pub transactions_processed: u64,
    pub ai_approvals: u64,
    pub ai_rejections: u64,
    pub manual_overrides: u64,
    pub avg_processing_time_ms: f64,
    pub current_balance: u64,
    pub inactivity_duration_hours: f64,
}

#[derive(Debug)]
struct KeyManager {
    primary_key: Option<PrivateKey>,
    override_key: Option<PrivateKey>,
    ai_key: Option<PrivateKey>,
    multisig_address: Option<Address>,
    public_keys: Vec<PublicKey>,
}

impl KeyManager {
    fn new() -> Self {
        Self {
            primary_key: None,
            override_key: None,
            ai_key: None,
            multisig_address: None,
            public_keys: Vec::new(),
        }
    }
}

/// Transaction creation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionParams {
    pub destination: Address,
    pub amount: u64,
    pub fee_rate: u64,
    pub use_ai: bool,
    pub priority: String,
}

impl VaultManager {
    /// Create a new vault manager with performance optimizations
    pub async fn new(
        config: Config,
        crypto: Arc<CryptoManager>,
        ai_engine: Arc<AIEngine>,
        storage: Arc<StorageManager>,
    ) -> Result<Self> {
        let config = Arc::new(config);
        
        // Initialize vault state
        let vault_state = VaultState {
            address: String::new(), // Will be set after key setup
            balance: 0,
            last_activity: Instant::now(),
            inactivity_blocks: 0,
            pending_transactions: Vec::new(),
        };

        let manager = Self {
            config,
            crypto,
            ai_engine,
            storage,
            state: Arc::new(RwLock::new(vault_state)),
            tx_pool: DashMap::new(),
            metrics: Arc::new(Mutex::new(VaultMetrics::default())),
            keys: Arc::new(RwLock::new(KeyManager::new())),
        };

        // Load existing state if available
        manager.load_state().await?;
        
        // Start background processing
        manager.start_background_tasks().await;

        Ok(manager)
    }

    /// Initialize vault with keys
    pub async fn initialize_keys(
        &self,
        primary_key: PrivateKey,
        override_key: PrivateKey,
        ai_key: PrivateKey,
    ) -> Result<Address> {
        let mut keys = self.keys.write().await;
        
        // Derive public keys
        let primary_pubkey = self.crypto.derive_public_key(&primary_key)?;
        let override_pubkey = self.crypto.derive_public_key(&override_key)?;
        let ai_pubkey = self.crypto.derive_public_key(&ai_key)?;
        
        let public_keys = vec![primary_pubkey, override_pubkey, ai_pubkey];
        
        // Create 2-of-3 multisig address
        let multisig_address = self.crypto.create_multisig_address(&public_keys, 2)?;
        
        // Store keys and address
        keys.primary_key = Some(primary_key);
        keys.override_key = Some(override_key);
        keys.ai_key = Some(ai_key);
        keys.multisig_address = Some(multisig_address.clone());
        keys.public_keys = public_keys;
        
        // Update vault state
        {
            let mut state = self.state.write().await;
            state.address = multisig_address.to_string();
        }
        
        // Persist state
        self.save_state().await?;
        
        Ok(multisig_address)
    }

    /// Create and submit a transaction with AI decision making
    pub async fn create_transaction(&self, params: TransactionParams) -> Result<String> {
        let start_time = Instant::now();
        
        // Validate parameters
        self.validate_transaction_params(&params).await?;
        
        // Create transaction context for AI
        let context = self.create_transaction_context(&params).await?;
        
        // Get AI decision if requested
        let ai_decision = if params.use_ai {
            Some(self.ai_engine.make_decision(&context).await?)
        } else {
            None
        };
        
        // Check if transaction should proceed
        match &ai_decision {
            Some(AIDecision::Reject) => {
                return Err(TesaurusError::Transaction("AI rejected transaction".to_string()));
            }
            Some(AIDecision::ReviewRequired) => {
                // Queue for manual review
                return self.queue_for_review(params, context).await;
            }
            _ => {} // Approve or no AI decision
        }
        
        // Create and sign transaction
        let txid = self.execute_transaction(params, ai_decision).await?;
        
        // Update metrics
        let processing_time = start_time.elapsed();
        self.update_transaction_metrics(processing_time, &ai_decision);
        
        Ok(txid)
    }

    /// Execute transaction with appropriate key combination
    async fn execute_transaction(
        &self,
        params: TransactionParams,
        ai_decision: Option<AIDecision>,
    ) -> Result<String> {
        let keys = self.keys.read().await;
        let state = self.state.read().await;
        
        // Determine which keys to use based on inactivity and AI decision
        let (signing_keys, key_description) = if state.inactivity_blocks >= self.config.bitcoin.inactivity_blocks {
            // Post-inactivity: use primary + AI key
            if let (Some(primary), Some(ai)) = (&keys.primary_key, &keys.ai_key) {
                (vec![primary.clone(), ai.clone()], "primary+ai")
            } else {
                return Err(TesaurusError::Transaction("Required keys not available".to_string()));
            }
        } else {
            // Pre-inactivity: use primary + override keys
            if let (Some(primary), Some(override_key)) = (&keys.primary_key, &keys.override_key) {
                (vec![primary.clone(), override_key.clone()], "primary+override")
            } else {
                return Err(TesaurusError::Transaction("Required keys not available".to_string()));
            }
        };
        
        // Create Bitcoin transaction (simplified - would need proper UTXO management)
        let txid = format!("tx_{}", uuid::Uuid::new_v4());
        
        // Store transaction record
        let pending_tx = PendingTransaction {
            txid: txid.clone(),
            amount: params.amount,
            destination: params.destination.to_string(),
            created_at: Instant::now(),
            ai_decision: ai_decision.map(|d| format!("{:?}", d)),
        };
        
        self.storage.store_transaction(&pending_tx).await?;
        
        // Add to transaction pool
        let priority = match params.priority.as_str() {
            "low" => TransactionPriority::Low,
            "high" => TransactionPriority::High,
            "critical" => TransactionPriority::Critical,
            _ => TransactionPriority::Normal,
        };
        
        self.tx_pool.insert(txid.clone(), PooledTransaction {
            transaction: pending_tx,
            priority,
            retry_count: 0,
            last_attempt: Instant::now(),
        });
        
        tracing::info!(
            "Transaction created with {} keys: {}",
            key_description,
            txid
        );
        
        Ok(txid)
    }

    /// Queue transaction for manual review
    async fn queue_for_review(
        &self,
        params: TransactionParams,
        context: TransactionContext,
    ) -> Result<String> {
        let review_id = format!("review_{}", uuid::Uuid::new_v4());
        
        // Store for manual review (simplified)
        tracing::warn!(
            "Transaction queued for manual review: {} BTC to {}",
            params.amount as f64 / 100_000_000.0,
            params.destination
        );
        
        Ok(review_id)
    }

    /// Create transaction context for AI decision making
    async fn create_transaction_context(&self, params: &TransactionParams) -> Result<TransactionContext> {
        let state = self.state.read().await;
        
        // Get historical patterns (simplified)
        let historical_patterns = self.get_historical_patterns().await?;
        
        Ok(TransactionContext {
            amount: params.amount,
            destination: params.destination.to_string(),
            inactivity_duration: state.last_activity.elapsed(),
            fee_rate: params.fee_rate,
            historical_patterns,
            block_height: self.get_current_block_height().await?,
        })
    }

    /// Get historical transaction patterns for AI analysis
    async fn get_historical_patterns(&self) -> Result<Vec<crate::ai::TransactionPattern>> {
        // Query recent transactions from storage
        let recent_txs = self.storage.query_transactions(100, 0, Some("completed")).await?;
        
        // Analyze patterns (simplified)
        let mut patterns = Vec::new();
        
        for tx in recent_txs {
            let pattern = crate::ai::TransactionPattern {
                amount: tx.amount,
                frequency: 1.0, // Simplified
                time_of_day: 12, // Simplified
                day_of_week: 1,  // Simplified
            };
            patterns.push(pattern);
        }
        
        Ok(patterns)
    }

    /// Get current block height from Bitcoin node
    async fn get_current_block_height(&self) -> Result<u32> {
        // In a real implementation, this would query the Bitcoin node
        // For now, return a mock value
        Ok(800000)
    }

    /// Validate transaction parameters
    async fn validate_transaction_params(&self, params: &TransactionParams) -> Result<()> {
        let state = self.state.read().await;
        
        if params.amount == 0 {
            return Err(TesaurusError::InvalidInput("Amount must be greater than 0".to_string()));
        }
        
        if params.amount > state.balance {
            return Err(TesaurusError::InvalidInput("Insufficient balance".to_string()));
        }
        
        if params.fee_rate == 0 {
            return Err(TesaurusError::InvalidInput("Fee rate must be greater than 0".to_string()));
        }
        
        Ok(())
    }

    /// Load vault state from storage
    async fn load_state(&self) -> Result<()> {
        if let Some(saved_state) = self.storage.retrieve::<VaultState>("vault_state").await? {
            let mut state = self.state.write().await;
            *state = saved_state;
        }
        Ok(())
    }

    /// Save vault state to storage
    async fn save_state(&self) -> Result<()> {
        let state = self.state.read().await;
        self.storage.store("vault_state", &*state).await
    }

    /// Start background processing tasks
    async fn start_background_tasks(&self) {
        let manager = self.clone();
        tokio::spawn(async move {
            manager.background_processing().await;
        });
    }

    /// Background processing loop
    async fn background_processing(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        
        loop {
            interval.tick().await;
            
            // Process pending transactions
            if let Err(e) = self.process_pending_transactions().await {
                tracing::error!("Error processing pending transactions: {}", e);
            }
            
            // Update inactivity status
            if let Err(e) = self.update_inactivity_status().await {
                tracing::error!("Error updating inactivity status: {}", e);
            }
            
            // Save state periodically
            if let Err(e) = self.save_state().await {
                tracing::error!("Error saving vault state: {}", e);
            }
        }
    }

    /// Process pending transactions in the pool
    async fn process_pending_transactions(&self) -> Result<()> {
        // Get transactions sorted by priority
        let mut pending: Vec<_> = self.tx_pool.iter().collect();
        pending.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        for entry in pending.into_iter().take(10) { // Process up to 10 at a time
            let txid = entry.key().clone();
            let mut pooled_tx = entry.value().clone();
            
            // Check if it's time to retry
            if pooled_tx.last_attempt.elapsed() < Duration::from_secs(60) {
                continue;
            }
            
            // Attempt to broadcast transaction
            match self.broadcast_transaction(&pooled_tx.transaction).await {
                Ok(_) => {
                    // Remove from pool on success
                    self.tx_pool.remove(&txid);
                    tracing::info!("Successfully broadcast transaction: {}", txid);
                }
                Err(e) => {
                    // Update retry count and timestamp
                    pooled_tx.retry_count += 1;
                    pooled_tx.last_attempt = Instant::now();
                    
                    if pooled_tx.retry_count >= 5 {
                        // Remove after 5 failed attempts
                        self.tx_pool.remove(&txid);
                        tracing::error!("Giving up on transaction after 5 retries: {}", txid);
                    } else {
                        self.tx_pool.insert(txid, pooled_tx);
                        tracing::warn!("Retry {} failed for transaction: {} - {}", 
                                     pooled_tx.retry_count, txid, e);
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Broadcast transaction to Bitcoin network
    async fn broadcast_transaction(&self, _tx: &PendingTransaction) -> Result<()> {
        // In a real implementation, this would broadcast to the Bitcoin network
        // For now, just simulate success
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    /// Update inactivity status based on block height
    async fn update_inactivity_status(&self) -> Result<()> {
        let current_height = self.get_current_block_height().await?;
        let mut state = self.state.write().await;
        
        // Calculate inactivity blocks (simplified)
        let last_activity_height = current_height.saturating_sub(10); // Mock calculation
        state.inactivity_blocks = current_height.saturating_sub(last_activity_height);
        
        // Update metrics
        {
            let mut metrics = self.metrics.lock();
            metrics.inactivity_duration_hours = state.last_activity.elapsed().as_secs_f64() / 3600.0;
            metrics.current_balance = state.balance;
        }
        
        Ok(())
    }

    /// Update transaction processing metrics
    fn update_transaction_metrics(&self, duration: Duration, ai_decision: &Option<AIDecision>) {
        let mut metrics = self.metrics.lock();
        metrics.transactions_processed += 1;
        
        match ai_decision {
            Some(AIDecision::Approve) => metrics.ai_approvals += 1,
            Some(AIDecision::Reject) => metrics.ai_rejections += 1,
            Some(AIDecision::ReviewRequired) => {}, // Handled separately
            None => metrics.manual_overrides += 1,
        }
        
        let duration_ms = duration.as_millis() as f64;
        metrics.avg_processing_time_ms = 
            (metrics.avg_processing_time_ms * (metrics.transactions_processed - 1) as f64 + duration_ms) 
            / metrics.transactions_processed as f64;
    }

    /// Get vault metrics
    pub fn get_metrics(&self) -> VaultMetrics {
        self.metrics.lock().clone()
    }

    /// Get current vault state
    pub async fn get_state(&self) -> VaultState {
        self.state.read().await.clone()
    }
}

impl Clone for VaultManager {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            crypto: Arc::clone(&self.crypto),
            ai_engine: Arc::clone(&self.ai_engine),
            storage: Arc::clone(&self.storage),
            state: Arc::clone(&self.state),
            tx_pool: self.tx_pool.clone(),
            metrics: Arc::clone(&self.metrics),
            keys: Arc::clone(&self.keys),
        }
    }
}