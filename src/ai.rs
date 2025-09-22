//! AI Engine with performance optimizations for Bitcoin vault decisions

use crate::{config::Config, error::TesaurusError, Result};
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use parking_lot::Mutex;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// AI decision types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AIDecision {
    /// Approve the transaction
    Approve,
    /// Reject the transaction
    Reject,
    /// Request human review
    ReviewRequired,
}

/// Transaction context for AI decision making
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionContext {
    /// Transaction amount in satoshis
    pub amount: u64,
    /// Destination address
    pub destination: String,
    /// Time since last activity
    pub inactivity_duration: Duration,
    /// Transaction fee rate
    pub fee_rate: u64,
    /// Historical transaction patterns
    pub historical_patterns: Vec<TransactionPattern>,
    /// Current block height
    pub block_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionPattern {
    pub amount: u64,
    pub frequency: f64,
    pub time_of_day: u8,
    pub day_of_week: u8,
}

/// High-performance AI engine for vault decisions
pub struct AIEngine {
    /// AI model configuration
    config: Arc<Config>,
    /// Decision cache to avoid repeated computations
    decision_cache: DashMap<String, (AIDecision, Instant)>,
    /// Inference semaphore to limit concurrent operations
    inference_semaphore: Arc<Semaphore>,
    /// Model state (simplified - in practice would load actual ML model)
    model_state: Arc<RwLock<ModelState>>,
    /// Performance metrics
    metrics: Arc<Mutex<AIMetrics>>,
}

#[derive(Debug, Default)]
struct ModelState {
    /// Model version
    version: String,
    /// Last update timestamp
    last_update: Instant,
    /// Model parameters (simplified)
    parameters: Vec<f32>,
}

#[derive(Debug, Default, Clone)]
pub struct AIMetrics {
    pub total_decisions: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub avg_inference_time_ms: f64,
    pub approvals: u64,
    pub rejections: u64,
    pub reviews_required: u64,
}

impl AIEngine {
    /// Create a new AI engine with performance optimizations
    pub async fn new(config: &Config) -> Result<Self> {
        let inference_semaphore = Arc::new(Semaphore::new(config.ai.threads));
        let model_state = Arc::new(RwLock::new(ModelState::default()));
        
        let engine = Self {
            config: Arc::new(config.clone()),
            decision_cache: DashMap::new(),
            inference_semaphore,
            model_state,
            metrics: Arc::new(Mutex::new(AIMetrics::default())),
        };

        // Load model if available
        engine.load_model().await?;
        
        Ok(engine)
    }

    /// Load AI model from disk with performance optimizations
    async fn load_model(&self) -> Result<()> {
        let model_path = &self.config.ai.model_path;
        
        if !model_path.exists() {
            // Initialize with default parameters if model doesn't exist
            self.initialize_default_model().await?;
            return Ok(());
        }

        // In a real implementation, this would load the actual ML model
        // For now, we'll simulate with default parameters
        let mut state = self.model_state.write().await;
        state.version = "1.0.0".to_string();
        state.last_update = Instant::now();
        state.parameters = vec![0.5; 1000]; // Simplified model parameters
        
        Ok(())
    }

    /// Initialize default model parameters
    async fn initialize_default_model(&self) -> Result<()> {
        let mut state = self.model_state.write().await;
        state.version = "default".to_string();
        state.last_update = Instant::now();
        
        // Initialize with reasonable defaults for Bitcoin vault decisions
        state.parameters = vec![
            0.8, // Amount threshold weight
            0.9, // Inactivity duration weight
            0.7, // Fee rate reasonableness weight
            0.6, // Pattern matching weight
            0.5, // Time-based factors weight
        ];
        
        Ok(())
    }

    /// Make AI decision with caching and performance optimizations
    pub async fn make_decision(&self, context: &TransactionContext) -> Result<AIDecision> {
        let start_time = Instant::now();
        
        // Create cache key from context
        let cache_key = self.create_cache_key(context);
        
        // Check cache first
        if let Some((decision, timestamp)) = self.decision_cache.get(&cache_key) {
            // Cache is valid for 5 minutes
            if timestamp.elapsed() < Duration::from_secs(300) {
                self.update_metrics_cache_hit();
                return Ok(decision.clone());
            }
        }

        // Acquire inference semaphore to limit concurrent operations
        let _permit = self.inference_semaphore.acquire().await
            .map_err(|_| TesaurusError::ai("Failed to acquire inference permit"))?;

        // Perform inference
        let decision = self.perform_inference(context).await?;
        
        // Cache the decision
        self.decision_cache.insert(cache_key, (decision.clone(), Instant::now()));
        
        // Update metrics
        let inference_time = start_time.elapsed();
        self.update_metrics_inference(decision.clone(), inference_time);
        
        Ok(decision)
    }

    /// Perform actual AI inference (optimized implementation)
    async fn perform_inference(&self, context: &TransactionContext) -> Result<AIDecision> {
        let state = self.model_state.read().await;
        
        // Simplified decision logic - in practice would use actual ML inference
        let mut score = 0.0;
        
        // Amount-based scoring
        let amount_btc = context.amount as f64 / 100_000_000.0;
        if amount_btc > 1.0 {
            score -= 0.3; // Large amounts are riskier
        }
        
        // Inactivity-based scoring
        let inactivity_hours = context.inactivity_duration.as_secs() as f64 / 3600.0;
        if inactivity_hours > 24.0 {
            score += 0.2; // Longer inactivity suggests legitimate recovery
        }
        
        // Fee rate analysis
        if context.fee_rate > 100 {
            score -= 0.1; // Unusually high fees are suspicious
        } else if context.fee_rate < 10 {
            score -= 0.2; // Very low fees might indicate spam
        }
        
        // Pattern matching (simplified)
        let pattern_score = self.analyze_patterns(&context.historical_patterns);
        score += pattern_score * state.parameters[3];
        
        // Time-based factors
        let time_score = self.analyze_timing(context);
        score += time_score * state.parameters[4];
        
        // Make decision based on score
        let decision = if score > 0.5 {
            AIDecision::Approve
        } else if score > 0.0 {
            AIDecision::ReviewRequired
        } else {
            AIDecision::Reject
        };
        
        Ok(decision)
    }

    /// Analyze transaction patterns for anomalies
    fn analyze_patterns(&self, patterns: &[TransactionPattern]) -> f64 {
        if patterns.is_empty() {
            return 0.0;
        }
        
        // Calculate pattern consistency score
        let mut consistency_score = 0.0;
        let avg_amount: f64 = patterns.iter().map(|p| p.amount as f64).sum::<f64>() / patterns.len() as f64;
        let avg_frequency: f64 = patterns.iter().map(|p| p.frequency).sum::<f64>() / patterns.len() as f64;
        
        // Patterns that are consistent with history get higher scores
        if avg_frequency > 0.1 {
            consistency_score += 0.2;
        }
        
        if avg_amount > 0.0 {
            consistency_score += 0.1;
        }
        
        consistency_score.min(0.5)
    }

    /// Analyze timing factors
    fn analyze_timing(&self, context: &TransactionContext) -> f64 {
        use chrono::{Utc, Timelike, Weekday, Datelike};
        
        let now = Utc::now();
        let hour = now.hour();
        let weekday = now.weekday();
        
        let mut timing_score = 0.0;
        
        // Normal business hours are slightly more trustworthy
        if (9..17).contains(&hour) && weekday != Weekday::Sat && weekday != Weekday::Sun {
            timing_score += 0.1;
        }
        
        // Very late night transactions are more suspicious
        if hour < 6 || hour > 23 {
            timing_score -= 0.1;
        }
        
        timing_score
    }

    /// Create cache key from transaction context
    fn create_cache_key(&self, context: &TransactionContext) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(context.amount.to_le_bytes());
        hasher.update(context.destination.as_bytes());
        hasher.update(context.inactivity_duration.as_secs().to_le_bytes());
        hasher.update(context.fee_rate.to_le_bytes());
        hasher.update(context.block_height.to_le_bytes());
        
        hex::encode(hasher.finalize())
    }

    /// Update metrics for cache hit
    fn update_metrics_cache_hit(&self) {
        let mut metrics = self.metrics.lock();
        metrics.cache_hits += 1;
    }

    /// Update metrics for inference
    fn update_metrics_inference(&self, decision: AIDecision, duration: Duration) {
        let mut metrics = self.metrics.lock();
        metrics.total_decisions += 1;
        metrics.cache_misses += 1;
        
        // Update average inference time
        let duration_ms = duration.as_millis() as f64;
        metrics.avg_inference_time_ms = 
            (metrics.avg_inference_time_ms * (metrics.total_decisions - 1) as f64 + duration_ms) 
            / metrics.total_decisions as f64;
        
        // Update decision counters
        match decision {
            AIDecision::Approve => metrics.approvals += 1,
            AIDecision::Reject => metrics.rejections += 1,
            AIDecision::ReviewRequired => metrics.reviews_required += 1,
        }
    }

    /// Get AI engine metrics
    pub fn get_metrics(&self) -> AIMetrics {
        self.metrics.lock().clone()
    }

    /// Clear decision cache to free memory
    pub fn clear_cache(&self) {
        self.decision_cache.clear();
    }

    /// Batch process multiple decisions for better performance
    pub async fn batch_decisions(&self, contexts: &[TransactionContext]) -> Result<Vec<AIDecision>> {
        let mut decisions = Vec::with_capacity(contexts.len());
        
        // Process in parallel batches
        let batch_size = self.config.ai.batch_size;
        for chunk in contexts.chunks(batch_size) {
            let mut batch_futures = Vec::new();
            
            for context in chunk {
                batch_futures.push(self.make_decision(context));
            }
            
            let batch_results = futures::future::try_join_all(batch_futures).await?;
            decisions.extend(batch_results);
        }
        
        Ok(decisions)
    }
}