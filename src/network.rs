//! High-performance network manager with connection pooling and optimization

use crate::{config::Config, error::TesaurusError, Result};
use reqwest::{Client, ClientBuilder};
use std::sync::Arc;
use tokio::sync::RwLock;
use parking_lot::Mutex;
use dashmap::DashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Network manager with connection pooling and caching
pub struct NetworkManager {
    /// HTTP client with connection pooling
    client: Client,
    /// Configuration
    config: Arc<Config>,
    /// Response cache for frequently accessed data
    response_cache: DashMap<String, CachedResponse>,
    /// Connection pool metrics
    metrics: Arc<Mutex<NetworkMetrics>>,
    /// Rate limiting state
    rate_limiter: Arc<RwLock<RateLimiter>>,
}

#[derive(Debug, Clone)]
struct CachedResponse {
    data: Vec<u8>,
    timestamp: Instant,
    ttl: Duration,
    hit_count: u64,
}

#[derive(Debug, Default, Clone)]
pub struct NetworkMetrics {
    pub requests_sent: u64,
    pub requests_cached: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub avg_response_time_ms: f64,
    pub connection_errors: u64,
    pub timeouts: u64,
}

#[derive(Debug)]
struct RateLimiter {
    requests_per_second: u32,
    current_window: Instant,
    requests_in_window: u32,
}

impl NetworkManager {
    /// Create a new network manager with performance optimizations
    pub async fn new(config: &Config) -> Result<Self> {
        // Build HTTP client with performance optimizations
        let client = ClientBuilder::new()
            .timeout(config.network.timeout)
            .pool_max_idle_per_host(config.network.pool_size)
            .pool_idle_timeout(config.network.keep_alive)
            .http2_prior_knowledge()
            .http2_keep_alive_interval(Some(Duration::from_secs(30)))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .tcp_nodelay(true)
            .use_rustls_tls() // Use rustls for better performance
            .gzip(true)
            .brotli(true)
            .build()
            .map_err(TesaurusError::Network)?;

        let rate_limiter = RateLimiter {
            requests_per_second: 100, // Default rate limit
            current_window: Instant::now(),
            requests_in_window: 0,
        };

        Ok(Self {
            client,
            config: Arc::new(config.clone()),
            response_cache: DashMap::new(),
            metrics: Arc::new(Mutex::new(NetworkMetrics::default())),
            rate_limiter: Arc::new(RwLock::new(rate_limiter)),
        })
    }

    /// Make HTTP GET request with caching and rate limiting
    pub async fn get(&self, url: &str, cache_ttl: Option<Duration>) -> Result<Vec<u8>> {
        let start_time = Instant::now();
        
        // Check cache first if TTL is specified
        if let Some(ttl) = cache_ttl {
            if let Some(mut cached) = self.response_cache.get_mut(url) {
                if cached.timestamp.elapsed() < cached.ttl {
                    cached.hit_count += 1;
                    self.update_cache_metrics();
                    return Ok(cached.data.clone());
                }
            }
        }

        // Apply rate limiting
        self.apply_rate_limit().await?;

        // Make HTTP request
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(TesaurusError::Network)?;

        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(TesaurusError::Network)?
            .to_vec();

        if !status.is_success() {
            return Err(TesaurusError::Network(reqwest::Error::from(
                reqwest::ErrorKind::Request
            )));
        }

        // Cache response if TTL is specified
        if let Some(ttl) = cache_ttl {
            self.response_cache.insert(url.to_string(), CachedResponse {
                data: bytes.clone(),
                timestamp: Instant::now(),
                ttl,
                hit_count: 0,
            });
        }

        // Update metrics
        let response_time = start_time.elapsed();
        self.update_request_metrics(bytes.len(), response_time);

        Ok(bytes)
    }

    /// Make HTTP POST request with JSON payload
    pub async fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        payload: &T,
    ) -> Result<R> {
        let start_time = Instant::now();

        // Apply rate limiting
        self.apply_rate_limit().await?;

        // Serialize payload
        let json_payload = serde_json::to_vec(payload)?;

        // Make HTTP request
        let response = self.client
            .post(url)
            .header("Content-Type", "application/json")
            .body(json_payload.clone())
            .send()
            .await
            .map_err(TesaurusError::Network)?;

        let status = response.status();
        let response_bytes = response
            .bytes()
            .await
            .map_err(TesaurusError::Network)?;

        if !status.is_success() {
            return Err(TesaurusError::Network(reqwest::Error::from(
                reqwest::ErrorKind::Request
            )));
        }

        // Deserialize response
        let result: R = serde_json::from_slice(&response_bytes)?;

        // Update metrics
        let response_time = start_time.elapsed();
        self.update_request_metrics(response_bytes.len(), response_time);

        Ok(result)
    }

    /// Bitcoin RPC call with optimizations
    pub async fn bitcoin_rpc<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: &T,
    ) -> Result<R> {
        #[derive(Serialize)]
        struct RpcRequest<'a, T> {
            jsonrpc: &'a str,
            id: u64,
            method: &'a str,
            params: &'a T,
        }

        #[derive(Deserialize)]
        struct RpcResponse<R> {
            result: Option<R>,
            error: Option<RpcError>,
        }

        #[derive(Deserialize)]
        struct RpcError {
            code: i32,
            message: String,
        }

        let request_id = self.generate_request_id();
        let rpc_request = RpcRequest {
            jsonrpc: "1.0",
            id: request_id,
            method,
            params,
        };

        // Use cached credentials
        let auth = base64::encode(format!(
            "{}:{}", 
            self.config.bitcoin.rpc_user, 
            self.config.bitcoin.rpc_password
        ));

        let start_time = Instant::now();

        // Apply rate limiting
        self.apply_rate_limit().await?;

        // Make RPC call
        let response = self.client
            .post(&self.config.bitcoin.rpc_url)
            .header("Authorization", format!("Basic {}", auth))
            .header("Content-Type", "application/json")
            .json(&rpc_request)
            .send()
            .await
            .map_err(TesaurusError::Network)?;

        let rpc_response: RpcResponse<R> = response
            .json()
            .await
            .map_err(TesaurusError::Network)?;

        // Handle RPC errors
        if let Some(error) = rpc_response.error {
            return Err(TesaurusError::Internal(format!(
                "Bitcoin RPC error {}: {}", error.code, error.message
            )));
        }

        let result = rpc_response.result.ok_or_else(|| {
            TesaurusError::Internal("Missing result in RPC response".to_string())
        })?;

        // Update metrics
        let response_time = start_time.elapsed();
        self.update_request_metrics(0, response_time); // Size unknown for JSON

        Ok(result)
    }

    /// Apply rate limiting
    async fn apply_rate_limit(&self) -> Result<()> {
        let mut limiter = self.rate_limiter.write().await;
        
        let now = Instant::now();
        
        // Reset window if needed
        if now.duration_since(limiter.current_window) >= Duration::from_secs(1) {
            limiter.current_window = now;
            limiter.requests_in_window = 0;
        }

        // Check if we've exceeded the limit
        if limiter.requests_in_window >= limiter.requests_per_second {
            let sleep_duration = Duration::from_secs(1) - now.duration_since(limiter.current_window);
            drop(limiter); // Release the lock before sleeping
            tokio::time::sleep(sleep_duration).await;
            return self.apply_rate_limit().await; // Retry
        }

        limiter.requests_in_window += 1;
        Ok(())
    }

    /// Generate unique request ID
    fn generate_request_id(&self) -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// Update request metrics
    fn update_request_metrics(&self, response_size: usize, response_time: Duration) {
        let mut metrics = self.metrics.lock();
        metrics.requests_sent += 1;
        metrics.bytes_received += response_size as u64;
        
        let response_time_ms = response_time.as_millis() as f64;
        metrics.avg_response_time_ms = 
            (metrics.avg_response_time_ms * (metrics.requests_sent - 1) as f64 + response_time_ms) 
            / metrics.requests_sent as f64;
    }

    /// Update cache metrics
    fn update_cache_metrics(&self) {
        let mut metrics = self.metrics.lock();
        metrics.requests_cached += 1;
    }

    /// Clear expired cache entries
    pub async fn cleanup_cache(&self) {
        let now = Instant::now();
        self.response_cache.retain(|_, entry| {
            now.duration_since(entry.timestamp) < entry.ttl
        });
    }

    /// Get network metrics
    pub fn get_metrics(&self) -> NetworkMetrics {
        self.metrics.lock().clone()
    }

    /// Batch multiple requests for better performance
    pub async fn batch_get(&self, urls: &[&str], cache_ttl: Option<Duration>) -> Result<Vec<Vec<u8>>> {
        let futures: Vec<_> = urls.iter()
            .map(|url| self.get(url, cache_ttl))
            .collect();

        futures::future::try_join_all(futures).await
    }

    /// WebSocket connection for real-time updates (placeholder)
    pub async fn connect_websocket(&self, _url: &str) -> Result<()> {
        // In a real implementation, this would establish WebSocket connections
        // for real-time Bitcoin network updates
        Ok(())
    }

    /// Health check endpoint
    pub async fn health_check(&self) -> Result<bool> {
        match self.get("https://httpbin.org/status/200", None).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl Clone for NetworkManager {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            config: Arc::clone(&self.config),
            response_cache: self.response_cache.clone(),
            metrics: Arc::clone(&self.metrics),
            rate_limiter: Arc::clone(&self.rate_limiter),
        }
    }
}