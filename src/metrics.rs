//! Performance metrics collection and monitoring

use crate::{config::Config, Result};
use std::sync::Arc;
use parking_lot::Mutex;
use dashmap::DashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Centralized metrics collector
pub struct MetricsCollector {
    /// Configuration
    config: Arc<Config>,
    /// System metrics
    system_metrics: Arc<Mutex<SystemMetrics>>,
    /// Application metrics
    app_metrics: Arc<Mutex<AppMetrics>>,
    /// Custom counters
    counters: DashMap<String, u64>,
    /// Custom gauges
    gauges: DashMap<String, f64>,
    /// Custom histograms
    histograms: DashMap<String, Histogram>,
    /// Start time for uptime calculation
    start_time: Instant,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub memory_available_bytes: u64,
    pub disk_usage_bytes: u64,
    pub disk_available_bytes: u64,
    pub network_bytes_sent: u64,
    pub network_bytes_received: u64,
    pub open_file_descriptors: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AppMetrics {
    pub transactions_processed: u64,
    pub agent_decisions_made: u64,
    pub cache_hit_ratio: f64,
    pub avg_transaction_time_ms: f64,
    pub error_count: u64,
    pub active_connections: u64,
    pub pending_operations: u64,
    pub memory_pool_size: u64,
}

#[derive(Debug, Clone)]
pub struct Histogram {
    buckets: Vec<(f64, u64)>, // (upper_bound, count)
    sum: f64,
    count: u64,
}

impl Histogram {
    pub fn new(buckets: Vec<f64>) -> Self {
        let buckets = buckets.into_iter()
            .map(|bound| (bound, 0))
            .collect();
        
        Self {
            buckets,
            sum: 0.0,
            count: 0,
        }
    }

    pub fn observe(&mut self, value: f64) {
        self.sum += value;
        self.count += 1;
        
        for (bound, count) in &mut self.buckets {
            if value <= *bound {
                *count += 1;
            }
        }
    }

    pub fn quantile(&self, q: f64) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        
        let target = (self.count as f64 * q) as u64;
        let mut cumulative = 0;
        
        for (bound, count) in &self.buckets {
            cumulative += count;
            if cumulative >= target {
                return *bound;
            }
        }
        
        self.buckets.last().map(|(bound, _)| *bound).unwrap_or(0.0)
    }
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            config: Arc::new(Config::default()),
            system_metrics: Arc::new(Mutex::new(SystemMetrics::default())),
            app_metrics: Arc::new(Mutex::new(AppMetrics::default())),
            counters: DashMap::new(),
            gauges: DashMap::new(),
            histograms: DashMap::new(),
            start_time: Instant::now(),
        }
    }

    /// Start metrics collection background task
    pub async fn start_collection(&self) {
        if !self.config.performance.enable_metrics {
            return;
        }

        let collector = self.clone();
        tokio::spawn(async move {
            collector.collection_loop().await;
        });

        // Start Prometheus metrics server if enabled
        if self.config.performance.enable_metrics {
            let collector = self.clone();
            tokio::spawn(async move {
                collector.start_prometheus_server().await;
            });
        }
    }

    /// Main metrics collection loop
    async fn collection_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        
        loop {
            interval.tick().await;
            
            // Collect system metrics
            if let Err(e) = self.collect_system_metrics().await {
                tracing::error!("Failed to collect system metrics: {}", e);
            }
            
            // Update uptime
            self.update_uptime();
        }
    }

    /// Collect system metrics
    async fn collect_system_metrics(&self) -> Result<()> {
        let mut metrics = self.system_metrics.lock();
        
        // CPU usage (simplified - would use proper system calls in production)
        metrics.cpu_usage_percent = self.get_cpu_usage().await;
        
        // Memory usage
        let (used, available) = self.get_memory_usage().await;
        metrics.memory_usage_bytes = used;
        metrics.memory_available_bytes = available;
        
        // Disk usage
        let (used, available) = self.get_disk_usage().await;
        metrics.disk_usage_bytes = used;
        metrics.disk_available_bytes = available;
        
        // Network stats
        let (sent, received) = self.get_network_stats().await;
        metrics.network_bytes_sent = sent;
        metrics.network_bytes_received = received;
        
        // File descriptors
        metrics.open_file_descriptors = self.get_open_fds().await;
        
        Ok(())
    }

    /// Get CPU usage percentage
    async fn get_cpu_usage(&self) -> f64 {
        // In a real implementation, this would read from /proc/stat or use system APIs
        // For now, return a mock value
        rand::random::<f64>() * 100.0
    }

    /// Get memory usage in bytes
    async fn get_memory_usage(&self) -> (u64, u64) {
        // In a real implementation, this would read from /proc/meminfo
        // For now, return mock values
        let used = 1024 * 1024 * 512; // 512 MB
        let available = 1024 * 1024 * 1024; // 1 GB
        (used, available)
    }

    /// Get disk usage in bytes
    async fn get_disk_usage(&self) -> (u64, u64) {
        // In a real implementation, this would use statvfs or similar
        // For now, return mock values
        let used = 1024 * 1024 * 1024 * 10; // 10 GB
        let available = 1024 * 1024 * 1024 * 50; // 50 GB
        (used, available)
    }

    /// Get network statistics
    async fn get_network_stats(&self) -> (u64, u64) {
        // In a real implementation, this would read from /proc/net/dev
        // For now, return mock values
        (1024 * 1024, 1024 * 512) // 1MB sent, 512KB received
    }

    /// Get number of open file descriptors
    async fn get_open_fds(&self) -> u64 {
        // In a real implementation, this would count files in /proc/self/fd
        // For now, return a mock value
        100
    }

    /// Update uptime metric
    fn update_uptime(&self) {
        let mut metrics = self.system_metrics.lock();
        metrics.uptime_seconds = self.start_time.elapsed().as_secs();
    }

    /// Increment a counter
    pub fn increment_counter(&self, name: &str, value: u64) {
        self.counters.entry(name.to_string())
            .and_modify(|v| *v += value)
            .or_insert(value);
    }

    /// Set a gauge value
    pub fn set_gauge(&self, name: &str, value: f64) {
        self.gauges.insert(name.to_string(), value);
    }

    /// Record a histogram observation
    pub fn record_histogram(&self, name: &str, value: f64) {
        self.histograms.entry(name.to_string())
            .and_modify(|h| h.observe(value))
            .or_insert_with(|| {
                let mut h = Histogram::new(vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
                ]);
                h.observe(value);
                h
            });
    }

    /// Record transaction processing time
    pub fn record_transaction_time(&self, duration: Duration) {
        let ms = duration.as_millis() as f64;
        self.record_histogram("transaction_duration_ms", ms);
        
        // Update application metrics
        let mut metrics = self.app_metrics.lock();
        metrics.transactions_processed += 1;
        metrics.avg_transaction_time_ms = 
            (metrics.avg_transaction_time_ms * (metrics.transactions_processed - 1) as f64 + ms) 
            / metrics.transactions_processed as f64;
    }

    /// Record agent decision time
    pub fn record_agent_decision_time(&self, duration: Duration) {
        let ms = duration.as_millis() as f64;
        self.record_histogram("agent_decision_duration_ms", ms);
        
        let mut metrics = self.app_metrics.lock();
        metrics.agent_decisions_made += 1;
    }

    /// Update cache hit ratio
    pub fn update_cache_hit_ratio(&self, hits: u64, total: u64) {
        let mut metrics = self.app_metrics.lock();
        metrics.cache_hit_ratio = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };
    }

    /// Record an error
    pub fn record_error(&self, error_type: &str) {
        self.increment_counter(&format!("errors_{}", error_type), 1);
        
        let mut metrics = self.app_metrics.lock();
        metrics.error_count += 1;
    }

    /// Get all metrics as JSON
    pub fn get_all_metrics(&self) -> serde_json::Value {
        let system = self.system_metrics.lock().clone();
        let app = self.app_metrics.lock().clone();
        
        let counters: std::collections::HashMap<String, u64> = 
            self.counters.iter().map(|entry| (entry.key().clone(), *entry.value())).collect();
        
        let gauges: std::collections::HashMap<String, f64> = 
            self.gauges.iter().map(|entry| (entry.key().clone(), *entry.value())).collect();
        
        let histograms: std::collections::HashMap<String, serde_json::Value> = 
            self.histograms.iter().map(|entry| {
                let hist = entry.value();
                let hist_data = serde_json::json!({
                    "count": hist.count,
                    "sum": hist.sum,
                    "p50": hist.quantile(0.5),
                    "p95": hist.quantile(0.95),
                    "p99": hist.quantile(0.99)
                });
                (entry.key().clone(), hist_data)
            }).collect();
        
        serde_json::json!({
            "system": system,
            "application": app,
            "counters": counters,
            "gauges": gauges,
            "histograms": histograms
        })
    }

    /// Start Prometheus metrics server
    async fn start_prometheus_server(&self) {
        use hyper::{Body, Request, Response, Server, Method, StatusCode};
        use hyper::service::{make_service_fn, service_fn};
        use std::convert::Infallible;
        use std::net::SocketAddr;

        let collector = self.clone();
        
        let make_svc = make_service_fn(move |_conn| {
            let collector = collector.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let collector = collector.clone();
                    async move {
                        match (req.method(), req.uri().path()) {
                            (&Method::GET, "/metrics") => {
                                let metrics = collector.get_prometheus_metrics();
                                Ok(Response::new(Body::from(metrics)))
                            }
                            (&Method::GET, "/health") => {
                                Ok(Response::new(Body::from("OK")))
                            }
                            _ => {
                                let mut not_found = Response::new(Body::from("Not Found"));
                                *not_found.status_mut() = StatusCode::NOT_FOUND;
                                Ok(not_found)
                            }
                        }
                    }
                }))
            }
        });

        let addr = SocketAddr::from(([127, 0, 0, 1], self.config.performance.metrics_port));
        let server = Server::bind(&addr).serve(make_svc);

        tracing::info!("Metrics server listening on http://{}", addr);

        if let Err(e) = server.await {
            tracing::error!("Metrics server error: {}", e);
        }
    }

    /// Get metrics in Prometheus format
    fn get_prometheus_metrics(&self) -> String {
        let mut output = String::new();
        
        // System metrics
        let system = self.system_metrics.lock();
        output.push_str(&format!("# HELP cpu_usage_percent CPU usage percentage\n"));
        output.push_str(&format!("# TYPE cpu_usage_percent gauge\n"));
        output.push_str(&format!("cpu_usage_percent {}\n", system.cpu_usage_percent));
        
        output.push_str(&format!("# HELP memory_usage_bytes Memory usage in bytes\n"));
        output.push_str(&format!("# TYPE memory_usage_bytes gauge\n"));
        output.push_str(&format!("memory_usage_bytes {}\n", system.memory_usage_bytes));
        
        // Application metrics
        let app = self.app_metrics.lock();
        output.push_str(&format!("# HELP transactions_processed_total Total transactions processed\n"));
        output.push_str(&format!("# TYPE transactions_processed_total counter\n"));
        output.push_str(&format!("transactions_processed_total {}\n", app.transactions_processed));
        
        // Custom counters
        for entry in &self.counters {
            let name = entry.key();
            let value = entry.value();
            output.push_str(&format!("# HELP {} Custom counter\n", name));
            output.push_str(&format!("# TYPE {} counter\n", name));
            output.push_str(&format!("{} {}\n", name, value));
        }
        
        // Custom gauges
        for entry in &self.gauges {
            let name = entry.key();
            let value = entry.value();
            output.push_str(&format!("# HELP {} Custom gauge\n", name));
            output.push_str(&format!("# TYPE {} gauge\n", name));
            output.push_str(&format!("{} {}\n", name, value));
        }
        
        output
    }
}

impl Clone for MetricsCollector {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            system_metrics: Arc::clone(&self.system_metrics),
            app_metrics: Arc::clone(&self.app_metrics),
            counters: self.counters.clone(),
            gauges: self.gauges.clone(),
            histograms: self.histograms.clone(),
            start_time: self.start_time,
        }
    }
}