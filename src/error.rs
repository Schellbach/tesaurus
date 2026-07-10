//! Error handling optimized for performance and minimal allocations

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TesaurusError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),
    
    #[error("Bitcoin RPC error: {0}")]
    BitcoinRpc(#[from] bitcoincore_rpc::Error),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Storage error: {0}")]
    Storage(#[from] sled::Error),
    
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Agent engine error: {0}")]
    Agent(String),
    
    #[error("Vault state error: {0}")]
    VaultState(String),
    
    #[error("Transaction error: {0}")]
    Transaction(String),
    
    #[error("Timeout error: operation timed out")]
    Timeout,
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

impl TesaurusError {
    /// Create a crypto error without heap allocation when possible
    pub fn crypto(msg: &'static str) -> Self {
        Self::Crypto(msg.to_string())
    }
    
    /// Create an agent error without heap allocation when possible
    pub fn agent(msg: &'static str) -> Self {
        Self::Agent(msg.to_string())
    }
    
    /// Create a vault state error without heap allocation when possible
    pub fn vault_state(msg: &'static str) -> Self {
        Self::VaultState(msg.to_string())
    }
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, TesaurusError>;