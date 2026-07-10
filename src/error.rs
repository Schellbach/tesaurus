//! Tesaurus error types.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("key error: {0}")]
    Key(String),

    #[error("descriptor error: {0}")]
    Descriptor(String),

    #[error("wallet error: {0}")]
    Wallet(String),

    #[error("spend error: {0}")]
    Spend(String),

    #[error("agent policy rejected: {0}")]
    AgentPolicy(String),

    #[error("Bitcoin RPC error: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),

    #[error("Bitcoin error: {0}")]
    Bitcoin(#[from] bitcoin::key::FromWifError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn key(msg: impl Into<String>) -> Self {
        Self::Key(msg.into())
    }

    pub fn descriptor(msg: impl Into<String>) -> Self {
        Self::Descriptor(msg.into())
    }

    pub fn wallet(msg: impl Into<String>) -> Self {
        Self::Wallet(msg.into())
    }

    pub fn spend(msg: impl Into<String>) -> Self {
        Self::Spend(msg.into())
    }

    pub fn agent_policy(msg: impl Into<String>) -> Self {
        Self::AgentPolicy(msg.into())
    }
}
