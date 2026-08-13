//! Agent-side errors. Not policy reject codes; construction fails closed
//! before `evaluate` when Core B cannot be trusted.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("mainnet Core B is disabled")]
    Mainnet,
    #[error("Core B is in initial block download; refusing chain view")]
    InitialBlockDownload,
    #[error("bitcoin RPC URL must use plain HTTP on 127.0.0.1 or [::1]")]
    RpcUrlNotLoopback,
    #[error("Core B RPC auth required: set cookie_path or rpc_user/rpc_password")]
    RpcAuthMissing,
    #[error("Core B network {actual} does not match configured network {expected}")]
    NetworkMismatch {
        expected: bitcoin::Network,
        actual: bitcoin::Network,
    },
    #[error("Core B chain error: {0}")]
    Chain(String),
    #[error("Core B RPC: {0}")]
    Rpc(String),
    #[error("configuration error: {0}")]
    Config(String),
}

impl AgentError {
    pub fn chain(msg: impl Into<String>) -> Self {
        Self::Chain(msg.into())
    }

    pub fn rpc(msg: impl Into<String>) -> Self {
        Self::Rpc(msg.into())
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
}
