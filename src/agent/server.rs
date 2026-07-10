//! HTTP co-signer API for the local agent.

use crate::agent::policy::{AgentPolicy, PolicyContext};
use crate::config::Config;
use crate::descriptor::VaultDescriptor;
use crate::error::{Error, Result};
use crate::keys::{KeyRole, VaultKey};
use crate::spend::{sign_recovery_with_keys, SpendPath, SpendRequest};
use crate::wallet::{VaultState, VaultUtxo};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::{Amount, Network, OutPoint, TxOut};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    agent_key: Arc<VaultKey>,
    policy: AgentPolicy,
    network: Network,
}

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    pub vault_state_path: Option<PathBuf>,
    pub vault: Option<VaultDescriptor>,
    pub spend: SpendRequest,
    /// Primary key WIF (or omit to load from configured keys_dir).
    pub primary_wif: Option<String>,
    pub utxos: Vec<SignUtxo>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SignUtxo {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub confirmations: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub tx_hex: String,
    pub txid: String,
    pub fee_sats: u64,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    role: &'static str,
}

pub async fn run_agent_server(config: Config) -> Result<()> {
    let network = config.network()?;
    let agent_key = VaultKey::from_file(KeyRole::Agent, &config.agent.key_path)?;
    let policy = AgentPolicy::from(&config.agent);
    let bind: SocketAddr = config
        .agent
        .bind
        .parse()
        .map_err(|e| Error::config(format!("invalid agent.bind: {e}")))?;

    let state = AppState {
        config: Arc::new(config),
        agent_key: Arc::new(agent_key),
        policy,
        network,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/sign", post(sign))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    info!("agent co-signer listening on http://{bind}");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::Http(e.to_string()))?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        role: "agent-cosigner",
    })
}

async fn sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SignRequest>,
) -> std::result::Result<Json<SignResponse>, (StatusCode, String)> {
    if let Some(token) = &state.config.agent.api_token {
        let provided = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let expected = format!("Bearer {token}");
        if provided != expected {
            return Err((StatusCode::UNAUTHORIZED, "invalid API token".into()));
        }
    }

    let vault = if let Some(v) = req.vault.clone() {
        v
    } else if let Some(path) = &req.vault_state_path {
        VaultState::load(path)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
            .vault
    } else {
        VaultState::load(&state.config.vault.state_path)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
            .vault
    };

    let min_conf = req
        .utxos
        .iter()
        .map(|u| u.confirmations)
        .min()
        .unwrap_or(0);

    let ctx = PolicyContext {
        network: state.network,
        csv_blocks: vault.csv_blocks,
        min_confirmations: min_conf,
    };

    let mut spend = req.spend.clone();
    spend.path = SpendPath::Recovery;

    state
        .policy
        .check(&spend, &ctx)
        .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;

    let primary = if let Some(wif) = &req.primary_wif {
        VaultKey::from_wif(KeyRole::Primary, wif)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    } else {
        VaultKey::from_file(
            KeyRole::Primary,
            state.config.vault.keys_dir.join("primary.wif"),
        )
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    };

    let script = vault
        .address()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
        .script_pubkey();

    let utxos: Vec<VaultUtxo> = req
        .utxos
        .iter()
        .map(|u| {
            let txid = bitcoin::Txid::from_str(&u.txid)
                .map_err(|e| Error::spend(format!("bad txid: {e}")))?;
            Ok(VaultUtxo {
                outpoint: OutPoint {
                    txid,
                    vout: u.vout,
                },
                txout: TxOut {
                    value: Amount::from_sat(u.amount_sats),
                    script_pubkey: script.clone(),
                },
                confirmations: u.confirmations,
                spendable_primary: true,
                spendable_recovery: u.confirmations >= vault.csv_blocks,
            })
        })
        .collect::<Result<Vec<_>>>()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let built = sign_recovery_with_keys(
        &vault,
        state.network,
        &utxos,
        &spend,
        &[primary, (*state.agent_key).clone()],
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(Json(SignResponse {
        tx_hex: built.tx_hex,
        txid: built.txid,
        fee_sats: built.fee_sats,
    }))
}
