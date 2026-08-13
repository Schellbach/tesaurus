//! Core B facts → policy [`ChainView`].
//!
//! tesaurus-agent is the production constructor. Policy cannot defend against
//! a lying view; this module must fill fields from Core B (or a test double of
//! that RPC boundary), never from coordinator claims or `from_test_facts`.

use bitcoin::{Amount, BlockHash, Network, OutPoint, ScriptBuf};
use tesaurus_policy::{ChainView, PrevoutFact};

use crate::error::AgentError;

/// Chain-wide Core B snapshot used to assemble [`ChainView`].
#[derive(Debug, Clone)]
pub struct CoreBChainInfo {
    pub network: Network,
    pub genesis_hash: BlockHash,
    pub tip_height: u32,
    pub initial_block_download: bool,
}

/// Confirmed unspent output as reported by Core B `gettxout` (mempool excluded).
#[derive(Debug, Clone)]
pub struct CoreBUnspent {
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
    pub confirmations: u32,
}

/// Independent chain oracle (live bitcoind or a test double at this boundary).
pub trait CoreB {
    fn chain_info(&self) -> Result<CoreBChainInfo, AgentError>;
    fn get_tx_out(&self, outpoint: OutPoint) -> Result<Option<CoreBUnspent>, AgentError>;
    fn header_time_unix(&self, height: u32) -> Result<u64, AgentError>;
}

/// Production constructor: map Core B RPC (or a mock of that RPC) into the
/// policy [`ChainView`]. Missing/unconfirmed prevouts are omitted so
/// `evaluate` rejects with `PREVOUT_MISSING` rather than inventing facts.
pub fn chain_view_from_core_b<C: CoreB>(
    core: &C,
    outpoints: &[OutPoint],
    now_unix: u64,
) -> Result<ChainView, AgentError> {
    let info = core.chain_info()?;
    if info.network == Network::Bitcoin {
        return Err(AgentError::Mainnet);
    }
    if !matches!(
        info.network,
        Network::Regtest | Network::Testnet | Network::Signet
    ) {
        return Err(AgentError::config(format!(
            "Core B network {} is not enabled",
            info.network
        )));
    }
    if info.initial_block_download {
        return Err(AgentError::InitialBlockDownload);
    }

    let mut prevouts = Vec::with_capacity(outpoints.len());
    let mut seen = Vec::with_capacity(outpoints.len());
    for &outpoint in outpoints {
        if seen.contains(&outpoint) {
            continue;
        }
        seen.push(outpoint);
        let Some(utxo) = core.get_tx_out(outpoint)? else {
            continue;
        };
        if utxo.confirmations == 0 {
            continue;
        }
        let confirm_height = info
            .tip_height
            .checked_add(1)
            .and_then(|t| t.checked_sub(utxo.confirmations))
            .ok_or_else(|| {
                AgentError::chain(format!(
                    "confirmations {} exceed tip {}",
                    utxo.confirmations, info.tip_height
                ))
            })?;
        let header_time_unix = core.header_time_unix(confirm_height)?;
        prevouts.push(PrevoutFact::from_agent_tcb(
            outpoint,
            utxo.value,
            utxo.script_pubkey,
            confirm_height,
            header_time_unix,
            true,
        ));
    }

    Ok(ChainView::from_agent_tcb(
        info.genesis_hash,
        info.tip_height,
        now_unix,
        prevouts,
    ))
}

/// Extension so agent code can write `ChainView::from_core_b(...)`.
///
/// This trait lives here, not on `tesaurus-policy`, so the policy crate has no
/// `from_core_b` that anyone can call with fake facts.
pub trait ChainViewFromCoreB {
    fn from_core_b<C: CoreB>(
        core: &C,
        outpoints: &[OutPoint],
        now_unix: u64,
    ) -> Result<ChainView, AgentError>;
}

impl ChainViewFromCoreB for ChainView {
    fn from_core_b<C: CoreB>(
        core: &C,
        outpoints: &[OutPoint],
        now_unix: u64,
    ) -> Result<ChainView, AgentError> {
        chain_view_from_core_b(core, outpoints, now_unix)
    }
}

#[cfg(test)]
pub(crate) fn empty_regtest_core(pin: &tesaurus_policy::AgentPin) -> MockCoreB {
    MockCoreB {
        info: CoreBChainInfo {
            network: bitcoin::Network::Regtest,
            genesis_hash: pin.genesis_hash(),
            tip_height: 1,
            initial_block_download: false,
        },
        utxos: Vec::new(),
        headers: Vec::new(),
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct MockCoreB {
    pub info: CoreBChainInfo,
    pub utxos: Vec<(OutPoint, CoreBUnspent)>,
    pub headers: Vec<(u32, u64)>,
}

#[cfg(test)]
impl CoreB for MockCoreB {
    fn chain_info(&self) -> Result<CoreBChainInfo, AgentError> {
        Ok(self.info.clone())
    }

    fn get_tx_out(&self, outpoint: OutPoint) -> Result<Option<CoreBUnspent>, AgentError> {
        Ok(self
            .utxos
            .iter()
            .find(|(op, _)| *op == outpoint)
            .map(|(_, u)| u.clone()))
    }

    fn header_time_unix(&self, height: u32) -> Result<u64, AgentError> {
        self.headers
            .iter()
            .find(|(h, _)| *h == height)
            .map(|(_, t)| *t)
            .ok_or_else(|| AgentError::chain(format!("missing header at height {height}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::{Psbt, PsbtSighashType};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::sighash::EcdsaSighashType;
    use bitcoin::{
        absolute::LockTime, Address, CompressedPublicKey, Network, PrivateKey, PublicKey,
        ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin::{blockdata::transaction::Version, OutPoint};
    use tesaurus_policy::{
        evaluate, AgentAuth, AgentPin, PolicyErrorCode, PolicyOutcome, PolicyRequest, ReplayStore,
    };

    struct Keys {
        secp: Secp256k1<bitcoin::secp256k1::All>,
        primary: SecretKey,
        override_sk: SecretKey,
        agent: SecretKey,
    }

    impl Keys {
        fn new() -> Self {
            Self {
                secp: Secp256k1::new(),
                primary: sk(1),
                override_sk: sk(2),
                agent: sk(3),
            }
        }

        fn pin(&self) -> AgentPin {
            AgentPin::provision(
                Network::Regtest,
                self.pk(&self.primary),
                self.pk(&self.override_sk),
                self.pk(&self.agent),
                10,
            )
            .unwrap()
        }

        fn pk(&self, sk: &SecretKey) -> PublicKey {
            PublicKey::from_private_key(&self.secp, &PrivateKey::new(*sk, Network::Regtest))
        }
    }

    fn sk(seed: u8) -> SecretKey {
        let mut buf = [seed; 32];
        buf[31] = seed.wrapping_add(3);
        SecretKey::from_slice(&buf).unwrap()
    }

    fn dest_script() -> ScriptBuf {
        let pk = PublicKey::from_private_key(
            &Secp256k1::new(),
            &PrivateKey::new(sk(9), Network::Regtest),
        );
        let cpk = CompressedPublicKey::try_from(pk).unwrap();
        Address::p2wpkh(&cpk, Network::Regtest).script_pubkey()
    }

    fn outpoint(n: u8) -> OutPoint {
        let mut txid = [0u8; 32];
        txid[0] = n;
        OutPoint {
            txid: Txid::from_byte_array(txid),
            vout: 0,
        }
    }

    struct SpendParts {
        value: u64,
        op: OutPoint,
        external: u64,
        change: u64,
    }

    fn default_spend() -> SpendParts {
        SpendParts {
            value: 20_000_000,
            op: outpoint(7),
            external: 1_000_000,
            change: 18_999_000,
        }
    }

    fn build_psbt(pin: &AgentPin, parts: &SpendParts, script: ScriptBuf) -> (Psbt, Vec<u8>) {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: parts.op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(pin.csv_blocks() as u16),
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(parts.external),
                    script_pubkey: dest_script(),
                },
                TxOut {
                    value: Amount::from_sat(parts.change),
                    script_pubkey: pin.script_pubkey().clone(),
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(parts.value),
            script_pubkey: script,
        });
        psbt.inputs[0].witness_script = Some(pin.witness_script().clone());
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
        let bytes = psbt.serialize();
        (psbt, bytes)
    }

    fn mature_mock(pin: &AgentPin, parts: &SpendParts, script: ScriptBuf) -> (MockCoreB, u64) {
        let need = pin.csv_blocks() + pin.safety_margin();
        let confirm_height = 1u32;
        let tip = confirm_height + need - 1;
        let t0 = 1_700_000_000_u64;
        let now = t0 + u64::from(need) * pin.wall_clock_seconds_per_block();
        let confirmations = tip - confirm_height + 1;
        let mock = MockCoreB {
            info: CoreBChainInfo {
                network: Network::Regtest,
                genesis_hash: pin.genesis_hash(),
                tip_height: tip,
                initial_block_download: false,
            },
            utxos: vec![(
                parts.op,
                CoreBUnspent {
                    value: Amount::from_sat(parts.value),
                    script_pubkey: script,
                    confirmations,
                },
            )],
            headers: vec![(confirm_height, t0)],
        };
        (mock, now)
    }

    fn eval_err(
        pin: &AgentPin,
        bytes: &[u8],
        claimed: u64,
        chain: &ChainView,
        store: &ReplayStore,
    ) -> tesaurus_policy::PolicyError {
        evaluate(
            pin,
            &PolicyRequest {
                request_id: [1u8; 16],
                psbt_bytes: bytes,
                confirm_token: None,
                claimed_external_sats: claimed,
            },
            AgentAuth::for_test_verified(),
            chain,
            store,
            &[],
        )
        .unwrap_err()
    }

    fn eval_ok(
        pin: &AgentPin,
        bytes: &[u8],
        claimed: u64,
        chain: &ChainView,
        store: &ReplayStore,
    ) -> PolicyOutcome {
        evaluate(
            pin,
            &PolicyRequest {
                request_id: [1u8; 16],
                psbt_bytes: bytes,
                confirm_token: None,
                claimed_external_sats: claimed,
            },
            AgentAuth::for_test_verified(),
            chain,
            store,
            &[],
        )
        .unwrap()
    }

    #[test]
    fn core_b_facts_populate_csv_and_evaluate_ok() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (_psbt, bytes) = build_psbt(&pin, &parts, pin.script_pubkey().clone());
        let (mock, now) = mature_mock(&pin, &parts, pin.script_pubkey().clone());
        let view = ChainView::from_core_b(&mock, &[parts.op], now).unwrap();
        assert_eq!(view.genesis_hash(), pin.genesis_hash());
        assert_eq!(view.tip_height(), mock.info.tip_height);
        assert_eq!(view.prevouts().len(), 1);
        let fact = &view.prevouts()[0];
        assert_eq!(fact.outpoint(), parts.op);
        assert_eq!(fact.value(), Amount::from_sat(parts.value));
        assert_eq!(fact.script_pubkey(), pin.script_pubkey());
        assert!(fact.visible_unspent());
        match eval_ok(&pin, &bytes, parts.external, &view, &store) {
            PolicyOutcome::ValidatedUnsigned { amounts, .. } => {
                assert_eq!(amounts.external_sats, parts.external);
            }
            PolicyOutcome::Idempotent { .. } => panic!("expected ValidatedUnsigned"),
        }
    }

    #[test]
    fn immature_core_b_confirmations_reject_csv() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (_psbt, bytes) = build_psbt(&pin, &parts, pin.script_pubkey().clone());
        let (mut mock, now) = mature_mock(&pin, &parts, pin.script_pubkey().clone());
        mock.utxos[0].1.confirmations = 2;
        mock.headers = vec![(mock.info.tip_height + 1 - 2, 1_700_000_000)];
        let view = ChainView::from_core_b(&mock, &[parts.op], now).unwrap();
        let err = eval_err(&pin, &bytes, parts.external, &view, &store);
        assert_eq!(err.code, PolicyErrorCode::CsvImmatureDepth);
    }

    #[test]
    fn missing_prevout_is_rejected() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (_psbt, bytes) = build_psbt(&pin, &parts, pin.script_pubkey().clone());
        let (mut mock, now) = mature_mock(&pin, &parts, pin.script_pubkey().clone());
        mock.utxos.clear();
        let view = ChainView::from_core_b(&mock, &[parts.op], now).unwrap();
        assert!(view.prevouts().is_empty());
        let err = eval_err(&pin, &bytes, parts.external, &view, &store);
        assert_eq!(err.code, PolicyErrorCode::PrevoutMissing);
    }

    #[test]
    fn disagreeing_prevout_amount_is_rejected() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let (_psbt, bytes) = build_psbt(&pin, &parts, pin.script_pubkey().clone());
        let (mut mock, now) = mature_mock(&pin, &parts, pin.script_pubkey().clone());
        mock.utxos[0].1.value = Amount::from_sat(parts.value - 1);
        let view = ChainView::from_core_b(&mock, &[parts.op], now).unwrap();
        let err = eval_err(&pin, &bytes, parts.external, &view, &store);
        assert_eq!(err.code, PolicyErrorCode::PrevoutMismatch);
    }

    #[test]
    fn foreign_input_from_core_b_is_rejected() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let foreign = dest_script();
        let (_psbt, bytes) = build_psbt(&pin, &parts, foreign.clone());
        let (mock, now) = mature_mock(&pin, &parts, foreign);
        let view = ChainView::from_core_b(&mock, &[parts.op], now).unwrap();
        assert_ne!(view.prevouts()[0].script_pubkey(), pin.script_pubkey());
        let err = eval_err(&pin, &bytes, parts.external, &view, &store);
        assert_eq!(err.code, PolicyErrorCode::ForeignInput);
    }

    #[test]
    fn mainnet_and_ibd_fail_closed() {
        let keys = Keys::new();
        let pin = keys.pin();
        let parts = default_spend();
        let (mut mock, now) = mature_mock(&pin, &parts, pin.script_pubkey().clone());
        mock.info.network = Network::Bitcoin;
        assert!(matches!(
            ChainView::from_core_b(&mock, &[parts.op], now),
            Err(AgentError::Mainnet)
        ));
        mock.info.network = Network::Regtest;
        mock.info.initial_block_download = true;
        assert!(matches!(
            ChainView::from_core_b(&mock, &[parts.op], now),
            Err(AgentError::InitialBlockDownload)
        ));
    }
}
