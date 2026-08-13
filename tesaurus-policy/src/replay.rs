//! Durable replay store (D4 + Aldo R1).
//!
//! Indexed by `request_id` **and** spent outpoints. Missing or corrupt store
//! refuses to proceed (no signing). Retention is the vault lifetime of the
//! AgentPin; this crate does not time-prune.
//!
//! `replay_id = SHA256(request_id || psbt_txid || psbt_content_hash)`
//!
//! 1. First success: persist the record **before** returning Ok.
//! 2. Same `request_id` + same `replay_id` → idempotent cached Ok (honest retry).
//! 3. Same `request_id` + different `replay_id` → `REPLAY_CONFLICT`.
//! 4. Same outpoints already signed with different outputs → `REPLAY`.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{OutPoint, TxOut};
use serde::{Deserialize, Serialize};

use crate::error::{PolicyError, PolicyErrorCode, PolicyResult};

const STORE_VERSION_TAG: &str = "TESAURUS_REPLAY_V1\n";
const RECORDS_FILE: &str = "records.json";
const VERSION_FILE: &str = "VERSION";

pub fn psbt_content_hash(psbt_bytes: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(psbt_bytes).to_byte_array()
}

pub fn replay_id(
    request_id: &[u8; 16],
    psbt_txid: &[u8; 32],
    psbt_content_hash: &[u8; 32],
) -> [u8; 32] {
    let mut buf = [0u8; 16 + 32 + 32];
    buf[..16].copy_from_slice(request_id);
    buf[16..48].copy_from_slice(psbt_txid);
    buf[48..].copy_from_slice(psbt_content_hash);
    sha256::Hash::hash(&buf).to_byte_array()
}

pub fn outputs_commitment(outputs: &[TxOut]) -> PolicyResult<[u8; 32]> {
    let mut buf = Vec::new();
    for txout in outputs {
        txout.consensus_encode(&mut buf).map_err(|e| {
            PolicyError::new(
                PolicyErrorCode::Internal,
                format!("failed to encode output for replay commitment: {e}"),
            )
        })?;
    }
    Ok(sha256::Hash::hash(&buf).to_byte_array())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRecord {
    pub request_id: [u8; 16],
    pub replay_id: [u8; 32],
    pub psbt_txid: [u8; 32],
    pub outpoints: Vec<OutPoint>,
    pub outputs_commitment: [u8; 32],
    pub signed_psbt_or_partial: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// Persist this record, then return Ok to the caller.
    Fresh,
    /// Honest retry: return the previously stored payload. Do not re-sign.
    Idempotent { signed_psbt_or_partial: Vec<u8> },
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredFile {
    version: u32,
    records: Vec<StoredRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRecord {
    request_id: String,
    replay_id: String,
    psbt_txid: String,
    outpoints: Vec<String>,
    outputs_commitment: String,
    signed_psbt_or_partial: String,
}

#[derive(Debug)]
pub struct ReplayStore {
    dir: PathBuf,
    records: Vec<ReplayRecord>,
}

impl ReplayStore {
    /// Create a new empty store. Fails if `dir` already has a VERSION file.
    pub fn init(dir: impl AsRef<Path>) -> PolicyResult<Self> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(io_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io_err)?;
        }
        let version_path = dir.join(VERSION_FILE);
        if version_path.exists() {
            return Err(PolicyError::new(
                PolicyErrorCode::Internal,
                format!("replay store already initialized at {}", dir.display()),
            ));
        }
        write_private_fsynced(&version_path, STORE_VERSION_TAG.as_bytes())?;
        persist_records(dir, &[])?;
        fsync_dir(dir)?;
        Self::open(dir)
    }

    /// Open an existing store. Missing or corrupt data refuses all further use.
    pub fn open(dir: impl AsRef<Path>) -> PolicyResult<Self> {
        let dir = dir.as_ref();
        if !dir.is_dir() {
            return Err(PolicyError::new(
                PolicyErrorCode::Internal,
                format!("replay store missing at {}", dir.display()),
            ));
        }
        let version = read_file(&dir.join(VERSION_FILE))?;
        if String::from_utf8_lossy(&version).trim() != STORE_VERSION_TAG.trim() {
            return Err(PolicyError::new(
                PolicyErrorCode::Internal,
                "replay store VERSION is missing or corrupt",
            ));
        }
        let raw = read_file(&dir.join(RECORDS_FILE))?;
        let stored: StoredFile = serde_json::from_slice(&raw).map_err(|e| {
            PolicyError::new(
                PolicyErrorCode::Internal,
                format!("replay store records are corrupt: {e}"),
            )
        })?;
        if stored.version != 1 {
            return Err(PolicyError::new(
                PolicyErrorCode::Internal,
                format!("unsupported replay store version {}", stored.version),
            ));
        }
        let records = stored
            .records
            .into_iter()
            .map(ReplayRecord::from_stored)
            .collect::<PolicyResult<Vec<_>>>()?;
        if overlapping_outpoints_inconsistent(&records) {
            return Err(PolicyError::new(
                PolicyErrorCode::Internal,
                "replay store outpoint index is inconsistent",
            ));
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            records,
        })
    }

    pub fn preflight(&self, candidate: &ReplayRecord) -> PolicyResult<ReplayVerdict> {
        if let Some(existing) = self
            .records
            .iter()
            .find(|r| r.request_id == candidate.request_id)
        {
            if existing.replay_id == candidate.replay_id {
                return Ok(ReplayVerdict::Idempotent {
                    signed_psbt_or_partial: existing.signed_psbt_or_partial.clone(),
                });
            }
            return Err(PolicyError::new(
                PolicyErrorCode::ReplayConflict,
                "same request_id with a different replay_id",
            ));
        }

        for existing in &self.records {
            if outpoints_overlap(&existing.outpoints, &candidate.outpoints)
                && existing.outputs_commitment != candidate.outputs_commitment
            {
                return Err(PolicyError::new(
                    PolicyErrorCode::Replay,
                    "spent outpoints already signed with different outputs",
                ));
            }
            if outpoints_overlap(&existing.outpoints, &candidate.outpoints) {
                return Err(PolicyError::new(
                    PolicyErrorCode::Replay,
                    "spent outpoints already signed",
                ));
            }
        }
        Ok(ReplayVerdict::Fresh)
    }

    /// Persist `record` before the caller returns Ok. Idempotent retries return
    /// the cached payload without rewriting a conflicting body.
    pub fn commit(&mut self, record: ReplayRecord) -> PolicyResult<ReplayVerdict> {
        match self.preflight(&record)? {
            ReplayVerdict::Idempotent {
                signed_psbt_or_partial,
            } => Ok(ReplayVerdict::Idempotent {
                signed_psbt_or_partial,
            }),
            ReplayVerdict::Fresh => {
                self.records.push(record);
                persist_records(&self.dir, &self.records)?;
                fsync_dir(&self.dir)?;
                Ok(ReplayVerdict::Fresh)
            }
        }
    }
}

fn overlapping_outpoints_inconsistent(records: &[ReplayRecord]) -> bool {
    let mut seen: HashSet<OutPoint> = HashSet::new();
    for record in records {
        for op in &record.outpoints {
            if !seen.insert(*op) {
                return true;
            }
        }
    }
    false
}

fn outpoints_overlap(a: &[OutPoint], b: &[OutPoint]) -> bool {
    let set: HashSet<_> = a.iter().copied().collect();
    b.iter().any(|op| set.contains(op))
}

fn persist_records(dir: &Path, records: &[ReplayRecord]) -> PolicyResult<()> {
    let stored = StoredFile {
        version: 1,
        records: records.iter().map(ReplayRecord::to_stored).collect(),
    };
    let json = serde_json::to_vec_pretty(&stored).map_err(|e| {
        PolicyError::new(
            PolicyErrorCode::Internal,
            format!("failed to serialize replay store: {e}"),
        )
    })?;
    let final_path = dir.join(RECORDS_FILE);
    let tmp_path = dir.join("records.json.tmp");
    write_private_fsynced(&tmp_path, &json)?;
    fs::rename(&tmp_path, &final_path).map_err(io_err)?;
    Ok(())
}

fn write_private_fsynced(path: &Path, contents: &[u8]) -> PolicyResult<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(io_err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_err)?;
    }
    file.write_all(contents).map_err(io_err)?;
    file.sync_all().map_err(io_err)?;
    Ok(())
}

fn fsync_dir(dir: &Path) -> PolicyResult<()> {
    let file = File::open(dir).map_err(io_err)?;
    file.sync_all().map_err(io_err)
}

fn read_file(path: &Path) -> PolicyResult<Vec<u8>> {
    let mut file = File::open(path).map_err(|e| {
        PolicyError::new(
            PolicyErrorCode::Internal,
            format!(
                "replay store file {} missing or unreadable: {e}",
                path.display()
            ),
        )
    })?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(io_err)?;
    Ok(buf)
}

fn io_err(err: std::io::Error) -> PolicyError {
    PolicyError::new(
        PolicyErrorCode::Internal,
        format!("replay store I/O: {err}"),
    )
}

fn hex_array<const N: usize>(hex: &str, field: &str) -> PolicyResult<[u8; N]> {
    let bytes = hex::decode(hex).map_err(|e| {
        PolicyError::new(
            PolicyErrorCode::Internal,
            format!("corrupt {field} hex: {e}"),
        )
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        PolicyError::new(
            PolicyErrorCode::Internal,
            format!("corrupt {field}: expected {N} bytes, got {}", bytes.len()),
        )
    })
}

impl ReplayRecord {
    fn to_stored(&self) -> StoredRecord {
        StoredRecord {
            request_id: hex::encode(self.request_id),
            replay_id: hex::encode(self.replay_id),
            psbt_txid: hex::encode(self.psbt_txid),
            outpoints: self.outpoints.iter().map(ToString::to_string).collect(),
            outputs_commitment: hex::encode(self.outputs_commitment),
            signed_psbt_or_partial: hex::encode(&self.signed_psbt_or_partial),
        }
    }

    fn from_stored(stored: StoredRecord) -> PolicyResult<Self> {
        let outpoints = stored
            .outpoints
            .iter()
            .map(|s| {
                s.parse::<OutPoint>().map_err(|e| {
                    PolicyError::new(
                        PolicyErrorCode::Internal,
                        format!("corrupt outpoint {s}: {e}"),
                    )
                })
            })
            .collect::<PolicyResult<Vec<_>>>()?;
        Ok(Self {
            request_id: hex_array(&stored.request_id, "request_id")?,
            replay_id: hex_array(&stored.replay_id, "replay_id")?,
            psbt_txid: hex_array(&stored.psbt_txid, "psbt_txid")?,
            outpoints,
            outputs_commitment: hex_array(&stored.outputs_commitment, "outputs_commitment")?,
            signed_psbt_or_partial: hex::decode(&stored.signed_psbt_or_partial).map_err(|e| {
                PolicyError::new(
                    PolicyErrorCode::Internal,
                    format!("corrupt signed payload hex: {e}"),
                )
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, ScriptBuf};

    fn outpoint(n: u32) -> OutPoint {
        let mut txid = [0u8; 32];
        txid[0] = n as u8;
        OutPoint {
            txid: bitcoin::Txid::from_byte_array(txid),
            vout: n,
        }
    }

    fn commitment(sats: u64) -> [u8; 32] {
        let txout = TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::new(),
        };
        outputs_commitment(&[txout]).unwrap()
    }

    fn record(req: u8, replay: u8, op: u32, sats: u64, payload: &[u8]) -> ReplayRecord {
        let mut request_id = [0u8; 16];
        request_id[0] = req;
        let mut replay_id = [0u8; 32];
        replay_id[0] = replay;
        let mut psbt_txid = [0u8; 32];
        psbt_txid[0] = req;
        ReplayRecord {
            request_id,
            replay_id,
            psbt_txid,
            outpoints: vec![outpoint(op)],
            outputs_commitment: commitment(sats),
            signed_psbt_or_partial: payload.to_vec(),
        }
    }

    #[test]
    fn ci24_idempotent_retry_returns_cached_payload() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = ReplayStore::init(tmp.path()).unwrap();
        let first = record(1, 1, 7, 1000, b"signed-psbt-v1");
        assert_eq!(store.commit(first.clone()).unwrap(), ReplayVerdict::Fresh);

        let retry = store.commit(first.clone()).unwrap();
        assert_eq!(
            retry,
            ReplayVerdict::Idempotent {
                signed_psbt_or_partial: b"signed-psbt-v1".to_vec()
            }
        );

        // Durable across reopen (crash / restart).
        drop(store);
        let store = ReplayStore::open(tmp.path()).unwrap();
        let again = store.preflight(&first).unwrap();
        assert_eq!(
            again,
            ReplayVerdict::Idempotent {
                signed_psbt_or_partial: b"signed-psbt-v1".to_vec()
            }
        );
    }

    #[test]
    fn ci24_replay_conflict_same_request_different_psbt() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = ReplayStore::init(tmp.path()).unwrap();
        store.commit(record(1, 1, 7, 1000, b"a")).unwrap();
        let err = store.commit(record(1, 2, 8, 1000, b"b")).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::ReplayConflict);
    }

    #[test]
    fn ci24_replay_same_outpoints_different_outputs() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = ReplayStore::init(tmp.path()).unwrap();
        store.commit(record(1, 1, 7, 1000, b"a")).unwrap();
        let err = store.commit(record(2, 9, 7, 2000, b"b")).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::Replay);
    }

    #[test]
    fn missing_store_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope");
        let err = ReplayStore::open(&missing).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::Internal);
        assert!(err.message.contains("missing"));
    }

    #[test]
    fn corrupt_store_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        ReplayStore::init(tmp.path()).unwrap();
        fs::write(tmp.path().join(RECORDS_FILE), b"{not json").unwrap();
        let err = ReplayStore::open(tmp.path()).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::Internal);
        assert!(err.message.contains("corrupt"));
    }

    #[test]
    fn replay_id_binds_request_txid_and_content() {
        let rid = [1u8; 16];
        let txid = [2u8; 32];
        let content = psbt_content_hash(b"psbt-bytes");
        let a = replay_id(&rid, &txid, &content);
        let b = replay_id(&rid, &txid, &content);
        assert_eq!(a, b);
        let mut other = txid;
        other[0] ^= 1;
        assert_ne!(a, replay_id(&rid, &other, &content));
        assert_ne!(a, replay_id(&rid, &txid, &psbt_content_hash(b"other")));
    }
}
