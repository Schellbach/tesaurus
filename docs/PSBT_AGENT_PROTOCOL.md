# Tesaurus PSBT-only agent protocol

**Status:** gate 1 design **ACCEPTED for implementation** (Aldo 2026-08-11;
D1–D5 closed).

**Hard rule:** Do **not** unlock `--via-agent` and do **not** restore HTTP
co-signing until implementation **and** the Security CI matrix in §10 are green
and reviewed. Until then, `tesaurus-agent` and `--via-agent` remain fail-closed.

Threat model (gate 0 ACCEPTED): [`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## 1. Goals

1. Replace the removed HTTP co-signer with a PSBT-only protocol that never
   transports private-key material.
2. Let an owner-operated agent add **at most one** partial signature for the
   pinned agent key after CSV maturity.
3. Enforce structure, foreign-input, recovery-path, amount, velocity, confirm,
   replay, and fee-bump policies on every request.
4. Verify chain state on **Core B**, independent of the coordinator’s Core A.
5. Keep research containment green until an explicit, reviewed unlock.

## 2. Non-goals

- Unlocking `--via-agent` in this documentation PR
- Restoring any HTTP JSON API that accepts WIFs or caller-trusted UTXO metadata
- Tesaurus-hosted multi-tenant agents (deferred)
- Liana wire compatibility (deferred)
- PSBT v2 (locked to v0 for gate 1)
- Agent custody of primary or override keys
- Automatic broadcast by the agent (coordinator broadcasts via Core A)

---

## 3. Locked parameters

| Parameter | Value |
|---|---|
| Descriptor policy | `thresh(2, pk(primary), pk(override), and(pk(agent), older(csv)))` |
| `csv_blocks` | `4320` |
| `safety_margin` | `1008` |
| `WALL_CLOCK_SECONDS_PER_BLOCK` | `600` (~37d intentional with csv+margin) |
| Velocity / signature | `10_000_000` sats |
| Velocity / 144 blocks | `50_000_000` sats |
| Confirm threshold (D1) | external ≥ `5_000_000` sats requires `confirm_token` |
| PSBT version | v0 |
| Sighash | `SIGHASH_ALL` on every input |
| `nLockTime` | `0` |
| Output shape | exactly one external output + exact vault change (omit change if dust/none per policy) |
| Nodes | Core A (coordinator), Core B (agent) |

---

## 4. Crate split

| Crate / binary | Responsibility |
|---|---|
| **`tesaurus-policy`** | Pure validation: pin checks, PSBT structural rules, amount/fee math, velocity accounting helpers, confirm preimage verify, error codes (`FOREIGN_INPUT`, `NOT_RECOVERY_PATH`, …). No RPC. No key I/O. |
| **`tesaurus-agent`** | Process: load agent key + `AgentPin`, Core B RPC, durable replay store, auth, call policy, sign, return PSBT with partial sig |
| **`tesaurus`** | Coordinator CLI: Core A, build PSBT, obtain HW/override signatures as needed, request agent co-sign, broadcast |

The monolithic research crate may host these as modules initially, but the
**trust split** above is locked: policy code used by the agent must not depend
on coordinator key loading.

---

## 5. AgentPin

At first start (or provision), the agent persists an `AgentPin`:

```text
AgentPin {
  network,                 // research nets until mainnet checklist
  descriptor,              // canonical wsh(thresh(...)) string
  csv_blocks,              // must equal 4320 for production pins
  primary_pubkey,
  override_pubkey,
  agent_pubkey,            // must match loaded agent key
  safety_margin,           // 1008
  velocity_per_sig_sats,   // 10_000_000
  velocity_per_144_sats,   // 50_000_000
  confirm_threshold_sats,  // 5_000_000
  wall_clock_seconds_per_block  // 600
}
```

Any request whose PSBT / metadata disagrees with the pin is rejected. Changing
the pin is an explicit re-provision ceremony, not a per-request field.

---

## 6. Transport API

Local, authenticated request/response (Unix socket or loopback TCP with mutual
auth — exact binding chosen at implementation; **not** the legacy HTTP WIF
protocol).

### 6.0 Request

```text
SignRequest {
  request_id:        opaque unique id (replay key material)
  psbt:              base64 PSBT v0
  auth:              MAC or signature over canonical request bytes
  confirm_token:     optional CompactSize-tagged bytes (see §9 / §15)
  claimed_external_sats: u64   // must match policy-computed external
}
```

### 6.1 Response

```text
SignResponse::Ok { psbt }           // same tx, agent partial sig added
SignResponse::Reject { code, msg }  // stable error codes for CI
```

Stable reject codes include: `AUTH`, `REPLAY`, `PSBT_MALFORMED`,
`PIN_MISMATCH`, `FOREIGN_INPUT`, `NOT_RECOVERY_PATH`, `CSV_IMMATURE`,
`WALL_CLOCK`, `AMOUNT`, `VELOCITY`, `CONFIRM_REQUIRED`, `CONFIRM_INVALID`,
`SIGHASH`, `LOCKTIME`, `FEE_BUMP_DENIED`.

---

## 7. Validation state machine (§6)

Every `SignRequest` runs these stages **in order**. Failure aborts with no
signature and does not advance velocity counters except where noted for durable
replay insertion.

### 6.1 Authentication & durable replay (D4)

1. Verify `auth` over the canonical request encoding.
2. Compute `replay_id = SHA256(request_id || psbt_txid || psbt_content_hash)`.
3. If `replay_id` exists in the durable store → `REPLAY`.
4. Insert `replay_id` **before** signing (fail closed if insert fails).
5. Retention: see §15.2.

### 6.2 PSBT structure

1. Parse PSBT **v0** only.
2. `nLockTime == 0` else `LOCKTIME`.
3. Every input sighash type present and equal to `SIGHASH_ALL` else `SIGHASH`.
4. Output count: one external + optional single change; no other shapes.
5. Fee = sum(inputs) − sum(outputs); must be non-negative and within
   implementation fee bounds (anti DoS); coordinator may be stricter.

### 6.3 Keys & witness UTXO metadata

1. Each input must include witness UTXO (or full prior tx per implementation
   choice locked in code review) sufficient to verify amounts and scripts.
2. Redeem/witness script for each vault input must match the pinned descriptor.

### 6.3b Foreign inputs (D3) → `FOREIGN_INPUT`

Reject if any input:

- does not pay the pinned vault script, or
- is not independently visible as an unspent output on **Core B** with matching
  amount and script.

No non-vault inputs. No unverified inputs.

### 6.3c Recovery path (D2) → `NOT_RECOVERY_PATH`

The agent signs **only** agent-branch recovery co-signing after maturity.
Reject PSBTs that:

- set sequences inconsistent with the CSV branch being used for agent
  satisfaction, or
- include final scripts / partial sigs indicating an attempt to use the agent
  as a substitute on the always-available primary path, or
- otherwise violate the locked rule that agent signatures are for the
  `and(pk(agent), older(csv))` branch participation only.

Primary-path spends (primary + override) never require the agent.

### 6.4 Core B CSV + wall-clock

For every vault input:

1. Query Core B for confirmations / coin age relevant to `older(csv_blocks)`.
2. Require CSV mature: confirmations ≥ `csv_blocks` (4320) per input being
   spent under the agent branch.
3. Wall-clock: require local trustworthy time such that elapsed bound covers
   `(csv_blocks + safety_margin) * WALL_CLOCK_SECONDS_PER_BLOCK`
   since the earliest admissible birth time derived from Core B headers /
   block times for those coins (implementation uses the conservative
   interpretation reviewed in gate 2). Intentional ~37 day bound.
4. Failures → `CSV_IMMATURE` or `WALL_CLOCK`.

### 6.5 Amounts

1. Compute external output value `E` and change value `C`.
2. Change, if present, must pay the **exact** pinned vault script (same
   receive script as pin).
3. `claimed_external_sats` must equal `E`.
4. Reject dust/absurd fees per policy constants → `AMOUNT`.

### 6.6 Velocity

1. `E ≤ 10_000_000` else `VELOCITY`.
2. Sum of externals signed in the trailing 144-block window (Core B tip)
   including this `E` must be ≤ `50_000_000` else `VELOCITY`.
3. On successful signature, record `(tip_height, E, replay_id)` durably.

### 6.6b Confirm token (D1)

If `E ≥ 5_000_000`:

1. `confirm_token` must be present else `CONFIRM_REQUIRED`.
2. Verify per §9 / §15 against the **override** pubkey in the pin else
   `CONFIRM_INVALID`.
3. If `E < 5_000_000`, `confirm_token` must be absent or is ignored
   (implementation picks one; CI locks **external-only** enforcement — see
   §15.3).

### 6.7 Sign

1. Produce agent partial signature(s) for vault inputs with `SIGHASH_ALL`.
2. Return updated PSBT. Do not broadcast.

---

## 8. Coordinator flow

```text
1. Owner builds spend intent (external address, amount).
2. Core A: select vault UTXOs, construct PSBT v0
   (locktime 0, SIGHASH_ALL, one external + exact change).
3. If primary path: collect primary HW + override signatures; broadcast via A.
4. If agent recovery path (after maturity):
   a. Optionally collect primary partial sig first (typical 2-of-3).
   b. If E ≥ 5M: obtain confirm_token from override holder (§9).
   c. Send SignRequest to owner-operated agent.
   d. Agent runs §6 against Core B; returns PSBT or reject.
   e. Finalize and broadcast via Core A.
5. Fee-bump: see §8 (D5) — rebuild/replace PSBT and re-run full agent policy.
```

---

## 9. Fee-bump policy (D5)

Fee-bumps / RBF replacements are **not** a privileged path.

1. Replacement PSBT must pass the **entire** §6 state machine.
2. External destination script and external amount `E` must be identical to the
   replaced intent (fee may rise by reducing change only, or by approved
   pattern locked in implementation tests).
3. Velocity accounting charges the external amount according to the locked rule:
   replacements that do not increase `E` do not double-charge; increases are
   rejected unless they pass velocity as a new `E` (production default:
   **forbid external increases** on bumps).
4. Confirm token: if `E ≥ 5M`, bump requests need a valid `confirm_token`
   binding the bump’s preimage fields (§15), not a reused token from a
   different `psbt_content_hash`.
5. Replay: new `request_id` / content hash required; old ids remain
   non-replayable.

Violations → `FEE_BUMP_DENIED` or the underlying stage code.

---

## 10. Confirm attestation (§9)

`confirm_token` proves the **override** key authorized a specific large
external spend.

### Semantics

- Signature scheme: **ECDSA secp256k1 compact 64-byte** signature
  (RFC6979 deterministic recommended) over `SHA256(preimage)`.
- Verifying key: pin `override_pubkey`.
- Required iff policy-computed external `E ≥ 5_000_000` sats (D1).

### Preimage

Canonical byte layout is locked in **§15.1**. High-level fields:

- domain tag
- network
- descriptor hash
- external script pubkey
- external amount `E`
- change amount `C` (0 if none)
- PSBT txid / content binding
- CSV / pin version fields as specified in §15

The agent verifies the signature; it does not possess the override private key.

---

## 11. Security CI matrix (§10)

Gate 3 lands these as automated fail-closed checks. Design acceptance requires
the matrix to exist as a specification now; documentation-only PRs must not
weaken current containment CI.

| ID | Check | Expected |
|---|---|---|
| CI-01 | `tesaurus-agent` entrypoint without unlock | Exits non-zero; mentions PSBT-only / disabled |
| CI-02 | `--via-agent` on CLI | Fail-closed until reviewed unlock |
| CI-03 | Mainnet config / vault construction | Rejected |
| CI-04 | Unit: `FOREIGN_INPUT` (D3) | Non-vault input rejected |
| CI-05 | Unit: `NOT_RECOVERY_PATH` (D2) | Invalid path/sequence rejected |
| CI-06 | Unit: CSV immature | `CSV_IMMATURE` |
| CI-07 | Unit: wall-clock short | `WALL_CLOCK` |
| CI-08 | Unit: velocity per sig | Reject `E > 10M` |
| CI-09 | Unit: velocity 144-block window | Reject cumulative `> 50M` |
| CI-10 | Unit: confirm missing at 5M | `CONFIRM_REQUIRED` |
| CI-11 | Unit: confirm invalid sig | `CONFIRM_INVALID` |
| CI-12 | Unit: confirm not required below 5M | Signs without token (external-only rule) |
| CI-13 | Unit: sighash ≠ ALL | `SIGHASH` |
| CI-14 | Unit: locktime ≠ 0 | `LOCKTIME` |
| CI-15 | Unit: durable replay (D4) | Second identical request `REPLAY` after restart |
| CI-16 | Unit: fee-bump full policy (D5) | Bump without full checks denied; honest bump ok |
| CI-17 | Property: amount conservation | No signed PSBT with negative fee / diverted change |
| CI-18 | Dual-node regtest | Core B disagreement with poisoned metadata → reject |
| CI-19 | No WIF in transport fixtures | Grep / type-level transport excludes secrets |
| CI-20 | Container surface | Image does not expose agent listener by default |

Current repo Security CI already covers CI-01..CI-03 style containment. CI-04+
arrive with implementation.

---

## 12. Property tests

Minimum property suite (gate 3):

1. **Conservation:** for any signed agent PSBT, `sum(in) = sum(out) + fee`.
2. **Change integrity:** change script equals pin vault script.
3. **External uniqueness:** exactly one non-change output.
4. **Pin closure:** mutating any pin field fails open requests.
5. **Replay:** random valid request succeeds once; identical replay_id fails.
6. **Confirm binding:** flipping any preimage field invalidates `confirm_token`.
7. **Velocity monotonicity:** externals accumulate in-window until expiry by
   height.

---

## 13. Locked choices (§12)

| Topic | Choice |
|---|---|
| D1 Confirm | Agent-enforced at ≥5M external; override ECDSA compact64 |
| D2 Path | `NOT_RECOVERY_PATH` reject codes for non-agent-branch misuse |
| D3 Inputs | `FOREIGN_INPUT` — vault-only, Core B verified |
| D4 Replay | Durable store; insert-before-sign; retention §15.2 |
| D5 Fee-bump | Full policy re-validation; no external increase by default |
| PSBT | v0 only |
| Sighash | ALL |
| Locktime | 0 |
| Hosting | Owner-operated agent |
| Dual node | Core A build/broadcast; Core B verify |
| Crate split | `tesaurus-policy` / `tesaurus-agent` / `tesaurus` |

Aldo closed D1–D5 on 2026-08-11 as part of design acceptance.

---

## 14. Acceptance checklist (implementation PR)

- [ ] `tesaurus-policy` encodes §6 with stable error codes
- [ ] Agent loads pin + agent key only; cannot read primary/override paths
- [ ] Core B CSV + wall-clock enforced with locked constants
- [ ] D1–D5 tests green (`confirm`, `NOT_RECOVERY_PATH`, `FOREIGN_INPUT`,
      replay restart, fee-bump)
- [ ] §10 CI matrix jobs added and green
- [ ] Property tests in §11 green
- [ ] No WIF/HTTP legacy types restored
- [ ] `--via-agent` still fail-closed **or** unlocked only behind explicit
      reviewed feature flag + docs update after CI green
- [ ] Threat model invariants 1–13 preserved
- [ ] Code review by maintainer (Steve) + design owner (Aldo)

---

## 15. Protocol polish

### 15.1 `confirm_token` encoding

**Token:** 64-byte compact ECDSA signature
`sig[0..32] || sig[32..64]` (r || s), no sighash byte suffix.

**Message:** `SHA256(preimage)`.

**Preimage layout** (big-endian integers, length-prefixed byte strings as
`u32_be length || bytes`):

```text
preimage =
  "TESAURUS_CONFIRM_V1" ||          # 18 bytes ASCII domain
  u8  network_id ||                 # 0=regtest, 1=testnet, 2=signet, 3=bitcoin
  u8  csv_version ||                # must be 1 for this document
  hash32 descriptor_sha256 ||       # SHA256(canonical descriptor UTF-8)
  u32_be pk_script_len || pk_script ||   # external output scriptPubKey
  u64_be external_sats ||           # E
  u64_be change_sats ||             # C or 0
  hash32 psbt_txid ||               # bitcoin txid byte order locked in tests
  hash32 psbt_content_hash ||       # SHA256(raw PSBT bytes as received)
  u32_be csv_blocks ||              # 4320
  u32_be safety_margin              # 1008
```

Verification:

1. Reconstruct preimage from PSBT + pin (ignore client-supplied amounts except
   as already equal under §6.5).
2. `msg = SHA256(preimage)`.
3. ECDSA verify compact64 with `override_pubkey`.

### 15.2 Replay retention (D4)

- Store: append-only or KV with crash-safe sync (e.g. SQLite WAL or similar).
- Key: `replay_id` from §6.1.
- Value: `{ created_at, tip_height_at_sign, external_sats }`.
- Retain entries for at least **2016 blocks** of Core B tip growth **or** 30
  days wall-clock, whichever is longer.
- Prune only after both thresholds; never prune on read path if prune fails.
- Backup/restore of the replay DB is an operational requirement before mainnet.

### 15.3 External-only confirm threshold CI

CI must lock that confirm enforcement keys off **external** value `E` only:

| External `E` | Change `C` | Token |
|---|---|---|
| `4_999_999` | large | not required |
| `5_000_000` | 0 | required |
| `5_000_000` | large | required |
| `10_000_000` | any | required + velocity per-sig boundary |

A test that only sums `E+C` for the threshold is a **failing** test relative to
this design.

---

## 16. Document control

| Field | Value |
|---|---|
| Status | Gate 1 design **ACCEPTED for implementation** (Aldo 2026-08-11; D1–D5 closed) |
| Unlock | **No** `--via-agent` until implementation + Security CI matrix green and reviewed |
| Companion | `docs/THREAT_MODEL.md` (gate 0 ACCEPTED 2026-08-11) |
