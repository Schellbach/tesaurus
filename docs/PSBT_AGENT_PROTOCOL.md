# Tesaurus PSBT-only agent protocol

**Status:** gate 1 design **ACCEPTED for implementation** (Aldo 2026-08-11;
D1–D5 closed). No `--via-agent` unlock until implementation + Security CI
matrix are green and reviewed.

**Hard rule:** Do **not** unlock `--via-agent` and do **not** restore HTTP
co-signing until that condition is met. Until then, `tesaurus-agent` and
`--via-agent` remain fail-closed.

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
| Replay retention (D4) | Vault lifetime |

---

## 4. Crate split

| Crate / binary | Responsibility |
|---|---|
| **`tesaurus-policy`** | Pure validation: pin checks, PSBT structural rules, amount/fee math, velocity, confirm preimage verify, crash-safe R1 replay store, enumerable error codes. No RPC. No key I/O. |
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
  genesis_hash,            // 32-byte chain genesis (confirm binding)
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

## 5b. Transport API

Local, authenticated request/response (Unix socket or loopback TCP with mutual
auth — exact binding chosen at implementation; **not** the legacy HTTP WIF
protocol).

### Request

```text
SignRequest {
  request_id:            UUID v4 (16 bytes raw in confirm preimage)
  psbt:                  base64 PSBT v0
  auth:                  MAC or signature over canonical request bytes
  confirm_token:         optional 64-byte compact ECDSA (see §9 / §15.1)
  claimed_external_sats: u64   // must match policy-computed external
}
```

### Response

```text
SignResponse::Ok { psbt }           // same tx, agent partial sig added
SignResponse::Reject { code, msg }  // stable error codes for CI
```

Stable reject codes include: `AUTH`, `REPLAY`, `REPLAY_CONFLICT`,
`PSBT_PARSE`, `FOREIGN_INPUT`, `NOT_RECOVERY_PATH`, `CSV_IMMATURE_DEPTH`,
`CSV_IMMATURE_WALLCLOCK`, `VELOCITY`, `CONFIRM_REQUIRED`, `CONFIRM_INVALID`,
`SIGHASH`, `LOCKTIME`, `FEE_BUMP_INVALID` (see `tesaurus-policy`
`PolicyErrorCode` for the enumerable set).

---

## 6. Validation state machine (normative order)

Every `SignRequest` runs these stages **in this exact order**. Failure aborts
with no signature. Replay insertion (D4) occurs before signing as specified.

### 6.1 Authentication & durable replay (D4 / Aldo R1)

1. Verify `auth` over the canonical request encoding → else `AUTH`.
2. Compute `replay_id = SHA256(request_id || psbt_txid || psbt_content_hash)`.
3. Index the durable store by `request_id` **and** spent outpoints. A missing
   or corrupt store refuses to sign.
4. Same `request_id` + same `replay_id` → **idempotent cached Ok** (honest
   retry after a network drop). This is **not** a hard `REPLAY`.
5. Same `request_id` + different `replay_id` → `REPLAY_CONFLICT`; do not sign.
6. Same outpoints already signed with different outputs (any `request_id`) →
   `REPLAY`, **except** a D5 vault-change-only mutation: external destination
   script and external amount `E` unchanged, no new external outputs, vault
   change strictly decreased (fee increased). That shape is **not** `REPLAY` at
   the store layer; full §8 policy still applies when fee-bump signing is
   wired. Same outpoints with the same outputs (or any other output mutation)
   remain `REPLAY`.
7. First success: persist `{request_id, replay_id, psbt_txid, outpoints,
   signed_psbt_or_partial}` **before** returning Ok (fail closed if persist
   fails).
8. Retention: **vault lifetime** (see §15.2). Do not prune on a timer while the
   vault pin remains active.

### 6.2 PSBT structure

1. Parse PSBT **v0** only → else `PSBT_MALFORMED`.
2. `nLockTime == 0` else `LOCKTIME`.
3. Every input sighash type present and equal to `SIGHASH_ALL` else `SIGHASH`.
4. Output count: one external + optional single change; no other shapes.
5. Fee = sum(inputs) − sum(outputs); must be non-negative and within
   implementation fee bounds (anti DoS); coordinator may be stricter.

### 6.3 Keys & witness UTXO metadata

1. Each input must include witness UTXO (or full prior tx per implementation
   choice locked in code review) sufficient to verify amounts and scripts.
2. Redeem/witness script for each vault input must match the pinned descriptor
   → else `PIN_MISMATCH`.

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
   spent under the agent branch → else `CSV_IMMATURE`.
3. Wall-clock: require local trustworthy time such that elapsed bound covers
   `(csv_blocks + safety_margin) * WALL_CLOCK_SECONDS_PER_BLOCK`
   since the earliest admissible birth time derived from Core B headers /
   block times for those coins (implementation uses the conservative
   interpretation reviewed in gate 2). Intentional ~37 day bound.
4. Failures of the wall-clock bound → `WALL_CLOCK`.

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
2. Verify per §9 / §15.1 against the **override** pubkey in the pin else
   `CONFIRM_INVALID`.

If `E < 5_000_000`, confirm is **not** required. Threshold keys off
**external-only** `E` (never `E+C`). See §15.3 CI cases.

### 6.7 Sign

1. Produce agent partial signature(s) for vault inputs with `SIGHASH_ALL`.
2. Return updated PSBT. Do not broadcast.

---

## 7. Coordinator flow

```text
1. Owner builds spend intent (external address, amount).
2. Core A: select vault UTXOs, construct PSBT v0
   (locktime 0, SIGHASH_ALL, one external + exact change).
3. If primary path: collect primary HW + override signatures; broadcast via A.
4. If agent recovery path (after maturity):
   a. Optionally collect primary partial sig first (typical 2-of-3).
   b. If E ≥ 5M: obtain confirm_token from override holder (§9 / §15.1).
   c. Send SignRequest to owner-operated agent.
   d. Agent runs §6 against Core B; returns PSBT or reject.
   e. Finalize and broadcast via Core A.
5. Fee-bump: see §8 (D5) — rebuild/replace PSBT and re-run full agent policy.
```

---

## 8. Fee-bump policy (D5)

Fee-bumps / RBF replacements are **not** a privileged path.

1. Replacement PSBT must pass the **entire** §6 state machine in normative
   order.
2. External destination script and external amount `E` must be identical to the
   replaced intent (fee may rise by reducing change only, or by approved
   pattern locked in implementation tests).
3. Velocity accounting charges the external amount according to the locked rule:
   replacements that do not increase `E` do not double-charge; increases are
   rejected unless they pass velocity as a new `E` (production default:
   **forbid external increases** on bumps).
4. Confirm token: if `E ≥ 5M`, bump requests need a valid `confirm_token`
   whose preimage binds this request’s `request_id` (uuid16) and txid
   (§15.1), not a reused token from a different binding.
5. Replay: new `request_id` / content hash required; old ids remain
   non-replayable for the vault lifetime. Honest fee-bumps reuse spent
   outpoints with a **vault-change-only** output mutation (same external
   destination and `E`, lower vault change / higher fee, no extra externals).
   The durable store must **not** treat that shape as outpoint `REPLAY`; it is
   a D5 replacement that still runs the entire §6 machine. Diverting the
   external, increasing `E`, adding outputs, or increasing change remains
   `REPLAY`.

Violations → `FEE_BUMP_DENIED` or the underlying stage code.

---

## 9. Confirm attestation

`confirm_token` proves the **override** key authorized a specific large
external spend.

### Semantics

- Signature scheme: **ECDSA secp256k1 compact 64-byte** signature
  (RFC6979 deterministic recommended) over `SHA256(preimage)`.
- Verifying key: pin `override_pubkey`.
- Required iff policy-computed external `E ≥ 5_000_000` sats (D1).

### Preimage (normative)

Canonical byte layout is locked in **§15.1**:

```text
TESAURUS_CONFIRM_V1 || u8(1) || uuid16 || txid32 || u64_be(amount) || genesis32
```

The agent verifies the signature; it does not possess the override private key.

---

## 10. Security CI matrix

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
| CI-10 | Unit: confirm missing at 5M external | `CONFIRM_REQUIRED` |
| CI-11 | Unit: confirm invalid sig | `CONFIRM_INVALID` |
| CI-12 | Unit: confirm not required below 5M external | Signs without token |
| CI-13 | Unit: sighash ≠ ALL | `SIGHASH` |
| CI-14 | Unit: locktime ≠ 0 | `LOCKTIME` |
| CI-15 | Unit: durable replay (D4 / R1) | Identical `request_id`+`replay_id` is idempotent cached Ok across restart; vault-lifetime retention |
| CI-16 | Unit: fee-bump full policy (D5) | Bump without full checks denied; honest bump ok |
| CI-17 | Property: amount conservation | No signed PSBT with negative fee / diverted change |
| CI-18 | Dual-node regtest | Core B disagreement with poisoned metadata → reject |
| CI-19 | No WIF in transport fixtures | Grep / type-level transport excludes secrets |
| CI-20 | Container surface | Image does not expose agent listener by default |
| CI-21 | Confirm threshold external-only (§15.3) | Cases in §15.3 table; `E+C` must not drive threshold |
| CI-22 | Confirm preimage encoding (§15.1) | Vectors for `TESAURUS_CONFIRM_V1\|\|u8(1)\|\|uuid16\|\|txid32\|\|u64_be\|\|genesis32` |
| CI-23 | Normative §6 stage order | Mutating earlier-stage failures never reach later stages / signing |
| CI-24 | Unit: R1 replay split | Idempotent cached payload; `REPLAY_CONFLICT` on same `request_id` different PSBT; `REPLAY` on same outpoints different outputs |

Current repo Security CI already covers CI-01..CI-03 style containment. CI-04+
arrive with implementation.

---

## 11. Property tests

Minimum property suite (gate 3):

1. **Conservation:** for any signed agent PSBT, `sum(in) = sum(out) + fee`.
2. **Change integrity:** change script equals pin vault script.
3. **External uniqueness:** exactly one non-change output.
4. **Pin closure:** mutating any pin field fails open requests.
5. **Replay:** random valid request succeeds once; identical replay_id fails
   across restart (vault-lifetime store).
6. **Confirm binding:** flipping any §15.1 preimage field invalidates
   `confirm_token`.
7. **Velocity monotonicity:** externals accumulate in-window until expiry by
   height.
8. **Stage order:** inject faults per §6 stage; observe first matching reject
   code only.

---

## 12. Locked choices

| Topic | Choice |
|---|---|
| D1 Confirm | Agent-enforced at ≥5M **external**; override ECDSA compact64 over SHA256(preimage) |
| D2 Path | `NOT_RECOVERY_PATH` reject codes for non-agent-branch misuse |
| D3 Inputs | `FOREIGN_INPUT` — vault-only, Core B verified |
| D4 Replay | Durable store; insert-before-sign; **vault-lifetime** retention |
| D5 Fee-bump | Full policy re-validation; no external increase by default |
| PSBT | v0 only |
| Sighash | ALL |
| Locktime | 0 |
| Hosting | Owner-operated agent |
| Dual node | Core A build/broadcast; Core B verify |
| Crate split | `tesaurus-policy` / `tesaurus-agent` / `tesaurus` |
| Confirm preimage | §15.1 exact layout |

Aldo closed D1–D5 on 2026-08-11 as part of design acceptance.

---

## 13. Acceptance checklist (implementation PR)

- [ ] `tesaurus-policy` encodes §6 with stable error codes in normative order
- [ ] Agent loads pin + agent key only; cannot read primary/override paths
- [ ] Core B CSV + wall-clock enforced with locked constants
- [ ] D1–D5 tests green (`confirm`, `NOT_RECOVERY_PATH`, `FOREIGN_INPUT`,
      replay restart + vault-lifetime retention, fee-bump)
- [ ] §10 CI matrix jobs added and green (including CI-21..CI-23)
- [ ] Property tests in §11 green
- [ ] No WIF/HTTP legacy types restored
- [ ] `--via-agent` still fail-closed **or** unlocked only behind explicit
      reviewed feature flag + docs update after CI green
- [ ] Threat model invariants 1–13 preserved
- [ ] Code review by maintainer (Steve) + design owner (Aldo)

---

## 14. Decisions closed (D1–D5)

| ID | Decision | Locked rule |
|---|---|---|
| **D1** | Large external confirm | Agent enforces `confirm_token` when external `E ≥ 5_000_000`; override key; §15.1 encoding |
| **D2** | Recovery path misuse | Reject with `NOT_RECOVERY_PATH` |
| **D3** | Non-vault inputs | Reject with `FOREIGN_INPUT`; Core B must see each UTXO |
| **D4** | Replay | Durable insert-before-sign; retain for **vault lifetime** |
| **D5** | Fee-bump | Re-run full §6 policy; no external-amount increase by default |

---

## 15. Protocol polish

### 15.1 `confirm_token` encoding

**Token:** 64-byte compact ECDSA signature `r \|\| s` (no sighash byte).

**Message:** `SHA256(preimage)`.

**Preimage layout** (concatenation, no length prefixes except as shown):

```text
preimage =
    "TESAURUS_CONFIRM_V1"   # 19 bytes ASCII domain separator (locked; do not treat as 18)
 || u8(1)                   # encoding version = 1
 || uuid16                  # request_id as 16 raw UUID bytes
 || txid32                  # transaction id, Bitcoin display/RPC byte order
 || u64_be(amount)          # external amount E, big-endian u64 sats
 || genesis32               # chain genesis block hash (32 bytes, pin.genesis_hash)
```

Verification (agent):

1. Reconstruct `preimage` from `SignRequest.request_id`, the PSBT’s txid
   (display order), policy-computed external `E`, and `AgentPin.genesis_hash`.
2. `msg = SHA256(preimage)`.
3. ECDSA-verify compact64 with pin `override_pubkey`.
4. Mismatch or bad sig → `CONFIRM_INVALID`.

Test vectors in CI-22 must cover: version byte ≠ 1, flipped uuid byte, wrong
txid endianness, wrong amount, wrong genesis, and a known-valid compact64.

### 15.2 Replay retention (D4)

- Store: crash-safe durable KV or SQLite WAL (or equivalent). Indexed by
  `request_id` and spent outpoints; `replay_id` is
  `SHA256(request_id || psbt_txid || psbt_content_hash)`.
- Value: `{ request_id, replay_id, psbt_txid, outpoints, outputs, vault_script, signed_psbt_or_partial, … }`
  (see §6.1 R1: identical `replay_id` is idempotent; a different `replay_id` for
  the same `request_id` is `REPLAY_CONFLICT`; D5 vault-change-only replacements
  may share outpoints and are not `REPLAY`).
- **Retention: vault lifetime.** While the current `AgentPin` / vault remains
  provisioned, do **not** time-prune replay records. Clearing the store is an
  explicit re-provision / vault-rotation ceremony, not a background job.
- Backup/restore of the replay DB is an operational requirement before mainnet.
- After pin rotation, old replay DBs must not be reused against a new pin
  without review (fail closed preferred).

### 15.3 External-only confirm threshold CI

CI-21 must lock that confirm enforcement keys off **external** value `E` only:

| External `E` | Change `C` | Token |
|---|---|---|
| `4_999_999` | `0` | not required |
| `4_999_999` | `50_000_000` | not required (`E+C` must not trigger) |
| `5_000_000` | `0` | required |
| `5_000_000` | `50_000_000` | required |
| `10_000_000` | any | required + at per-sig velocity boundary |

A test or implementation that uses `E+C` (or input total) for the confirm
threshold is a **design violation**.

---

## 16. Document control

| Field | Value |
|---|---|
| Status | Gate 1 design **ACCEPTED for implementation** (Aldo 2026-08-11; D1–D5 closed). No `--via-agent` unlock until implementation + Security CI matrix are green and reviewed |
| Companion | `docs/THREAT_MODEL.md` (gate 0 ACCEPTED 2026-08-11) |
