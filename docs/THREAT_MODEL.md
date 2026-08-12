# Tesaurus threat model & custody architecture

**Status:** gate 0 **ACCEPTED** 2026-08-11.

This document is the accepted gate 0 product and security baseline for moving
Tesaurus from research containment toward a production custody path. It does
**not** unlock `--via-agent`, restore HTTP co-signing, or enable mainnet.
Those remain fail-closed until later gates land with reviewed code and Security
CI.

Companion design (gate 1, design accepted for implementation):
[`PSBT_AGENT_PROTOCOL.md`](PSBT_AGENT_PROTOCOL.md).

---

## 1. Product intent

Tesaurus is a decaying 2-of-3 Bitcoin vault. The on-chain policy is:

```text
thresh(2, pk(primary), pk(override), and(pk(agent), older(csv)))
```

| Path | Keys | Availability |
|---|---|---|
| Primary / normal | primary + override | Always |
| Recovery / delayed | any valid 2-of-3 that includes the agent branch | After relative CSV maturity |

**Intended production use:** Steve Schellbach self-custody with:

- a cold hardware primary key;
- a named second-person override key for two-human authorization;
- an **owner-operated** agent that may co-sign only after CSV maturity, under
  strict off-chain policy, using PSBT-only transport.

**Not intended:**

- a hosted Tesaurus co-signing service (deferred);
- Liana compatibility as a near-term requirement (deferred);
- research local flows that load primary + agent WIFs in one process as a
  production custody model.

The research CLI remains useful for regtest/testnet descriptor and signing
experiments. Production claims require this threat model, the PSBT agent
protocol, Security CI, and later gates.

---

## 2. Locked custody architecture

| Role | Holder | Material | Normal use |
|---|---|---|---|
| **primary** | Steve (owner) | Cold hardware wallet | Signs intentional spends; never on the agent host |
| **override** | Named second person | Separate cold / high-assurance key | Co-signs with primary for always-available path; also issues `confirm_token` attestations for large agent-path externals |
| **agent** | Owner-operated agent host | Hot key, pin-bound to one vault descriptor + network | May add one partial signature only after CSV maturity and full policy validation |

**Locked decisions:**

- **Owner-operated agent** for v1. Tesaurus-hosted agent is deferred.
- **Two-human override** is required for the always-available path (primary +
  override). The override holder is a named person recorded before mainnet.
- **Liana** integration / policy compatibility is deferred past gate 5.
- The agent process **must not** be able to read primary or override private
  keys.

---

## 3. Dual-node verification (Core A / Core B)

Production agent-path spends use two independently operated Bitcoin Core nodes:

```text
┌────────────────────┐         PSBT + auth          ┌────────────────────┐
│ Coordinator        │─────────────────────────────►│ tesaurus-agent     │
│ (owner CLI / ops)  │◄─────────────────────────────│ owner-operated     │
│                    │     partial sig or reject    │                    │
│ Core A ────────────┤                              │ Core B ────────────┤
│ watch-only / build │                              │ independent verify │
│ UTXO + broadcast   │                              │ CSV + wall-clock   │
└────────────────────┘                              └────────────────────┘
```

| Node | Role | Trust boundary |
|---|---|---|
| **Core A** | Coordinator: wallet sync, UTXO selection, PSBT construction, broadcast | Compromised A alone must not produce an agent signature |
| **Core B** | Agent: independent UTXO existence, confirmations, tip height / time | Compromised B alone must not move funds without agent key + policy |

The agent treats Core B as its sole chain oracle for CSV maturity and
wall-clock bounds. It does not trust coordinator-supplied confirmation counts
or fees without recomputation from the PSBT and Core B.

---

## 4. Adversaries

| Adversary | Goal | Notes |
|---|---|---|
| Remote network attacker | Steal keys, forge agent signatures, redirect spends | No HTTP legacy protocol; auth + replay required |
| Compromised coordinator host | Build malicious PSBTs, drain via agent | Agent must validate structure, keys, foreign inputs, amounts, velocity, confirm |
| Compromised agent host | Sign anything, exfiltrate agent key | Pin + policy + velocity + CSV; primary/override still required before maturity |
| Malicious or buggy Core A | Lie about UTXOs / fees | Agent verifies on Core B |
| Malicious or buggy Core B / **eclipse** | Premature CSV, fake tips, withheld blocks | Wall-clock bound + safety margin; dual-node ops; monitoring |
| Malicious override holder | Coerce or collude on always-available path | Operational / legal; two-human procedure |
| Supply-chain / dependency | Introduce signing bugs | Locked builds, audit, CI |
| Physical theft of one device | Single-key compromise | 2-of-3 before CSV; agent branch delayed |

**Eclipse / chain-oracle abuse** is in scope: an adversary who partitions the
agent from honest peers and feeds a false chain must still fail the wall-clock
bound (`WALL_CLOCK_SECONDS_PER_BLOCK = 600`) with `csv_blocks + safety_margin`
before the agent accepts recovery maturity (~37 days intentional).

---

## 5. Assets

1. Primary private key (cold HW)
2. Override private key (named second person)
3. Agent private key (hot, pin-bound)
4. Vault UTXOs and change
5. Agent authentication secret / request credentials
6. Durable replay database (vault-lifetime retention)
7. Bitcoin Core cookies / RPC access (A and B)
8. Descriptor / `AgentPin` integrity
9. Operational procedures and named override identity

---

## 6. Trust boundaries

| Component | May hold | Must not hold |
|---|---|---|
| Cold primary HW | primary | override, agent |
| Override device | override | primary, agent |
| `tesaurus-agent` | agent key, pin, replay DB, Core B cookie | primary, override |
| Coordinator / CLI | construction state, Core A cookie; may prompt HW | agent key (production) |
| Core A / Core B | chain data | vault private keys |
| Network transport | PSBT + auth + optional `confirm_token` | WIF / seed material |

---

## 7. Security invariants (1–13)

These are product invariants. Gate 1+ implementation and Security CI must
preserve them. Research containment already enforces a subset (no mainnet, no
HTTP signer, `--via-agent` fail-closed).

1. **No mainnet until gate checklist complete.** Configuration and vault
   construction reject mainnet until explicitly unlocked after review.
2. **No private key on the wire.** Transport is PSBT + authentication only.
   Never serialize WIF, seeds, or primary/override material to the agent.
3. **Agent cannot read primary or override keys.** Process isolation and pin
   design must make this structural, not advisory.
4. **Descriptor pin.** The agent signs only for one locked descriptor,
   network, CSV, and pubkey set (`AgentPin`).
5. **CSV maturity from Core B.** Agent-path signing requires relative timelock
   maturity verified independently; coordinator claims are insufficient.
6. **Wall-clock bound.** Even if Core B is eclipsed, wall-clock time must
   cover `(csv_blocks + safety_margin) * WALL_CLOCK_SECONDS_PER_BLOCK` before
   recovery signing is allowed.
7. **PSBT structure.** PSBT v0; every input `SIGHASH_ALL`; `nLockTime = 0`;
   exactly one external output plus exact vault change (when change exists);
   no foreign inputs (D3).
8. **Not recovery-path abuse of primary policy (D2).** Agent refuses PSBTs
   that attempt to satisfy or advertise a non-agent recovery satisfaction
   contrary to `NOT_RECOVERY_PATH` rules in the protocol doc.
9. **Amount & change integrity.** External amount, change script, and fee are
   recomputed and bounded; change must pay the pinned vault script.
10. **Velocity limits.** At most **10,000,000 sats per signature** and
    **50,000,000 sats per 144 blocks** (agent-enforced).
11. **Large external confirm (D1).** External value ≥ **5,000,000 sats**
    requires a valid override-key `confirm_token` before the agent signs.
12. **Durable replay protection (D4).** Auth requests / PSBT identities cannot
    be replayed across agent restarts; replay records are retained for the
    **vault lifetime**.
13. **Fee-bump policy (D5).** Replace-by-fee / fee-bump paths re-run full
    policy validation; bumps are not a bypass for amounts, velocity, confirm,
    CSV, or structure checks.

---

## 8. On-chain vs off-chain enforcement

| Control | Enforcement |
|---|---|
| 2-of-3 / CSV branch | Bitcoin consensus (Miniscript / Script) |
| Primary + override always-available path | Consensus |
| Agent may not sign before CSV | Consensus + agent policy + Core B |
| Wall-clock bound / safety margin | Agent policy only (defense in depth against eclipse) |
| Velocity, confirm_token, foreign-input, sighash | Agent policy only |
| Dual-node independence | Operations |

Off-chain checks are defense in depth. Documentation must not describe them as
consensus guarantees.

---

## 9. Locked parameters

| Parameter | Value | Notes |
|---|---|---|
| Policy | `thresh(2, pk(primary), pk(override), and(pk(agent), older(csv)))` | Locked |
| `csv_blocks` | **4320** | Relative timelock for agent branch |
| `safety_margin` | **1008** | Extra blocks for wall-clock / eclipse bound |
| `WALL_CLOCK_SECONDS_PER_BLOCK` | **600** | Intentional ~37d bound: `(4320 + 1008) * 600 ≈ 37 days` |
| Velocity per signature | **10,000,000 sats** | Agent-enforced |
| Velocity per 144 blocks | **50,000,000 sats** | Agent-enforced |
| Confirm threshold | **5,000,000 sats** external | D1 `confirm_token` |
| Agent hosting | **Owner-operated** | Tesaurus-hosted deferred |
| Override model | **Two-human** (named second person) | Recorded before mainnet |
| Liana | **Deferred** | Not a gate 0–5 blocker |
| PSBT | **v0** | Locked for gate 1 |
| Sighash | **SIGHASH_ALL** on every input | Locked |
| `nLockTime` | **0** | Locked for agent-path PSBTs |
| Outputs | Single external + exact vault change | Locked shape |
| Replay retention | **Vault lifetime** | D4; see protocol §15.2 |

---

## 10. Roadmap gates

| Gate | Scope | Status |
|---|---|---|
| **0** | Threat model & custody architecture | **ACCEPTED** 2026-08-11 |
| **1** | PSBT-only agent protocol design | **Design ACCEPTED** for implementation (Aldo 2026-08-11; D1–D5 closed). **No `--via-agent` unlock** until implementation + Security CI matrix are green and reviewed |
| **2** | `tesaurus-policy` + agent implementation behind fail-closed flags | Not started |
| **3** | Security CI matrix (§10 of protocol doc), property tests, dual-node regtest | Not started |
| **4** | Operational runbooks: Core A/B, override ceremonies, confirm_token issuance | Not started |
| **5** | External review / audit readiness; mainnet checklist sign-off | Not started |

Gates 2–5 must not weaken gate 0 invariants. Unlocking network co-signing or
mainnet without the checklist is a release blocker.

---

## 11. Mainnet checklist

Before any mainnet configuration unlock:

- [ ] Named override person recorded (legal name + contact + key ceremony notes)
- [ ] Primary key on cold hardware; seed backup procedure tested
- [ ] Override key ceremony completed; no shared single device with primary
- [ ] Owner-operated agent host hardened; agent key generated on that host
- [ ] `AgentPin` matches on-chain descriptor; `csv_blocks = 4320`
- [ ] Core A and Core B independently deployed and monitored (eclipse alerts)
- [ ] Wall-clock bound validated in staging (`safety_margin = 1008`)
- [ ] Velocity and confirm_token paths exercised on testnet/signet
- [ ] Durable replay store backup/restore tested (D4; vault-lifetime retention)
- [ ] Fee-bump policy tested (D5)
- [ ] Gate 1 implementation + Security CI matrix green and reviewed
- [ ] Independent review / audit of signing and policy code
- [ ] Incident response: lost primary, lost override, compromised agent
- [ ] Explicit maintainer approval to lift mainnet reject guards

---

## 12. Out of scope (gate 0)

- Lightning, covenants beyond this Miniscript policy, or alternate scripts
- Multiparty compute or threshold HSM protocols
- Tesaurus-hosted SaaS co-signing
- Guaranteeing safety if primary **and** override are compromised
- Guaranteeing safety if agent key **and** CSV maturity **and** policy bugs
  coincide without monitoring

---

## 13. Document control

| Field | Value |
|---|---|
| Status | Gate 0 **ACCEPTED** 2026-08-11 |
| Product owner | Steve Schellbach |
| Design companion | `docs/PSBT_AGENT_PROTOCOL.md` |
| Supersedes | Informal SECURITY.md research notes for production planning (SECURITY.md remains the vulnerability-reporting and containment notice) |
