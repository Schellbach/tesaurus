# Security Model

Tesaurus is custody software. Treat it like a wallet, not a demo.

## Threat model (intended)

- **You** control primary and override keys.
- The **agent** is a process you run. It holds the agent key and co-signs only after the on-chain relative timelock (`older(csv)`) is satisfied and local policy checks pass.
- Bitcoin Core is used as a **watch-only** indexer/broadcaster. Private keys are not imported into Core.

## On-chain guarantees

The spending policy is enforced by Bitcoin Script via Miniscript:

```text
thresh(2, pk(primary), pk(override), and(pk(agent), older(csv)))
```

Before `csv` confirmations on a UTXO, the agent branch is unavailable. Spending requires primary + override.

After maturity, any two of the three keys can spend. Typical recovery is primary + agent.

## Operational requirements

1. **Backup** the descriptor (`data/vault.json`) and all three WIF files offline.
2. **Never** commit keys, cookies, or API tokens to git.
3. Run `tesaurus-agent` on localhost (default) with `api_token` set.
4. Set `max_amount_sats` and optionally an address `allowlist` for the agent.
5. Use a large `csv_blocks` on mainnet. Ten blocks is for testnet/regtest demos only.
6. Prefer Bitcoin Core cookie authentication over username/password when possible.

## Agent HTTP co-sign

`tesaurus spend --via-agent` sends a JSON request that may include the primary WIF so the agent can assemble a fully signed recovery transaction.

That is acceptable only for a **local, authenticated** agent. Do not expose the agent API to the public internet. A future revision should switch to PSBT-only co-signing so the primary key never leaves the client.

## What this does not protect against

- Compromised primary **and** override keys before the timelock
- Compromised primary **and** agent keys after the timelock
- Malicious or buggy Bitcoin Core / OS / supply chain
- Loss of backups
- Incorrect network selection (testnet keys on mainnet, etc.)

## Reporting issues

Open a GitHub issue for security-relevant bugs. Do not include private keys in reports.
