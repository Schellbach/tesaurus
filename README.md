# Tesaurus

> [!WARNING]
> **This project is experimental.** It is not production-ready, has not been audited, and may contain serious bugs. Do not put meaningful funds at risk. Prefer **regtest/testnet**, and read [SECURITY.md](SECURITY.md) before any real-world use.

Sovereign Bitcoin vault with a **local agent** as the recovery co-signer.

Tesaurus is a decaying 2-of-3 vault. Spending conditions are enforced on-chain with [Miniscript](https://bitcoin.sipa.be/miniscript/) — not by trusting the agent process.

```text
thresh(2, pk(primary), pk(override), and(pk(agent), older(csv)))
```

| Path | Keys | Availability |
|------|------|----------------|
| **Primary** | primary + override | Always |
| **Recovery** | primary + agent (or any other 2-of-3) | After `csv` confirmations on that coin |

You hold primary and override. The agent is software you run locally: it holds the agent key and co-signs only when its policy allows (timelock mature, amount caps, optional allowlist).

Inspired by [Liana](https://github.com/wizardsardine/liana) and AnchorWatch-style recovery keyholders — with the third key kept under your control as a local agent instead of a remote custodian.

## Status

**Experimental** — APIs, config, and security properties may change without notice.

Working implementation:

- Miniscript descriptor compile + sanity checks
- Real P2WSH signing (primary and recovery paths)
- Bitcoin Core watch-only sync and broadcast
- Local agent HTTP co-signer with policy checks

Use **regtest/testnet** first. Mainnet needs your own ops review — see [SECURITY.md](SECURITY.md).

## Prerequisites

- Rust 1.85+ (`rustup`)
- Bitcoin Core 25+ with wallet RPC enabled
- Linux or macOS

## Install

```bash
git clone https://github.com/Schellbach/tesaurus.git
cd tesaurus
cargo build --release
```

Binaries:

- `./target/release/tesaurus` — vault CLI
- `./target/release/tesaurus-agent` — recovery co-signer

## Configuration

```bash
./target/release/tesaurus init-config --path config/tesaurus.toml --network testnet
# or use the shipped examples:
#   config/tesaurus.toml          (testnet defaults)
#   config/tesaurus.regtest.toml  (regtest defaults)
```

Important fields:

| Section | Field | Meaning |
|---------|-------|---------|
| `[bitcoin]` | `network` / `rpc_url` / auth | Bitcoin Core connection |
| `[bitcoin]` | `wallet_name` | Watch-only Core wallet Tesaurus manages |
| `[vault]` | `csv_blocks` | Relative timelock before agent path unlocks |
| `[vault]` | `keys_dir` / `state_path` | WIF keys + descriptor state |
| `[agent]` | `bind` / `api_token` / `max_amount_sats` | Co-signer listen address and policy |

## Quick start (regtest)

One-shot against a local `bitcoind`:

```bash
./scripts/regtest-e2e.sh
```

Or step by step:

```bash
# Terminal A — Bitcoin Core regtest (example)
bitcoind -regtest -server -txindex -fallbackfee=0.0002 \
  -rpcuser=tesaurus -rpcpassword=changeme -rpcport=18443 -daemon

bitcoin-cli -regtest -rpcuser=tesaurus -rpcpassword=changeme createwallet miner
bitcoin-cli -regtest -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner -generate 101

# Terminal B — Tesaurus
cp config/tesaurus.regtest.toml config/tesaurus.toml
cargo build --release

./target/release/tesaurus -c config/tesaurus.toml keys generate
./target/release/tesaurus -c config/tesaurus.toml init-vault
./target/release/tesaurus -c config/tesaurus.toml import-watch
ADDR=$(./target/release/tesaurus -c config/tesaurus.toml address | head -1)

bitcoin-cli -regtest -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner \
  sendtoaddress "$ADDR" 1
bitcoin-cli -regtest -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner -generate 1

./target/release/tesaurus -c config/tesaurus.toml status
DEST=$(bitcoin-cli -regtest -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner getnewaddress)

# Primary spend (primary + override)
./target/release/tesaurus -c config/tesaurus.toml spend \
  --to "$DEST" --amount-sats 100000 --fee-sats 1000 --path primary --broadcast

# After CSV maturity: recovery via local agent
bitcoin-cli -regtest -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner -generate 10
./target/release/tesaurus-agent -c config/tesaurus.toml &
./target/release/tesaurus -c config/tesaurus.toml spend \
  --to "$DEST" --amount-sats 50000 --fee-sats 1000 --path recovery --via-agent --broadcast
```

Docker Compose can also start Core (`docker compose up -d bitcoind`) if you have Docker; point `rpc_url` at `http://127.0.0.1:18443` with the credentials in `config/tesaurus.regtest.toml`.

## Testnet

1. Run Bitcoin Core with `testnet=1` and RPC enabled.
2. Copy/edit `config/tesaurus.toml` (`network = "testnet"`, RPC URL usually `18332`).
3. `keys generate` → `init-vault` → `import-watch`.
4. Fund the printed address from a testnet faucet.
5. Spend with `--path primary`, or after `csv_blocks` confirmations use recovery / `--via-agent`.

## CLI reference

```text
tesaurus -c config/tesaurus.toml <COMMAND>
```

| Command | Purpose |
|---------|---------|
| `init-config` | Write an example config file |
| `keys generate` | Create primary / override / agent WIF files (`0600`) |
| `init-vault` | Compile descriptor and save `data/vault.json` |
| `address` | Print receive address and descriptor |
| `import-watch` | Import descriptor into Bitcoin Core (watch-only) |
| `status` | Tip height, balance, UTXOs, CSV maturity |
| `spend` | Build, sign, optionally `--broadcast` |
| `tesaurus-agent` | Run the local co-signer (`GET /health`, `POST /v1/sign`) |

Spend flags:

- `--path primary|recovery`
- `--via-agent` — ask `tesaurus-agent` to co-sign (recovery)
- `--broadcast` — submit via Bitcoin Core `sendrawtransaction`

Local recovery without HTTP (both keys on one machine):

```bash
./target/release/tesaurus spend --to "$DEST" --amount-sats 50000 \
  --fee-sats 1000 --path recovery --broadcast
```

## Architecture

```text
┌──────────────────┐     watch-only / broadcast     ┌──────────────┐
│ tesaurus CLI     │◄──────────────────────────────►│ Bitcoin Core │
│ keys + signing   │     listunspent / sendraw      │ (RPC wallet) │
└────────┬─────────┘                                └──────────────┘
         │
         │ primary: sign with primary + override locally
         │ recovery: POST /v1/sign ──► tesaurus-agent
         ▼
┌──────────────────┐
│ tesaurus-agent   │  holds agent.wif
│ policy gate      │  timelock · max amount · allowlist
└──────────────────┘
```

Private keys stay in `keys/*.wif`. Bitcoin Core is watch-only.

## Project layout

```text
src/
  descriptor.rs   # Miniscript vault policy
  keys.rs         # WIF key generation / loading
  wallet.rs       # Vault state + UTXO sync
  spend.rs        # Transaction build + satisfy
  rpc.rs          # Bitcoin Core helpers
  agent/          # Co-signer policy + HTTP API
  bin/            # tesaurus, tesaurus-agent
config/           # Example TOML + bitcoind conf
scripts/regtest-e2e.sh
SECURITY.md
```

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
./scripts/regtest-e2e.sh   # needs bitcoind on PATH
```

## Security

Read [SECURITY.md](SECURITY.md) before mainnet use. Short version:

- Back up `data/vault.json` **and** all three WIF files offline.
- Raise `csv_blocks` for mainnet (weeks/months), not demo values like `10`.
- Bind the agent to localhost and set `api_token`.
- `--via-agent` sends the primary WIF to the agent over HTTP — localhost + token only (or use local `--path recovery` without `--via-agent`).
- Losing keys without backup means permanent loss of funds.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- [Liana](https://github.com/wizardsardine/liana) by Wizardsardine
- [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) and [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript)
- AnchorWatch / Trident-style recovery keyholder model
