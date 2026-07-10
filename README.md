# Tesaurus

Sovereign Bitcoin vault with a **local agent** recovery co-signer.

Tesaurus encodes a decaying 2-of-3 policy on-chain with [Miniscript](https://bitcoin.sipa.be/miniscript/):

```text
thresh(2, pk(primary), pk(override), and(pk(agent), older(csv)))
```

| Path | Keys | When |
|------|------|------|
| Primary | primary + override | Always |
| Recovery | primary + agent (or any other 2-of-3) | After `csv` confirmations on the coin |

The agent is a local process you run. It holds the agent key and will only co-sign when its policy allows (timelock mature, amount caps, optional allowlist).

## Status

This is a working vault implementation (descriptor, signing, Bitcoin Core watch-only sync, agent HTTP co-signer). Use **testnet/regtest** first. Mainnet requires your own operational security review — see [SECURITY.md](SECURITY.md).

## Prerequisites

- Rust 1.85+
- Bitcoin Core 25+ with RPC (wallet support)
- Linux/macOS recommended

## Quick start (regtest)

```bash
# 1. Bitcoin Core regtest
docker compose up -d bitcoind
bitcoin-cli -regtest -rpcuser=tesaurus -rpcpassword=changeme createwallet miner
bitcoin-cli -regtest -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner \
  -generate 101

# 2. Build Tesaurus
cargo build --release

# 3. Configure + keys + vault
cp config/tesaurus.regtest.toml config/tesaurus.toml
./target/release/tesaurus -c config/tesaurus.toml keys generate
./target/release/tesaurus -c config/tesaurus.toml init-vault
./target/release/tesaurus -c config/tesaurus.toml import-watch
ADDR=$(./target/release/tesaurus -c config/tesaurus.toml address | head -1)

# 4. Fund vault
bitcoin-cli -regtest -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner \
  sendtoaddress "$ADDR" 1
bitcoin-cli -regtest -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner -generate 1

# 5. Primary spend (primary + override)
./target/release/tesaurus -c config/tesaurus.toml status
DEST=$(bitcoin-cli -regtest -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner getnewaddress)
./target/release/tesaurus -c config/tesaurus.toml spend \
  --to "$DEST" --amount-sats 100000 --fee-sats 1000 --path primary --broadcast

# 6. Recovery spend after CSV maturity
bitcoin-cli -regtest -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner -generate 10
./target/release/tesaurus-agent -c config/tesaurus.toml &
./target/release/tesaurus -c config/tesaurus.toml spend \
  --to "$DEST" --amount-sats 50000 --fee-sats 1000 --path recovery --via-agent --broadcast
```

## Commands

| Command | Purpose |
|---------|---------|
| `tesaurus init-config` | Write example `tesaurus.toml` |
| `tesaurus keys generate` | Create primary / override / agent WIF files |
| `tesaurus init-vault` | Compile miniscript descriptor + save vault state |
| `tesaurus import-watch` | Import descriptor into Bitcoin Core (watch-only) |
| `tesaurus address` | Print receive address + descriptor |
| `tesaurus status` | Balances / UTXOs / CSV maturity |
| `tesaurus spend` | Build, sign, optionally broadcast |
| `tesaurus-agent` | Run local agent co-signer HTTP API |

## Architecture

```text
┌─────────────┐     watch-only      ┌──────────────┐
│  tesaurus   │◄───────────────────►│ Bitcoin Core │
│  CLI/wallet │   listunspent /     │  (RPC)       │
└──────┬──────┘   sendrawtransaction└──────────────┘
       │
       │ primary path: sign with primary+override locally
       │ recovery path: POST /v1/sign ──► tesaurus-agent
       ▼
┌─────────────────┐
│ tesaurus-agent  │  holds agent.wif, enforces policy
└─────────────────┘
```

## Production notes

- Prefer cookie auth over password RPC where possible.
- Set a strong `agent.api_token` and bind the agent to localhost (or a private network).
- Increase `csv_blocks` for mainnet (e.g. weeks/months), not 10 blocks.
- Back up `data/vault.json` (descriptor) and all three WIF files separately.
- The descriptor alone cannot spend funds; losing keys without backup is permanent loss.
- `--via-agent` currently sends the primary WIF to the agent over HTTP for co-signing. Only use on localhost with a token, or use local recovery (`--path recovery` without `--via-agent`) so both keys stay on one machine.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- Inspired by [Liana](https://github.com/wizardsardine/liana) (Wizardsardine) and AnchorWatch-style recovery keyholders.
- Built on [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) and [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript).
