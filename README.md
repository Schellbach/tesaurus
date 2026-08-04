# Tesaurus

> [!CAUTION]
> **Research software only. Mainnet and network co-signing are disabled in code.**
> Tesaurus has not received an independent audit. Use regtest or testnet only,
> never use meaningful funds, and read [SECURITY.md](SECURITY.md).

Tesaurus explores a decaying 2-of-3 Bitcoin vault enforced on-chain with
[Miniscript](https://bitcoin.sipa.be/miniscript/):

```text
thresh(2, pk(primary), pk(override), and(pk(agent), older(csv)))
```

| Path | Keys | Availability |
|---|---|---|
| Primary | primary + override | Always |
| Recovery | any valid 2-of-3 including the agent branch | After `csv` confirmations |

The key named `agent` is currently just the third local research key. The former
HTTP co-signer transmitted primary key material and has been removed from the
active library. `tesaurus-agent` and `--via-agent` now fail closed while a
PSBT-only protocol is designed and reviewed.

## Containment status

- Mainnet configuration is rejected.
- No process listens for co-signing requests.
- No WIF is serialized or sent over HTTP.
- Local signing fails unless all required keys are present.
- Vault metadata is checked against a canonical descriptor before use.
- Config, vault-state, and WIF files require owner-only Unix permissions.
- Bitcoin Core RPC is restricted to numeric loopback addresses and its network
  must match the configured research network.
- Transaction arithmetic is checked, fees/input counts have research caps, and
  Core must accept the signed transaction before broadcast.
- The Docker image contains only the local CLI.

These controls reduce accidental exposure; they do not make the software
production-ready.

## Working research surface

- Miniscript descriptor compilation and sanity checks
- P2WSH primary and recovery signing with local keys
- Bitcoin Core watch-only synchronization and broadcast
- Regtest/testnet/signet configuration

## Prerequisites

- Rust 1.85
- Bitcoin Core 25+ with wallet RPC enabled
- Linux or macOS

## Build

```bash
git clone https://github.com/Schellbach/tesaurus.git
cd tesaurus
cargo build --release --locked
```

The active binary is `target/release/tesaurus`. The
`target/release/tesaurus-agent` placeholder exits with a containment message.

## Configuration

Generate a private-mode example:

```bash
./target/release/tesaurus init-config \
  --path config/tesaurus.toml \
  --network testnet
```

Supported networks are `regtest`, `testnet`, and `signet`. Mainnet is rejected.
Prefer Bitcoin Core cookie authentication. Never commit RPC credentials, WIFs,
cookies, or local configuration containing secrets.

| Section | Field | Meaning |
|---|---|---|
| `[bitcoin]` | `network`, `rpc_url`, authentication | Watch-only Core connection |
| `[bitcoin]` | `wallet_name` | Wallet Tesaurus creates/loads |
| `[vault]` | `csv_blocks` | Relative recovery delay |
| `[vault]` | `keys_dir`, `state_path` | Local research keys and canonical vault state |

## Regtest

Run the smoke test when `bitcoind` is available:

```bash
./scripts/regtest-e2e.sh
```

Or run the core flow:

```bash
cp config/tesaurus.regtest.toml config/tesaurus.toml
chmod 600 config/tesaurus.toml
cargo build --release --locked

./target/release/tesaurus -c config/tesaurus.toml keys generate
./target/release/tesaurus -c config/tesaurus.toml init-vault
./target/release/tesaurus -c config/tesaurus.toml import-watch
./target/release/tesaurus -c config/tesaurus.toml address
./target/release/tesaurus -c config/tesaurus.toml status
```

Primary spend:

```bash
./target/release/tesaurus -c config/tesaurus.toml spend \
  --to "$DEST" \
  --amount-sats 100000 \
  --fee-sats 1000 \
  --path primary \
  --broadcast
```

Local recovery after CSV maturity:

```bash
./target/release/tesaurus -c config/tesaurus.toml spend \
  --to "$DEST" \
  --amount-sats 50000 \
  --fee-sats 1000 \
  --path recovery \
  --broadcast
```

This local recovery loads primary and agent WIFs into one process and exists only
for regtest/testnet research. It is not the intended production custody model.
Signed transaction hex is hidden by default to reduce terminal/log disclosure;
pass `--show-transaction` only when the raw transaction is needed.

## Architecture

```text
┌──────────────────┐     watch-only / broadcast     ┌──────────────┐
│ tesaurus CLI     │◄──────────────────────────────►│ Bitcoin Core │
│ local research   │     listunspent / sendraw      │ no vault keys│
└──────────────────┘                                └──────────────┘

No HTTP signer is active.
```

## Development

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
```

The next security-sensitive milestone is a PSBT-only signer that:

1. cannot read primary or override keys;
2. pins one descriptor and network;
3. verifies UTXOs and confirmations independently through Bitcoin Core;
4. verifies every input, output, amount, change script, sequence, and fee;
5. returns only an additional partial signature.

## Security reporting

Do not publish suspected vulnerabilities in a GitHub issue. Follow the private
reporting instructions in [SECURITY.md](SECURITY.md).
Before changing repository visibility, complete
[OPEN_SOURCE_CHECKLIST.md](OPEN_SOURCE_CHECKLIST.md).

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- [Liana](https://github.com/wizardsardine/liana)
- [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)
- [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript)
