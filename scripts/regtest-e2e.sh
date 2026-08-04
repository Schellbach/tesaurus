#!/usr/bin/env bash
# Regtest smoke test against a local bitcoind.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BITCOIN_BIN="${BITCOIN_BIN:-}"
if [[ -z "$BITCOIN_BIN" ]]; then
  if command -v bitcoind >/dev/null; then
    BITCOIN_BIN="$(dirname "$(command -v bitcoind)")"
  elif [[ -x /tmp/bitcoin-28.0/bin/bitcoind ]]; then
    BITCOIN_BIN=/tmp/bitcoin-28.0/bin
  else
    echo "bitcoind not found; set BITCOIN_BIN" >&2
    exit 1
  fi
fi
export PATH="$BITCOIN_BIN:$PATH"

DATADIR="${DATADIR:-/tmp/tesaurus-regtest-datadir}"
WORK="${WORK:-/tmp/tesaurus-regtest-work}"
TES="$ROOT/target/release/tesaurus"

cargo build --release --manifest-path "$ROOT/Cargo.toml"

if [[ "$DATADIR" != /tmp/tesaurus-* || "$WORK" != /tmp/tesaurus-* ]]; then
  echo "refusing to delete non-Tesaurus paths: DATADIR=$DATADIR WORK=$WORK" >&2
  exit 1
fi
rm -rf -- "$DATADIR" "$WORK"
mkdir -p "$DATADIR" "$WORK"
cp "$ROOT/config/tesaurus.regtest.toml" "$WORK/tesaurus.toml"
chmod 600 "$WORK/tesaurus.toml"

bitcoind -regtest -datadir="$DATADIR" -server -txindex -fallbackfee=0.0002 \
  -rpcuser=tesaurus -rpcpassword=changeme -rpcport=18443 -daemon
cleanup() {
  bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=tesaurus -rpcpassword=changeme stop >/dev/null 2>&1 || true
}
trap cleanup EXIT
sleep 2

bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=tesaurus -rpcpassword=changeme createwallet miner >/dev/null
bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner -generate 101 >/dev/null

cd "$WORK"
"$TES" -c tesaurus.toml keys generate
"$TES" -c tesaurus.toml init-vault
ADDR="$("$TES" -c tesaurus.toml address | head -1)"
"$TES" -c tesaurus.toml import-watch

bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner sendtoaddress "$ADDR" 1 >/dev/null
bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner -generate 1 >/dev/null
DEST="$(bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner getnewaddress)"

"$TES" -c tesaurus.toml spend --to "$DEST" --amount-sats 100000 --fee-sats 1000 --path primary --broadcast >/dev/null
bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner -generate 1 >/dev/null

bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner sendtoaddress "$ADDR" 0.5 >/dev/null
bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=tesaurus -rpcpassword=changeme -rpcwallet=miner -generate 10 >/dev/null
"$TES" -c tesaurus.toml spend --to "$DEST" --amount-sats 50000 --fee-sats 1000 --path recovery --broadcast >/dev/null

echo "regtest e2e OK"
