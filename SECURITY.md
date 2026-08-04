# Security Policy

Tesaurus is experimental custody research. No released version is supported for
mainnet or meaningful funds.

## Current containment boundary

- Mainnet configuration is rejected.
- The HTTP co-signer has been removed from the active library.
- `tesaurus-agent` and `--via-agent` fail closed.
- WIF material is never serialized for network transport.
- Only local regtest/testnet/signet signing remains.

Do not restore the legacy HTTP signer. Its request accepted caller-controlled
vault and UTXO metadata, could load `primary.wif`, and transported primary key
material. The replacement must be a separately reviewed PSBT-only design.
Historical commits retain that removed prototype for review; do not build or
deploy them.

## Private reporting

Do **not** open a public issue for a suspected vulnerability.

When the repository is public, use GitHub's private vulnerability reporting:

<https://github.com/Schellbach/tesaurus/security/advisories/new>

Include:

- the affected commit;
- exploit prerequisites and realistic impact;
- a minimal reproducer or failing test using synthetic regtest keys;
- the violated security invariant;
- a suggested mitigation, if known.

Never send real WIFs, seed phrases, RPC cookies, access tokens, wallet backups,
or transaction data tied to real funds.

Duplicate scanner output without a reachable code path or reproducer may be
closed without action.

## Security invariants

Reports are especially valuable when they show that code can:

1. operate on mainnet despite the containment guard;
2. send or log private-key material;
3. sign without the locally required key set;
4. accept vault metadata inconsistent with its descriptor;
5. redirect a payment or change output;
6. miscalculate an input total, output total, or fee;
7. bypass CSV maturity in a transaction accepted by Bitcoin consensus;
8. expose Bitcoin Core RPC beyond its intended local boundary.

## Known limitations

- No independent cryptographic or implementation audit has been completed.
- Local research flows place multiple WIFs on one machine.
- WIFs are plaintext files, protected primarily by filesystem permissions.
- Bitcoin Core, the OS, build host, and Rust dependency graph are trusted.
- Hardware signers, encrypted key stores, PSBT co-signing, replay controls, and
  production operational guidance are not implemented.
- Regtest examples use public development RPC credentials.
- Windows is not supported; Unix permission checks are required for local
  config, vault-state, and WIF files.

## On-chain policy

The intended script is:

```text
thresh(2, pk(primary), pk(override), and(pk(agent), older(csv)))
```

Before CSV maturity, spending requires primary + override. After maturity, the
agent branch can participate in a valid 2-of-3 satisfaction. Off-chain software
checks are defense in depth and must not be described as consensus guarantees.
