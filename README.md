# Tesaurus
**Tesaurus** is an open-source Bitcoin vault built on [Liana](https://github.com/wizardsardine/liana), blending self-sovereign custody with agent recovery. Inspired by AnchorWatch’s Trident Vault, it swaps their Isle of Man keyholder for a locally run agent as the preferred key holder. It’s a 2-of-3 multisig where the agent co-signs after a certain number of blocks of inactivity. We use 10 blocks/~2 hours on testnet.
## Features
- Sovereign: User controls all keys, agent is local.
- Agent Recovery: Post-10 blocks, agent co-signs with primary key.
- Override: Primary + override keys bypass agent.
- Testnet: Runs on Bitcoin testnet.
- Open-Source: Rust + Python, auditable.
## How It Works
- Pre-Inactivity: Primary + Override (Key 1 + Key 2).
- Post-Inactivity: Primary + Agent Key after 10 blocks.
- Sovereignty: Override stays active; Agent Key backup ensures recovery.
## Prerequisites
- Bitcoin Core: Testnet node (v24.0+).
- Rust: Stable (rustup update).
- Python: 3.8+ (pip install bitcoinlib scikit-learn).
- Hardware: Laptop or Raspberry Pi.
## Installation
1. Clone Repository: git clone https://github.com/<your-username>/tesaurus.git, then cd tesaurus.
2. Build the Rust Backend: cargo build --release.
3. Set Up Bitcoin Testnet: Config (~/.bitcoin/bitcoin.conf): testnet=1, server=1, rpcuser=testuser, rpcpassword=testpass, txindex=1. Start: bitcoind -testnet -daemon.
## Configuration
1. Generate Keys:
   - Primary (Key 1): bitcoin-cli -testnet getnewaddress, export WIF with dumpprivkey.
   - Override (Key 2): Same process.
   - Agent Key: Generate, export WIF (e.g., tprvAI...).
2. Update Agent Module: Edit agent_vault.py, set agent = OptimizedAgentEngine("tprvAI...").
3. Set Up Wallet: Run cargo run --release --bin liana-gui --network testnet, input pubkeys for Key 1, Key 2, Agent Key (from getaddressinfo), save address (e.g., tb1qvault...).
## Usage
1. Start agent: python agent_vault.py &.
2. Run Daemon: cargo run --release --bin lianad --network testnet --rpcuser=testuser --rpcpassword=testpass.
3. Fund Vault: Send 1 tBTC from coinfaucet.eu/en/btc-testnet to tb1qvault....
4. Spend:
   - Pre-Inactivity: Use Liana GUI/CLI with Key 1 + Key 2.
   - Post-Inactivity: Wait 10 blocks (bitcoin-cli -testnet generate 10), send with Key 1—agent co-signs.
## Testing
Test cases:
1. Pre-Inactivity: Send 0.1 tBTC with Key 1 + Key 2. *Expect*: Instant, agent dormant.
2. Post-Inactivity: Generate 10 blocks (bitcoin-cli -testnet generate 10), send 0.6 tBTC with Key 1. *Expect*: agent signs, tx succeeds.
3. Override: Post-10 blocks, kill agent (pkill python), send 0.3 tBTC with Key 1 + Key 2. *Expect*: Tx succeeds.
4. Manual Recovery: Post-10 blocks, use Agent Key WIF (bitcoin-cli -testnet signrawtransactionwithkey). *Expect*: Tx succeeds.
## Sovereignty Guarantee
- No Third Parties: Agent is local, replaces AnchorWatch’s keyholder.
- User Control: You manage all keys.
- Override: Key 1 + Key 2 always works.
## Contributing
Fork, submit PRs (e.g., mainnet timers), audit: src/wallet.rs, src/descriptor.rs, agent_vault.py.
## License
MIT—see [LICENSE](LICENSE).
## Acknowledgments
- Based on [Liana](https://github.com/wizardsardine/liana) by Wizardsardine.
- Inspired by [AnchorWatch](https://anchorwatch.com).
## Contact
Open a GitHub issue.
