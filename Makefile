.PHONY: build release test fmt fmt-check clippy audit verify clean example-config

build:
	cargo build --locked

release:
	cargo build --release --locked

test:
	cargo test --locked --workspace

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

clippy:
	cargo clippy --locked --workspace --all-targets -- -D warnings

audit:
	cargo audit

verify: fmt-check test clippy audit

clean:
	cargo clean

example-config:
	cargo run --bin tesaurus -- init-config --path config/tesaurus.toml --network testnet --force
