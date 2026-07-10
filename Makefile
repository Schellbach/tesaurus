.PHONY: build release test fmt clippy clean example-config

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings

clean:
	cargo clean

example-config:
	cargo run --bin tesaurus -- init-config --path config/tesaurus.toml --network testnet --force
