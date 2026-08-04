# Multi-stage research image for the local Tesaurus CLI.
FROM rust:1.97-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin tesaurus

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 tesaurus
COPY --from=builder /app/target/release/tesaurus /usr/local/bin/tesaurus
USER tesaurus
WORKDIR /home/tesaurus
ENTRYPOINT ["tesaurus"]
CMD ["--help"]
