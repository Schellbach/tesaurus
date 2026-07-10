# Multi-stage production image for Tesaurus binaries.
FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 tesaurus
COPY --from=builder /app/target/release/tesaurus /usr/local/bin/tesaurus
COPY --from=builder /app/target/release/tesaurus-agent /usr/local/bin/tesaurus-agent
COPY config/tesaurus.toml /etc/tesaurus/tesaurus.toml
USER tesaurus
WORKDIR /home/tesaurus
EXPOSE 18480
ENTRYPOINT ["tesaurus"]
CMD ["--help"]
