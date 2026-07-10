# Multi-stage Docker build optimized for performance and size

# Build stage with performance optimizations
FROM rust:1.75-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    lld \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables for optimal builds
ENV RUSTFLAGS="-C target-cpu=native -C link-arg=-fuse-ld=lld"
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo

# Build dependencies first for better caching
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -f target/release/deps/tesaurus*

# Copy source code
COPY src ./src
COPY benches ./benches

# Build the application with optimizations
RUN cargo build --release --bin tesaurus-daemon

# Runtime stage with minimal footprint
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

# Create non-root user for security
RUN groupadd -r tesaurus && useradd -r -g tesaurus tesaurus

# Create data directories
RUN mkdir -p /data/tesaurus /logs && \
    chown -R tesaurus:tesaurus /data /logs

# Copy binary from builder stage
COPY --from=builder /app/target/release/tesaurus-daemon /usr/local/bin/

# Copy configuration template
COPY docker/tesaurus.toml /etc/tesaurus/tesaurus.toml

# Set user and working directory
USER tesaurus
WORKDIR /data/tesaurus

# Expose metrics port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

# Default command
CMD ["tesaurus-daemon", "--config", "/etc/tesaurus/tesaurus.toml"]

# Build-time metadata
LABEL org.opencontainers.image.title="Tesaurus Bitcoin Vault"
LABEL org.opencontainers.image.description="High-performance Bitcoin vault with AI recovery"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.vendor="Tesaurus Team"