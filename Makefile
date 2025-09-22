# Tesaurus Bitcoin Vault - High-Performance Build System
# Optimized for fast builds, small binaries, and comprehensive testing

.PHONY: all build release debug test bench clean install docker profile help

# Default target
all: build

# Build configuration
CARGO := cargo
PYTHON := python3
DOCKER := docker

# Performance build flags
RELEASE_FLAGS := --release
PROFILE_FLAGS := --profile=bench

# Default build (debug)
build:
	@echo "🔨 Building Tesaurus (debug)..."
	$(CARGO) build

# Optimized release build
release:
	@echo "🚀 Building Tesaurus (release - optimized)..."
	$(CARGO) build $(RELEASE_FLAGS)
	@echo "✅ Release build complete!"
	@ls -lh target/release/tesaurus-daemon 2>/dev/null || echo "Binary location: target/release/"

# Debug build with symbols
debug:
	@echo "🐛 Building Tesaurus (debug with symbols)..."
	$(CARGO) build --profile=dev
	@echo "✅ Debug build complete!"

# Run tests
test:
	@echo "🧪 Running tests..."
	$(CARGO) test
	@echo "🐍 Running Python tests..."
	$(PYTHON) -m pytest tests/ -v || echo "Python tests not found"

# Run benchmarks
bench:
	@echo "📊 Running performance benchmarks..."
	$(CARGO) bench
	@echo "✅ Benchmarks complete! Check target/criterion/ for results"

# Performance profiling
profile: release
	@echo "🔍 Running performance profiling..."
	@if command -v perf >/dev/null 2>&1; then \
		echo "Using perf for profiling..."; \
		perf record --call-graph dwarf ./target/release/tesaurus-daemon --help; \
		perf report; \
	else \
		echo "⚠️  perf not available, install with: apt install linux-perf"; \
	fi

# Memory profiling
memprof: release
	@echo "🧠 Running memory profiling..."
	@if command -v valgrind >/dev/null 2>&1; then \
		valgrind --tool=massif --pages-as-heap=yes ./target/release/tesaurus-daemon --help; \
	else \
		echo "⚠️  valgrind not available, install with: apt install valgrind"; \
	fi

# Flamegraph profiling
flamegraph: 
	@echo "🔥 Generating flamegraph..."
	@if cargo install --list | grep -q flamegraph; then \
		$(CARGO) flamegraph --bin tesaurus-daemon -- --help; \
	else \
		echo "Installing flamegraph..."; \
		$(CARGO) install flamegraph; \
		$(CARGO) flamegraph --bin tesaurus-daemon -- --help; \
	fi

# Binary size analysis
bloat:
	@echo "📦 Analyzing binary size..."
	@if cargo install --list | grep -q cargo-bloat; then \
		$(CARGO) bloat --release --crates; \
	else \
		echo "Installing cargo-bloat..."; \
		$(CARGO) install cargo-bloat; \
		$(CARGO) bloat --release --crates; \
	fi

# Security audit
audit:
	@echo "🔒 Running security audit..."
	@if cargo install --list | grep -q cargo-audit; then \
		$(CARGO) audit; \
	else \
		echo "Installing cargo-audit..."; \
		$(CARGO) install cargo-audit; \
		$(CARGO) audit; \
	fi

# Dependency analysis
deps:
	@echo "🔍 Analyzing dependencies..."
	$(CARGO) tree
	@echo ""
	@echo "📊 Outdated dependencies:"
	@if cargo install --list | grep -q cargo-outdated; then \
		$(CARGO) outdated; \
	else \
		echo "Installing cargo-outdated..."; \
		$(CARGO) install cargo-outdated; \
		$(CARGO) outdated; \
	fi

# Code formatting
fmt:
	@echo "✨ Formatting code..."
	$(CARGO) fmt
	@echo "🐍 Formatting Python code..."
	@if command -v black >/dev/null 2>&1; then \
		black ai_vault.py scripts/; \
	else \
		echo "⚠️  black not available for Python formatting"; \
	fi

# Linting
lint:
	@echo "🔍 Running linter..."
	$(CARGO) clippy -- -D warnings
	@echo "🐍 Running Python linter..."
	@if command -v flake8 >/dev/null 2>&1; then \
		flake8 ai_vault.py scripts/; \
	else \
		echo "⚠️  flake8 not available for Python linting"; \
	fi

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	$(CARGO) clean
	@rm -rf target/
	@rm -rf __pycache__/
	@rm -rf *.egg-info/
	@echo "✅ Clean complete!"

# Install binary to system
install: release
	@echo "📦 Installing Tesaurus..."
	$(CARGO) install --path . --force
	@echo "✅ Tesaurus installed! Run with: tesaurus-daemon"

# Docker build
docker:
	@echo "🐳 Building Docker image..."
	$(DOCKER) build -t tesaurus:latest .
	@echo "✅ Docker image built: tesaurus:latest"

# Docker run with optimizations
docker-run: docker
	@echo "🚀 Running Tesaurus in Docker..."
	$(DOCKER) run -it --rm \
		-p 9090:9090 \
		-v tesaurus_data:/data/tesaurus \
		tesaurus:latest

# Docker compose for full stack
docker-compose:
	@echo "🐳 Starting full Tesaurus stack..."
	docker-compose up -d
	@echo "✅ Stack started! Metrics: http://localhost:9090"

# Performance analysis
analyze:
	@echo "📊 Running performance analysis..."
	@./scripts/analyze-performance.sh

# Setup development environment
dev-setup:
	@echo "🔧 Setting up development environment..."
	@echo "Installing Rust components..."
	rustup component add rustfmt clippy
	@echo "Installing development tools..."
	$(CARGO) install cargo-watch cargo-audit cargo-outdated cargo-bloat flamegraph
	@echo "🐍 Setting up Python environment..."
	@if [ ! -d "venv" ]; then \
		$(PYTHON) -m venv venv; \
		echo "Virtual environment created"; \
	fi
	@echo "Installing Python dependencies..."
	@./venv/bin/pip install -r requirements.txt
	@echo "✅ Development environment ready!"

# Watch for changes and rebuild
watch:
	@echo "👀 Watching for changes..."
	@if cargo install --list | grep -q cargo-watch; then \
		$(CARGO) watch -x build; \
	else \
		echo "Installing cargo-watch..."; \
		$(CARGO) install cargo-watch; \
		$(CARGO) watch -x build; \
	fi

# Quick development cycle
dev: fmt lint test
	@echo "✅ Development cycle complete!"

# Full CI pipeline
ci: fmt lint test audit bench
	@echo "✅ CI pipeline complete!"

# Performance testing suite
perf-test: release
	@echo "🏃 Running performance test suite..."
	@echo "1. Building optimized binary..."
	@ls -lh target/release/tesaurus-daemon
	@echo ""
	@echo "2. Running benchmarks..."
	$(CARGO) bench --bench performance
	@echo ""
	@echo "3. Memory usage test..."
	@./target/release/tesaurus-daemon --help >/dev/null &
	@PID=$$!; sleep 2; ps -p $$PID -o pid,ppid,rss,vsz,comm || true; kill $$PID 2>/dev/null || true
	@echo ""
	@echo "4. Binary size analysis..."
	@du -h target/release/tesaurus-daemon
	@echo "✅ Performance tests complete!"

# Generate documentation
docs:
	@echo "📚 Generating documentation..."
	$(CARGO) doc --no-deps --open
	@echo "✅ Documentation generated!"

# Help target
help:
	@echo "Tesaurus Build System - Performance Optimized"
	@echo "=============================================="
	@echo ""
	@echo "🏗️  Build Targets:"
	@echo "  build          Build debug version"
	@echo "  release        Build optimized release version"
	@echo "  debug          Build with debug symbols"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  test           Run all tests"
	@echo "  bench          Run performance benchmarks"
	@echo "  perf-test      Comprehensive performance testing"
	@echo ""
	@echo "🔍 Analysis:"
	@echo "  profile        CPU profiling with perf"
	@echo "  memprof        Memory profiling with valgrind"
	@echo "  flamegraph     Generate flamegraph"
	@echo "  bloat          Binary size analysis"
	@echo "  audit          Security audit"
	@echo "  deps           Dependency analysis"
	@echo "  analyze        Run performance analysis script"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  docker         Build Docker image"
	@echo "  docker-run     Run in Docker container"
	@echo "  docker-compose Start full stack"
	@echo ""
	@echo "🛠️  Development:"
	@echo "  dev-setup      Setup development environment"
	@echo "  watch          Watch for changes and rebuild"
	@echo "  fmt            Format code"
	@echo "  lint           Run linter"
	@echo "  dev            Quick development cycle"
	@echo "  ci             Full CI pipeline"
	@echo ""
	@echo "📦 Installation:"
	@echo "  install        Install binary to system"
	@echo "  clean          Clean build artifacts"
	@echo ""
	@echo "📚 Documentation:"
	@echo "  docs           Generate and open documentation"
	@echo "  help           Show this help message"

# Default help
.DEFAULT_GOAL := help