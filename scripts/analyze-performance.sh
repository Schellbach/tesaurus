#!/bin/bash
# Performance analysis script for Tesaurus Bitcoin Vault
# Analyzes dependencies, bundle sizes, and performance bottlenecks

set -e

echo "🔍 Tesaurus Performance Analysis"
echo "================================"

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Cargo.toml not found. Please run from project root."
    exit 1
fi

echo ""
echo "📦 Analyzing Rust Dependencies..."
echo "----------------------------------"

# Check Cargo.toml for large dependencies
echo "Large dependencies found:"
grep -E "(tokio|serde|reqwest|bitcoin|rusqlite)" Cargo.toml | head -10

echo ""
echo "🔧 Build Configuration Analysis..."
echo "-----------------------------------"

# Check if release profile is optimized
if grep -q "opt-level = 3" Cargo.toml; then
    echo "✅ Release optimization level: 3 (maximum)"
else
    echo "⚠️  Release optimization could be improved"
fi

if grep -q "lto = true" Cargo.toml; then
    echo "✅ Link-time optimization enabled"
else
    echo "⚠️  Consider enabling LTO for better performance"
fi

if grep -q "codegen-units = 1" Cargo.toml; then
    echo "✅ Codegen units optimized for performance"
else
    echo "⚠️  Consider setting codegen-units = 1 for release builds"
fi

echo ""
echo "🐍 Python Dependencies Analysis..."
echo "-----------------------------------"

if [ -f "requirements.txt" ]; then
    echo "Python dependencies found:"
    wc -l requirements.txt | awk '{print $1 " dependencies"}'
    
    echo ""
    echo "Heavy dependencies:"
    grep -E "(pandas|torch|tensorflow|scipy|matplotlib)" requirements.txt || echo "None found"
    
    echo ""
    echo "Performance-optimized dependencies:"
    grep -E "(uvloop|orjson|cachetools|psutil)" requirements.txt || echo "Consider adding performance libraries"
else
    echo "❌ requirements.txt not found"
fi

echo ""
echo "🏗️  Build Size Analysis..."
echo "----------------------------"

if command -v cargo >/dev/null 2>&1; then
    echo "Checking if project builds..."
    if cargo check --quiet; then
        echo "✅ Project builds successfully"
        
        # Try to get binary size if it exists
        if [ -f "target/release/tesaurus-daemon" ]; then
            size=$(du -h target/release/tesaurus-daemon | cut -f1)
            echo "📊 Binary size: $size"
        else
            echo "💡 Run 'cargo build --release' to analyze binary size"
        fi
    else
        echo "⚠️  Build issues detected - check dependencies"
    fi
else
    echo "❌ Cargo not found - install Rust toolchain"
fi

echo ""
echo "⚡ Performance Optimization Recommendations:"
echo "============================================="

cat << 'EOF'
🔧 Rust Optimizations:
  • Enable LTO (Link Time Optimization) in release profile
  • Use 'opt-level = 3' for maximum optimization
  • Set 'codegen-units = 1' for better optimization
  • Use 'panic = "abort"' to reduce binary size
  • Consider 'strip = true' to remove debug symbols

📦 Dependency Optimizations:
  • Use 'default-features = false' for large crates
  • Enable only required features for tokio
  • Use rustls instead of openssl for TLS
  • Consider parking_lot for faster mutexes
  • Use dashmap for concurrent data structures

🐍 Python Optimizations:
  • Use uvloop for high-performance async event loop
  • Consider orjson instead of standard json
  • Use cachetools for efficient caching
  • Minimize heavy dependencies like pandas/scipy
  • Use CPU-only versions of ML libraries

🚀 Runtime Optimizations:
  • Implement async/await patterns
  • Use connection pooling for network operations
  • Enable compression for storage/network
  • Implement efficient caching strategies
  • Use SIMD optimizations where applicable

📊 Monitoring & Profiling:
  • Enable metrics collection
  • Use profiling tools (perf, flamegraph)
  • Monitor memory usage and allocation patterns
  • Track performance regressions in CI/CD

🏗️  Build Optimizations:
  • Use parallel compilation
  • Enable incremental compilation for dev builds
  • Use sccache for build caching
  • Consider using mold/lld linker for faster linking
EOF

echo ""
echo "✅ Analysis complete!"
echo ""
echo "💡 Next steps:"
echo "  1. Review the recommendations above"
echo "  2. Run 'cargo build --release' to build optimized binary"
echo "  3. Use 'cargo bench' to run performance benchmarks"
echo "  4. Profile the application with production workloads"
echo "  5. Monitor performance metrics in production"

echo ""
echo "🔗 Useful commands:"
echo "  • cargo build --release          # Build optimized binary"
echo "  • cargo bench                    # Run benchmarks"
echo "  • cargo tree                     # Analyze dependency tree"
echo "  • cargo audit                    # Security audit"
echo "  • cargo outdated                 # Check for updates"