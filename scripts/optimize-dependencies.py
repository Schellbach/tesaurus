#!/usr/bin/env python3
"""
Dependency optimization script for Tesaurus project.
Analyzes and optimizes dependencies for better performance and smaller bundle sizes.
"""

import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple
import toml
import json

class DependencyOptimizer:
    """Analyzes and optimizes project dependencies"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.cargo_toml = project_root / "Cargo.toml"
        self.requirements_txt = project_root / "requirements.txt"
        
    def analyze_rust_dependencies(self) -> Dict[str, any]:
        """Analyze Rust dependencies for optimization opportunities"""
        if not self.cargo_toml.exists():
            return {}
        
        with open(self.cargo_toml, 'r') as f:
            cargo_data = toml.load(f)
        
        dependencies = cargo_data.get('dependencies', {})
        dev_dependencies = cargo_data.get('dev-dependencies', {})
        
        analysis = {
            'total_dependencies': len(dependencies),
            'dev_dependencies': len(dev_dependencies),
            'large_dependencies': [],
            'unused_features': [],
            'optimization_suggestions': []
        }
        
        # Check for large dependencies that could be optimized
        large_crates = {
            'tokio': 'Consider using only required features',
            'serde': 'Already optimized with derive feature',
            'reqwest': 'Consider using rustls-tls instead of default-tls',
            'bitcoin': 'Consider disabling unused features',
            'rusqlite': 'Using bundled feature for static linking'
        }
        
        for dep_name, suggestion in large_crates.items():
            if dep_name in dependencies:
                analysis['large_dependencies'].append({
                    'name': dep_name,
                    'suggestion': suggestion
                })
        
        # Check for feature optimization opportunities
        feature_optimizations = [
            "Use 'default-features = false' for large crates",
            "Enable only required features for tokio",
            "Use rustls instead of openssl for better performance",
            "Consider using 'lto = true' in release profile"
        ]
        
        analysis['optimization_suggestions'] = feature_optimizations
        
        return analysis
    
    def analyze_python_dependencies(self) -> Dict[str, any]:
        """Analyze Python dependencies for optimization opportunities"""
        if not self.requirements_txt.exists():
            return {}
        
        with open(self.requirements_txt, 'r') as f:
            lines = f.readlines()
        
        dependencies = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                dependencies.append(line.split('==')[0])
        
        analysis = {
            'total_dependencies': len(dependencies),
            'heavy_dependencies': [],
            'optimization_suggestions': []
        }
        
        # Identify heavy dependencies
        heavy_deps = {
            'pandas': 'Only use if data analysis is required',
            'torch': 'Use CPU-only version for inference',
            'tensorflow': 'Consider using ONNX runtime instead',
            'scipy': 'Large scientific computing library',
            'matplotlib': 'Heavy plotting library'
        }
        
        for dep in dependencies:
            if dep in heavy_deps:
                analysis['heavy_dependencies'].append({
                    'name': dep,
                    'suggestion': heavy_deps[dep]
                })
        
        # Optimization suggestions
        optimizations = [
            "Use uvloop for high-performance async event loop",
            "Consider using orjson instead of json for better performance",
            "Use cachetools for efficient caching",
            "Consider using pydantic for data validation",
            "Use psutil for system monitoring"
        ]
        
        analysis['optimization_suggestions'] = optimizations
        
        return analysis
    
    def find_unused_dependencies(self) -> List[str]:
        """Find potentially unused dependencies"""
        unused = []
        
        # This is a simplified check - in production, you'd use tools like
        # cargo-udeps for Rust or pip-check for Python
        
        # For demonstration, we'll check if imports exist in source files
        source_files = list(self.project_root.glob('src/**/*.rs'))
        source_content = ''
        
        for file in source_files:
            try:
                with open(file, 'r') as f:
                    source_content += f.read()
            except Exception:
                continue
        
        # Check for common unused patterns
        if 'serde_json' not in source_content and 'use serde_json' not in source_content:
            unused.append('serde_json (possibly unused)')
        
        return unused
    
    def generate_optimized_cargo_toml(self) -> str:
        """Generate an optimized Cargo.toml with better dependency configuration"""
        optimized_config = '''[package]
name = "tesaurus"
version = "0.1.0"
edition = "2021"

# Optimized release profile
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
strip = true

# Optimized dependencies with minimal features
[dependencies]
# Core Bitcoin functionality - minimal features
bitcoin = { version = "0.31", default-features = false, features = ["serde", "std"] }
bitcoincore-rpc = { version = "0.18", default-features = false }

# Async runtime - only required features
tokio = { version = "1.0", default-features = false, features = [
    "rt-multi-thread", "macros", "sync", "time", "net", "io-util"
] }

# Serialization - minimal features
serde = { version = "1.0", default-features = false, features = ["derive"] }
bincode = "1.3"  # Binary serialization for performance

# Cryptography - optimized features
secp256k1 = { version = "0.28", default-features = false, features = ["std", "recovery"] }

# HTTP client - rustls for better performance
reqwest = { version = "0.11", default-features = false, features = ["json", "rustls-tls"] }

# Database - bundled for static linking
rusqlite = { version = "0.30", features = ["bundled"] }
sled = "0.34"

# Performance-focused alternatives
parking_lot = "0.12"  # Faster than std::sync::Mutex
dashmap = "5.5"       # Concurrent HashMap
'''
        
        return optimized_config
    
    def generate_optimized_requirements(self) -> str:
        """Generate optimized Python requirements"""
        optimized_reqs = '''# Core dependencies - performance optimized
bitcoinlib==0.12.0
ecdsa==0.18.0

# Machine learning - minimal footprint
scikit-learn==1.3.0
numpy==1.24.3
joblib==1.3.2

# High-performance networking
aiohttp==3.8.5
uvloop==0.17.0  # High-performance event loop

# Efficient caching and data structures
cachetools==5.3.1
redis==4.6.0

# System monitoring - lightweight
psutil==5.9.5

# Fast JSON processing
orjson==3.9.2  # Faster than standard json

# Optional: Remove if not needed
# pandas==2.0.3  # Only if data analysis is required
'''
        
        return optimized_reqs
    
    def run_cargo_bloat_analysis(self) -> str:
        """Run cargo bloat to analyze binary size"""
        try:
            result = subprocess.run(
                ['cargo', 'bloat', '--release', '--crates'],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "cargo-bloat not available or timed out"
    
    def run_optimization_report(self) -> Dict[str, any]:
        """Generate a comprehensive optimization report"""
        report = {
            'rust_analysis': self.analyze_rust_dependencies(),
            'python_analysis': self.analyze_python_dependencies(),
            'unused_dependencies': self.find_unused_dependencies(),
            'binary_size_analysis': self.run_cargo_bloat_analysis(),
            'recommendations': self.get_optimization_recommendations()
        }
        
        return report
    
    def get_optimization_recommendations(self) -> List[str]:
        """Get specific optimization recommendations"""
        recommendations = [
            "🔧 Enable LTO (Link Time Optimization) in release builds",
            "📦 Use 'default-features = false' for large dependencies",
            "🚀 Consider using rustls instead of openssl for TLS",
            "💾 Use binary serialization (bincode) instead of JSON where possible",
            "🧵 Use parking_lot for faster mutex operations",
            "📊 Implement lazy loading for non-critical components",
            "🗜️ Enable compression for storage and network operations",
            "⚡ Use SIMD optimizations where applicable",
            "🎯 Profile-guided optimization (PGO) for hot paths",
            "📈 Implement efficient caching strategies",
            "🔄 Use async/await for non-blocking I/O operations",
            "🏗️ Consider using fewer codegen-units for better optimization",
            "🎨 Strip debug symbols in production builds",
            "📱 Use thin LTO for faster builds with good optimization"
        ]
        
        return recommendations

def main():
    """Main function to run dependency optimization analysis"""
    project_root = Path.cwd()
    optimizer = DependencyOptimizer(project_root)
    
    print("🔍 Analyzing Tesaurus dependencies for performance optimization...")
    print("=" * 70)
    
    report = optimizer.run_optimization_report()
    
    # Print Rust analysis
    rust_analysis = report['rust_analysis']
    if rust_analysis:
        print(f"\n📦 Rust Dependencies Analysis")
        print(f"Total dependencies: {rust_analysis['total_dependencies']}")
        print(f"Dev dependencies: {rust_analysis['dev_dependencies']}")
        
        if rust_analysis['large_dependencies']:
            print("\n🔍 Large Dependencies:")
            for dep in rust_analysis['large_dependencies']:
                print(f"  • {dep['name']}: {dep['suggestion']}")
    
    # Print Python analysis
    python_analysis = report['python_analysis']
    if python_analysis:
        print(f"\n🐍 Python Dependencies Analysis")
        print(f"Total dependencies: {python_analysis['total_dependencies']}")
        
        if python_analysis['heavy_dependencies']:
            print("\n⚠️  Heavy Dependencies:")
            for dep in python_analysis['heavy_dependencies']:
                print(f"  • {dep['name']}: {dep['suggestion']}")
    
    # Print unused dependencies
    unused = report['unused_dependencies']
    if unused:
        print(f"\n🗑️  Potentially Unused Dependencies:")
        for dep in unused:
            print(f"  • {dep}")
    
    # Print binary size analysis
    bloat_output = report['binary_size_analysis']
    if bloat_output and "not available" not in bloat_output:
        print(f"\n📊 Binary Size Analysis:")
        print(bloat_output[:500] + "..." if len(bloat_output) > 500 else bloat_output)
    
    # Print recommendations
    print(f"\n💡 Optimization Recommendations:")
    for rec in report['recommendations']:
        print(f"  {rec}")
    
    print(f"\n✅ Analysis complete! Consider implementing the recommendations above.")
    
    # Optionally save optimized configurations
    save_optimized = input("\n❓ Save optimized configuration files? (y/n): ").lower().strip()
    if save_optimized == 'y':
        # Save optimized Cargo.toml
        optimized_cargo = optimizer.generate_optimized_cargo_toml()
        with open(project_root / "Cargo.optimized.toml", 'w') as f:
            f.write(optimized_cargo)
        
        # Save optimized requirements.txt
        optimized_reqs = optimizer.generate_optimized_requirements()
        with open(project_root / "requirements.optimized.txt", 'w') as f:
            f.write(optimized_reqs)
        
        print("💾 Optimized configuration files saved:")
        print("  • Cargo.optimized.toml")
        print("  • requirements.optimized.txt")

if __name__ == "__main__":
    main()