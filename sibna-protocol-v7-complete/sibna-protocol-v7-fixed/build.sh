#!/bin/bash
# Build script for Sibna Protocol

set -e

echo "Building Sibna Protocol v7.0.0..."

# Build Rust core
echo "Building Rust core..."
cd core
cargo build --release
cargo test

# Build WASM
echo "Building WASM bindings..."
cd ../wasm
wasm-pack build --target web --out-dir pkg

# Build Web Client
echo "Building Web Client..."
cd ../web-client
npm install
npm run build

echo "Build complete!"
