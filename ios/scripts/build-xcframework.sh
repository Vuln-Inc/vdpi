#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$REPO_ROOT/ios/Frameworks"
XCFRAMEWORK="$OUT_DIR/VdpiCore.xcframework"
HEADERS_DIR="$REPO_ROOT/crates/vdpi-ios/include"

cd "$REPO_ROOT"

# Ensure required Apple targets are installed
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# Cross-compile static libraries for physical iOS (arm64) and iOS Simulator (arm64 + x86_64)
cargo build -p vdpi-ios --release --locked --target aarch64-apple-ios
cargo build -p vdpi-ios --release --locked --target aarch64-apple-ios-sim
cargo build -p vdpi-ios --release --locked --target x86_64-apple-ios

SIM_FAT_DIR="$REPO_ROOT/target/ios-sim-universal/release"
mkdir -p "$SIM_FAT_DIR" "$OUT_DIR"

lipo -create \
  "$REPO_ROOT/target/aarch64-apple-ios-sim/release/libvdpi_ios.a" \
  "$REPO_ROOT/target/x86_64-apple-ios/release/libvdpi_ios.a" \
  -output "$SIM_FAT_DIR/libvdpi_ios.a"

rm -rf "$XCFRAMEWORK"

xcodebuild -create-xcframework \
  -library "$REPO_ROOT/target/aarch64-apple-ios/release/libvdpi_ios.a" \
  -headers "$HEADERS_DIR" \
  -library "$SIM_FAT_DIR/libvdpi_ios.a" \
  -headers "$HEADERS_DIR" \
  -output "$XCFRAMEWORK"

echo "Built $XCFRAMEWORK"
