#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

cd "$REPO_ROOT"

cargo ndk \
  -P 26 \
  -t arm64-v8a \
  -t armeabi-v7a \
  -t x86_64 \
  -o apps/android/app/src/main/jniLibs \
  build -p vdpi-android --release --locked
