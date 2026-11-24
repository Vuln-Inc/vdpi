#!/bin/sh
# vdpi installer for macOS and Linux
# Usage: curl -fsSL https://vuln-inc.github.io/vdpi/install.sh | sh
set -eu

REPO="Vuln-Inc/vdpi"
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    ASSET="vdpi-macos-universal.tar.gz"
    ;;
  Linux)
    case "$ARCH" in
      x86_64|amd64) ASSET="vdpi-linux-x86_64.tar.gz" ;;
      aarch64|arm64) ASSET="vdpi-linux-arm64.tar.gz" ;;
      *)
        echo "error: unsupported Linux architecture: $ARCH" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    echo "error: unsupported OS: $OS" >&2
    exit 1
    ;;
esac

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM

BASE_URL="https://github.com/$REPO/releases/latest/download"
ARCHIVE="$TMP_DIR/$ASSET"
SUMS="$TMP_DIR/SHA256SUMS.txt"

echo "Downloading $ASSET..."
curl -fsSL --proto '=https' --tlsv1.2 "$BASE_URL/$ASSET" -o "$ARCHIVE"
curl -fsSL --proto '=https' --tlsv1.2 "$BASE_URL/SHA256SUMS.txt" -o "$SUMS"

EXPECTED="$(awk -v file="$ASSET" '{ f=$2; sub(/^\*/, "", f); if (f == file) { print tolower($1); exit } }' "$SUMS")"
if [ -z "$EXPECTED" ]; then
  echo "error: checksum for $ASSET not found in SHA256SUMS.txt" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$ARCHIVE" | awk '{print tolower($1)}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "$ARCHIVE" | awk '{print tolower($1)}')"
else
  echo "error: sha256sum or shasum is required for integrity verification" >&2
  exit 1
fi

if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "error: SHA-256 mismatch for $ASSET (expected $EXPECTED, got $ACTUAL)" >&2
  exit 1
fi

echo "SHA-256 verified."
tar -xzf "$ARCHIVE" -C "$TMP_DIR" vdpi
chmod 755 "$TMP_DIR/vdpi"

INSTALL_DIR="${VDPI_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"
mv "$TMP_DIR/vdpi" "$INSTALL_DIR/vdpi"

if [ "$OS" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then
  codesign -fs - "$INSTALL_DIR/vdpi" >/dev/null 2>&1 || true
fi

echo "Installed vdpi to $INSTALL_DIR/vdpi"
case ":${PATH:-}:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Note: add $INSTALL_DIR to your PATH (or run '$INSTALL_DIR/vdpi install' for background service + PATH setup)." ;;
esac
echo "Run 'vdpi install' for automatic background startup, or 'vdpi start' for the live dashboard."
