#!/bin/sh
set -eu

REPO="Vuln-Inc/vdpi"
OS="$(uname -s)"
ARCH="$(uname -m)"

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || { echo "error: required command '$1' not found" >&2; exit 1; }
}

need_cmd curl

verify_sha256() {
    file="$1"
    expected="$2"
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    else
        echo "error: sha256sum or shasum is required to verify downloads" >&2
        exit 1
    fi
    if [ "$actual" != "$expected" ]; then
        echo "error: SHA-256 mismatch for $file (expected $expected, got $actual)" >&2
        exit 1
    fi
}

TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
if [ -z "$TAG" ]; then
    echo "error: could not resolve latest release tag" >&2
    exit 1
fi

BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -fsSL "${BASE_URL}/SHA256SUMS.txt" -o "${TMP_DIR}/SHA256SUMS.txt"

if [ "$OS" = "Darwin" ]; then
    ASSET="vdpi-desktop-macos-universal.dmg"
    EXPECTED="$(awk -v a="$ASSET" '$2 == a {print $1; exit}' "${TMP_DIR}/SHA256SUMS.txt")"
    [ -n "$EXPECTED" ] || { echo "error: checksum missing for $ASSET" >&2; exit 1; }
    echo "Downloading vdpi Desktop ${TAG} (${ASSET})..."
    curl -fsSL "${BASE_URL}/${ASSET}" -o "${TMP_DIR}/${ASSET}"
    verify_sha256 "${TMP_DIR}/${ASSET}" "$EXPECTED"
    MOUNT_DIR="${TMP_DIR}/mnt"
    mkdir -p "$MOUNT_DIR"
    hdiutil attach "${TMP_DIR}/${ASSET}" -nobrowse -quiet -mountpoint "$MOUNT_DIR"
    rm -rf "/Applications/vdpi Desktop.app"
    cp -R "${MOUNT_DIR}/vdpi Desktop.app" "/Applications/vdpi Desktop.app"
    hdiutil detach "$MOUNT_DIR" -quiet || true
    echo "Installed /Applications/vdpi Desktop.app (${TAG})."
    exit 0
fi

if [ "$OS" != "Linux" ]; then
    echo "error: unsupported OS '${OS}'" >&2
    exit 1
fi

if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "amd64" ]; then
    echo "vdpi Desktop GUI binaries are currently x86_64 on Linux; installing CLI/TUI instead..."
    exec sh -c "$(curl -fsSL https://vuln-inc.github.io/vdpi/install.sh)"
fi

if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
    ASSET="vdpi-desktop-linux-x86_64.deb"
    EXPECTED="$(awk -v a="$ASSET" '$2 == a {print $1; exit}' "${TMP_DIR}/SHA256SUMS.txt")"
    [ -n "$EXPECTED" ] || { echo "error: checksum missing for $ASSET" >&2; exit 1; }
    echo "Downloading vdpi Desktop ${TAG} (${ASSET})..."
    curl -fsSL "${BASE_URL}/${ASSET}" -o "${TMP_DIR}/${ASSET}"
    verify_sha256 "${TMP_DIR}/${ASSET}" "$EXPECTED"
    if [ "$(id -u)" -eq 0 ]; then
        apt-get install -y "${TMP_DIR}/${ASSET}"
    else
        sudo apt-get install -y "${TMP_DIR}/${ASSET}"
    fi
    echo "Installed vdpi Desktop ${TAG} via apt."
    exit 0
fi

ASSET="vdpi-desktop-linux-x86_64.AppImage"
EXPECTED="$(awk -v a="$ASSET" '$2 == a {print $1; exit}' "${TMP_DIR}/SHA256SUMS.txt")"
[ -n "$EXPECTED" ] || { echo "error: checksum missing for $ASSET" >&2; exit 1; }
echo "Downloading vdpi Desktop ${TAG} (${ASSET})..."
curl -fsSL "${BASE_URL}/${ASSET}" -o "${TMP_DIR}/${ASSET}"
verify_sha256 "${TMP_DIR}/${ASSET}" "$EXPECTED"

BIN_DIR="${HOME}/.local/bin"
APP_DIR="${HOME}/.local/share/applications"
mkdir -p "$BIN_DIR" "$APP_DIR"
install -m 755 "${TMP_DIR}/${ASSET}" "${BIN_DIR}/vdpi-desktop.AppImage"
cat > "${APP_DIR}/vdpi-desktop.desktop" <<EOF
[Desktop Entry]
Name=vdpi Desktop
Comment=Self-healing local anti-DPI engine
Exec=${BIN_DIR}/vdpi-desktop.AppImage
Terminal=false
Type=Application
Categories=Network;Utility;
EOF
echo "Installed ${BIN_DIR}/vdpi-desktop.AppImage (${TAG})."
