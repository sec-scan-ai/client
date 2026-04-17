#!/bin/sh
set -e

REPO="sec-scan-ai/client"
BINARY="sec-scan"
BIN_DIR="$HOME/.sec-scan/bin"
SYMLINK_DIR="/usr/local/bin"

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Darwin) OS="darwin" ;;
  Linux)  OS="linux" ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  ARCH="amd64" ;;
  arm64|aarch64)  ARCH="arm64" ;;
  *)              echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

ASSET="${BINARY}-${OS}-${ARCH}"
URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/latest/download/checksums.txt"

echo "Downloading sec-scan for ${OS}/${ARCH}..."
mkdir -p "$BIN_DIR"
TMP_BIN="$(mktemp)"
TMP_SUMS="$(mktemp)"
# shellcheck disable=SC2064
trap "rm -f '$TMP_BIN' '$TMP_SUMS'" EXIT

curl -fsSL -o "$TMP_BIN" "$URL"
curl -fsSL -o "$TMP_SUMS" "$CHECKSUMS_URL"

# Verify SHA256. The checksums file is 'sha256  filename' or 'sha256 *filename'
# per line. We use awk with field equality so special characters in the asset
# name (like the dot in .exe) aren't interpreted as regex.
EXPECTED="$(awk -v asset="$ASSET" '$2 == asset || $2 == "*"asset {print $1; exit}' "$TMP_SUMS")"
if [ -z "$EXPECTED" ]; then
  echo "error: no checksum for ${ASSET} in checksums.txt"
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$TMP_BIN" | awk '{print $1}')"
else
  ACTUAL="$(shasum -a 256 "$TMP_BIN" | awk '{print $1}')"
fi

if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "error: checksum mismatch for ${ASSET}"
  echo "  expected: ${EXPECTED}"
  echo "  actual:   ${ACTUAL}"
  exit 1
fi

mv "$TMP_BIN" "$BIN_DIR/$BINARY"
chmod +x "$BIN_DIR/$BINARY"

# Remove macOS quarantine attribute (binary is signed and notarized)
if [ "$OS" = "darwin" ] && command -v xattr >/dev/null 2>&1; then
  xattr -d com.apple.quarantine "$BIN_DIR/$BINARY" 2>/dev/null || true
fi

# Symlink into a PATH location. The real binary stays in the user-owned
# $BIN_DIR so future daily auto-updates (and `sec-scan update`) never
# need sudo.
if [ -w "$SYMLINK_DIR" ]; then
  ln -sfn "$BIN_DIR/$BINARY" "$SYMLINK_DIR/$BINARY"
else
  echo "Creating symlink in ${SYMLINK_DIR} (requires sudo, one-time)..."
  sudo ln -sfn "$BIN_DIR/$BINARY" "$SYMLINK_DIR/$BINARY"
fi

echo "sec-scan installed to ${BIN_DIR}/${BINARY}"
echo "  symlinked from ${SYMLINK_DIR}/${BINARY}"
sec-scan --version
