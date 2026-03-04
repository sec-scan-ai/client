#!/bin/sh
set -e

REPO="sec-scan-ai/client"
BINARY="sec-scan"
INSTALL_DIR="/usr/local/bin"

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

URL="https://github.com/${REPO}/releases/latest/download/${BINARY}-${OS}-${ARCH}"

echo "Downloading sec-scan for ${OS}/${ARCH}..."
curl -fsSL -o "$BINARY" "$URL"
chmod +x "$BINARY"

if [ -w "$INSTALL_DIR" ]; then
  mv "$BINARY" "$INSTALL_DIR/$BINARY"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mv "$BINARY" "$INSTALL_DIR/$BINARY"
fi

echo "sec-scan installed to ${INSTALL_DIR}/${BINARY}"
sec-scan --version
