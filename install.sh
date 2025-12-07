#!/bin/bash
set -e

VERSION="0.1.0"
REPO="copyleftdev/unflare"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)
        case "$ARCH" in
            x86_64) BINARY="unflare-linux-x86_64" ;;
            *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    darwin)
        case "$ARCH" in
            x86_64) BINARY="unflare-macos-x86_64" ;;
            arm64)  BINARY="unflare-macos-aarch64" ;;
            *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

URL="https://github.com/${REPO}/releases/download/v${VERSION}/${BINARY}"

echo "⚡ Installing unflare v${VERSION}..."
echo "   Downloading ${BINARY}..."

# Download
if command -v curl &> /dev/null; then
    curl -fsSL "$URL" -o /tmp/unflare
elif command -v wget &> /dev/null; then
    wget -q "$URL" -O /tmp/unflare
else
    echo "Error: curl or wget required"
    exit 1
fi

chmod +x /tmp/unflare

# Install
if [ -w "$INSTALL_DIR" ]; then
    mv /tmp/unflare "$INSTALL_DIR/unflare"
else
    echo "   Installing to $INSTALL_DIR (requires sudo)..."
    sudo mv /tmp/unflare "$INSTALL_DIR/unflare"
fi

echo "✓ Installed to $INSTALL_DIR/unflare"
echo ""
unflare version
