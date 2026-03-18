#!/bin/bash
set -e

# Rootwatch Installer
# Usage:
#   Install CLI (local scans, no account needed):
#     curl -sSL https://rootwatch.net/install | bash
#
#   Install agent daemon (continuous cloud monitoring):
#     curl -sSL https://rootwatch.net/install | bash -s -- --token rw_xxxxxxxx

VERSION="0.1.0"
GITHUB_REPO="rootwatch/rootwatch"
TOKEN=""
API_URL="https://rootwatch.net"
NO_SUDO=false
MODE=""  # "cli" or "agent" — determined automatically

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --token)      TOKEN="$2"; shift ;;
        --api-url)    API_URL="$2"; shift ;;
        --no-sudo)    NO_SUDO=true ;;
        --version)    VERSION="$2"; shift ;;
        --help|-h)
            echo "Usage: install.sh [--token <rw_...>] [--api-url <url>] [--no-sudo]"
            echo ""
            echo "  Without --token: installs the rootwatch CLI for local one-off scans."
            echo "  With --token:    installs the rootwatch-agent daemon for continuous"
            echo "                   cloud monitoring at https://rootwatch.net"
            exit 0
            ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Determine mode
if [ -n "$TOKEN" ]; then
    MODE="agent"
else
    MODE="cli"
fi

# Sudo helper
if [ "$NO_SUDO" = true ]; then
    SUDO=""
else
    SUDO="sudo"
fi

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case $ARCH in
    x86_64)       ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

if [ "$OS" != "linux" ] && [ "$OS" != "darwin" ]; then
    echo "Unsupported OS: $OS (linux and darwin supported)"
    exit 1
fi

echo "Rootwatch installer — mode: ${MODE}, system: ${OS}/${ARCH}"

# ─── CLI mode ─────────────────────────────────────────────────────────────────
if [ "$MODE" = "cli" ]; then
    BINARY="rootwatch"
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/rootwatch_${OS}_${ARCH}"

    echo "Downloading rootwatch CLI v${VERSION}..."
    $SUDO curl -sSL -o /usr/local/bin/rootwatch "${DOWNLOAD_URL}"
    $SUDO chmod +x /usr/local/bin/rootwatch

    echo ""
    echo "✓ rootwatch installed at /usr/local/bin/rootwatch"
    echo ""
    echo "  Run a scan:"
    echo "    rootwatch"
    echo ""
    echo "  JSON output:"
    echo "    rootwatch --output json"
    echo ""
    echo "  Continuous monitoring → https://rootwatch.net"
    exit 0
fi

# ─── Agent daemon mode ─────────────────────────────────────────────────────────
BINARY="rootwatch-agent"
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/rootwatch-agent_${OS}_${ARCH}"

echo "Downloading rootwatch-agent v${VERSION}..."

$SUDO mkdir -p /etc/rootwatch

# Write agent config
cat <<EOF | $SUDO tee /etc/rootwatch/config.yaml > /dev/null
api_url: "${API_URL}"
agent_token: "${TOKEN}"
scan_interval: "24h"
log_level: "info"
EOF

$SUDO curl -sSL -o /usr/local/bin/rootwatch-agent "${DOWNLOAD_URL}"
$SUDO chmod +x /usr/local/bin/rootwatch-agent

# Set up systemd service (Linux only)
if [ "$OS" = "linux" ] && [ "$NO_SUDO" = false ]; then
    $SUDO tee /etc/systemd/system/rootwatch-agent.service > /dev/null <<EOF
[Unit]
Description=Rootwatch Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rootwatch-agent
Restart=always
RestartSec=30
User=root
Environment=ROOTWATCH_CONFIG=/etc/rootwatch/config.yaml

[Install]
WantedBy=multi-user.target
EOF

    $SUDO systemctl daemon-reload
    $SUDO systemctl enable rootwatch-agent
    $SUDO systemctl start rootwatch-agent

    echo ""
    echo "✓ rootwatch-agent installed and started"
    echo "  Service: systemctl status rootwatch-agent"
elif [ "$NO_SUDO" = true ]; then
    echo ""
    echo "✓ rootwatch-agent installed (--no-sudo mode, systemd skipped)"
    echo "  Start manually: ROOTWATCH_CONFIG=/etc/rootwatch/config.yaml rootwatch-agent"
else
    # macOS — no systemd
    echo ""
    echo "✓ rootwatch-agent installed at /usr/local/bin/rootwatch-agent"
    echo "  Start manually: rootwatch-agent"
fi

echo ""
echo "  Dashboard: https://rootwatch.net"
