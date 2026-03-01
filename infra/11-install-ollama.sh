#!/usr/bin/env bash
# Script: 11-install-ollama.sh
# Run on: Mac (inference server)
# Purpose: Verify Ollama installation after manual download.
#
# Pre-steps (manual):
#   1. Download from https://ollama.com/download (macOS)
#   2. Drag Ollama.app to /Applications
#   3. Open Ollama.app and accept the CLI install prompt
#   4. Run this script to verify

set -euo pipefail

echo "=== Ollama Installation Verification ==="
echo ""

# Check 1: CLI available
if ! command -v ollama &>/dev/null; then
    echo "FAIL: 'ollama' command not found."
    echo "Open Ollama.app and accept the CLI install prompt, then retry."
    exit 1
fi
echo "PASS: ollama CLI found — $(ollama --version 2>&1)"

# Check 2: Server running
if curl -s --connect-timeout 3 http://localhost:11434 | grep -q "Ollama is running"; then
    echo "PASS: Ollama server running on localhost:11434"
else
    echo "FAIL: Ollama server not running. Open Ollama.app first."
    exit 1
fi

# Check 3: Listening interface
echo ""
echo "--- Listening Interface ---"
LISTEN=$(lsof -i :11434 -sTCP:LISTEN 2>/dev/null | tail -n +2 || true)
if [ -n "$LISTEN" ]; then
    echo "$LISTEN"
    if echo "$LISTEN" | grep -q '\*:11434'; then
        echo "PASS: Listening on all interfaces (0.0.0.0)"
    else
        echo "NOTE: Listening on localhost only."
        echo "  To fix: launchctl setenv OLLAMA_HOST \"0.0.0.0:11434\""
        echo "  Then quit and reopen Ollama.app."
    fi
else
    echo "Could not determine listening interface."
fi

# Check 4: Models
echo ""
echo "--- Available Models ---"
ollama list 2>/dev/null || echo "(none)"

echo ""
echo "=== Done ==="
