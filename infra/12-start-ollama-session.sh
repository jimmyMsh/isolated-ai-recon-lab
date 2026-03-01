#!/usr/bin/env bash
# Script: 12-start-ollama-session.sh
# Run on: Mac (inference server)
# Purpose: Start a Dark Agents dev session. Sets OLLAMA_HOST so Ollama
#          listens on all interfaces, opens the app, and verifies.
#
# Usage: bash 12-start-ollama-session.sh
#
# Run this at the start of each dev session. launchctl setenv does not
# persist across reboots, which is fine for a personal Mac.

set -euo pipefail

OLLAMA_PORT=11434
MAX_WAIT=30

echo "=== Starting Ollama Session ==="
echo ""

# Set OLLAMA_HOST for this login session.
# GUI apps on macOS read env vars from launchctl, not shell profiles.
echo "Setting OLLAMA_HOST=0.0.0.0:${OLLAMA_PORT}..."
launchctl setenv OLLAMA_HOST "0.0.0.0:${OLLAMA_PORT}"

# Check if already running on the right interface
if curl -s --connect-timeout 2 "http://localhost:${OLLAMA_PORT}" | grep -q "Ollama is running" 2>/dev/null; then
    LISTEN=$(lsof -i ":${OLLAMA_PORT}" -sTCP:LISTEN 2>/dev/null || true)
    if echo "$LISTEN" | grep -q "\*:${OLLAMA_PORT}"; then
        echo "PASS: Already running on all interfaces. Nothing to do."
    else
        echo "Running on localhost only. Needs restart to pick up OLLAMA_HOST."
        echo "Quit Ollama from the menu bar, then re-run this script."
        exit 1
    fi
else
    # Start the app and wait
    echo "Starting Ollama.app..."
    open -a Ollama

    echo -n "Waiting for server"
    WAITED=0
    while ! curl -s --connect-timeout 1 "http://localhost:${OLLAMA_PORT}" 2>/dev/null | grep -q "Ollama is running"; do
        sleep 1
        WAITED=$((WAITED + 1))
        echo -n "."
        if [ "$WAITED" -ge "$MAX_WAIT" ]; then
            echo ""
            echo "FAIL: Ollama did not start within ${MAX_WAIT}s."
            exit 1
        fi
    done
    echo " ready (${WAITED}s)"

    # Verify interface binding
    LISTEN=$(lsof -i ":${OLLAMA_PORT}" -sTCP:LISTEN 2>/dev/null || true)
    if echo "$LISTEN" | grep -q "\*:${OLLAMA_PORT}"; then
        echo "PASS: Listening on all interfaces"
    else
        echo "WARNING: Not listening on all interfaces."
        echo "Quit Ollama, then re-run this script."
        exit 1
    fi
fi

# Show network info
echo ""
LAN_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "unknown")
echo "LAN IP (en0):    ${LAN_IP}"
echo "Ollama endpoint: http://${LAN_IP}:${OLLAMA_PORT}"
echo ""
echo "--- Available Models ---"
ollama list 2>/dev/null || echo "(none — run: ollama pull qwen3:8b)"
echo ""
echo "If the inference server's IP changed, update iptables on the attacker VM:"
echo "  ssh <your-user>@192.168.122.10"
echo "  sudo bash infra/09-update-inference-ip.sh ${LAN_IP}"
