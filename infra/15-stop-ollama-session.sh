#!/usr/bin/env bash
# Script: 15-stop-ollama-session.sh
# Run on: Mac (inference server)
# Purpose: Stop Ollama and free memory after a dev session.
#
# Usage: bash 15-stop-ollama-session.sh
#
# Steps:
#   1. Unload all running models (frees GPU memory immediately)
#   2. Quit the Ollama.app GUI via AppleScript
#   3. Kill all ollama processes (GUI + server) to prevent auto-restart
#   4. Verify the port is actually closed

set -euo pipefail

PORT=11434

echo "=== Stopping Ollama Session ==="

# Step 1: Unload running models to free GPU memory.
# Even if the server process stays alive briefly, this reclaims the ~5-7GB
# that loaded models consume.
if command -v ollama >/dev/null 2>&1 && ollama ps >/dev/null 2>&1; then
    MODELS="$(ollama ps | awk 'NR>1 && $1 != "" {print $1}')"
    if [ -n "${MODELS}" ]; then
        echo "Unloading running models:"
        while IFS= read -r m; do
            [ -z "$m" ] && continue
            echo "  - ollama stop $m"
            ollama stop "$m" || true
        done <<< "${MODELS}"
    else
        echo "No running models."
    fi
fi

# Step 2: Quit the GUI app via AppleScript.
if pgrep -x "Ollama" >/dev/null 2>&1; then
    echo "Quitting Ollama.app..."
    osascript -e 'quit app "Ollama"' 2>/dev/null || true
    sleep 2
fi

# Step 3: Kill ALL ollama processes — both the GUI app ("Ollama") and the
# server binary ("ollama"). Quitting the GUI alone is not enough because
# macOS can auto-restart the server via Login Items / background tasks.
echo "Killing ollama processes..."
pkill -f "[Oo]llama" 2>/dev/null || true
sleep 2

# Step 4: Verify the port is closed.
if lsof -nP -iTCP:${PORT} -sTCP:LISTEN >/dev/null 2>&1; then
    # Something is still listening — try harder
    echo "Port still open. Force-killing listener..."
    PIDS="$(lsof -nP -iTCP:${PORT} -sTCP:LISTEN -t 2>/dev/null || true)"
    [ -n "${PIDS}" ] && kill -9 ${PIDS} 2>/dev/null || true
    sleep 1
fi

if lsof -nP -iTCP:${PORT} -sTCP:LISTEN >/dev/null 2>&1; then
    echo "FAIL: Port ${PORT} still in use after all stop attempts."
    echo "Ollama may be registered as a background task. Disable it:"
    echo "  System Settings → General → Login Items → Allow in the Background → Ollama → OFF"
    exit 1
fi

echo "Ollama stopped. Port ${PORT} closed. Memory freed."
