#!/usr/bin/env bash
# Script: 14-verify-connectivity.sh
# Run on: Attacker VM
# Purpose: Verify attacker VM can reach Ollama through NAT and that
#          isolation blocks everything else.
#
# Usage: bash 14-verify-connectivity.sh
#
# Requires: /etc/darkagents/inference.conf (from 06-setup-iptables.sh)
set -euo pipefail
if [ ! -f /etc/darkagents/inference.conf ]; then
    echo "FAIL: /etc/darkagents/inference.conf not found."
    echo "Run 06-setup-iptables.sh first."
    exit 1
fi
source /etc/darkagents/inference.conf
OLLAMA_URL="http://${INFERENCE_IP}:${INFERENCE_PORT}"
TARGET_IP="192.168.56.101"
echo "=== Connectivity and Isolation Verification ==="
echo "Inference: ${OLLAMA_URL}"
echo "NAT NIC:   ${NAT_NIC}"
echo ""
PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
# --- Test 1: Ollama reachable ---
# Curl the Ollama root endpoint through NAT. Confirms iptables allows
# traffic to INFERENCE_IP:INFERENCE_PORT and Ollama is running.
echo "--- Test 1: Ollama server reachable ---"
if curl -s --connect-timeout 5 "${OLLAMA_URL}" 2>&1 | grep -q "Ollama is running"; then
    pass "Ollama responds at ${OLLAMA_URL}"
else
    fail "Cannot reach Ollama at ${OLLAMA_URL}"
    echo "    Check: Is Ollama running? Has the Mac IP changed?"
    echo "    Update: sudo bash 09-update-inference-ip.sh <NEW_IP>"
fi
echo ""
# --- Test 2: Model available ---
# Query the /api/tags endpoint to list pulled models. Verifies the
# model is downloaded and Ollama can serve it.
echo "--- Test 2: Model available ---"
if curl -s --connect-timeout 5 "${OLLAMA_URL}/api/tags" 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
models = data.get('models', [])
if models:
    for m in models:
        print('    ' + m.get('name', ''))
    sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
    pass "Model(s) available"
else
    fail "No models found (run 'ollama pull qwen3:8b' on Mac)"
fi
echo ""
# --- Test 3: Inference works ---
# Send an actual generation request end-to-end. This is the slowest test
# because Qwen3's thinking mode adds ~10-12s overhead. We set num_predict=200
# so the thinking phase can complete and still leave tokens for the answer.
# Checks both 'response' and 'thinking' fields since thinking mode splits them.
echo "--- Test 3: Inference request ---"
echo "  Sending test prompt (may take 15-20s with thinking mode)..."
RESPONSE=$(curl -s --connect-timeout 30 --max-time 60 \
    "${OLLAMA_URL}/api/generate" \
    -d '{"model":"qwen3:8b","prompt":"Respond with only the word: working","stream":false,"options":{"temperature":0,"num_predict":200}}' \
    2>&1 || echo '{}')
if echo "$RESPONSE" | python3 -c "
import sys, json
data = json.loads(sys.stdin.read())
resp = data.get('response', '').strip()
think = data.get('thinking', '').strip()
if resp:
    print('    Response: ' + resp[:80])
    sys.exit(0)
elif think:
    print('    Response (in thinking): ' + think[:80])
    sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
    pass "Inference returned a response"
else
    fail "Inference request failed"
    echo "    Raw: ${RESPONSE:0:200}"
fi
echo ""
# --- Test 4: Internet blocked ---
# iptables OUTPUT chain should DROP all traffic except to INFERENCE_IP.
# Curl to Google DNS (8.8.8.8) on HTTP — should time out.
echo "--- Test 4: Internet blocked ---"
if curl -s --connect-timeout 3 http://8.8.8.8 &>/dev/null; then
    fail "8.8.8.8 is reachable (should be blocked)"
else
    pass "Internet blocked (8.8.8.8 unreachable)"
fi
echo ""
# --- Test 5: Alternate internet blocked ---
# Second internet check using Cloudflare (1.1.1.1) on HTTP to rule out
# a rule that only blocks 8.8.8.8 specifically.
echo "--- Test 5: Alternate internet blocked ---"
if curl -s --connect-timeout 3 http://1.1.1.1 &>/dev/null; then
    fail "1.1.1.1 is reachable (should be blocked)"
else
    pass "Alternate internet blocked (1.1.1.1 unreachable)"
fi
echo ""
# --- Test 6: LAN scan blocked ---
# nmap ping scan on the inference server's LAN subnet. iptables should
# block all outbound traffic to the LAN except the one inference rule.
echo "--- Test 6: LAN scan blocked ---"
LAN_SUBNET=$(echo "$INFERENCE_IP" | sed 's/\.[0-9]*$/.0\/24/')
echo "  Scanning ${LAN_SUBNET} (should find nothing)..."
if nmap -sn "$LAN_SUBNET" --max-retries 1 --host-timeout 2s 2>/dev/null | grep -q "Host is up"; then
    fail "LAN scan found hosts (iptables not blocking)"
else
    pass "LAN scan blocked on ${LAN_SUBNET}"
fi
echo ""
# --- Test 7: Target reachable on isolated network ---
# The isolated NIC (no iptables rules) should reach the target freely.
# This confirms the isolated libvirt bridge is up and the target VM is running.
echo "--- Test 7: Isolated network (attacker -> target) ---"
if ping -c 1 -W 2 "$TARGET_IP" &>/dev/null; then
    pass "Target VM reachable at ${TARGET_IP}"
else
    fail "Cannot reach target at ${TARGET_IP} (is VM running?)"
fi
echo ""
# --- Test 8: Non-inference ports blocked ---
# Curl the inference server on port 80 instead of 11434. iptables should
# only allow the Ollama port, not arbitrary services on the same host.
echo "--- Test 8: Non-inference ports blocked ---"
if curl -s --connect-timeout 3 "http://${INFERENCE_IP}:80" &>/dev/null; then
    fail "Port 80 on inference server reachable (only 11434 should be)"
else
    pass "Non-inference ports blocked"
fi
echo ""
# --- Summary ---
echo "==========================================="
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "==========================================="
if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "Some tests failed. Current iptables OUTPUT rules:"
    sudo iptables -L OUTPUT -v -n --line-numbers 2>/dev/null || echo "(need sudo)"
    exit 1
else
    echo ""
    echo "All tests passed. Infrastructure ready."
fi
