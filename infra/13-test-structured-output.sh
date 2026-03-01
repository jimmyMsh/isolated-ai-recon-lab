#!/usr/bin/env bash
# Script: 13-test-structured-output.sh
# Run on: Mac (inference server) or anywhere that can reach Ollama
# Purpose: Verify the model produces valid structured JSON for recon tasks.
#
# Usage: bash 13-test-structured-output.sh [OLLAMA_URL]
#   Default OLLAMA_URL: http://localhost:11434
#
# Tests:
#   1. Basic JSON mode (format: "json")
#   2. Schema-constrained mode (format: {schema}) with recon prompt
#   3. Follow-up recon prompt with timing

set -euo pipefail

OLLAMA_URL="${1:-http://localhost:11434}"
MODEL="qwen3:8b"

echo "=== Structured Output Test ==="
echo "Ollama: ${OLLAMA_URL}"
echo "Model:  ${MODEL}"
echo ""

# Verify model is available
if ! curl -s "${OLLAMA_URL}/api/tags" | python3 -c "
import sys, json
data = json.load(sys.stdin)
names = [m['name'] for m in data.get('models', [])]
if not any('${MODEL}'.split(':')[0] in n for n in names):
    sys.exit(1)
" 2>/dev/null; then
    echo "FAIL: Model ${MODEL} not found. Run: ollama pull ${MODEL}"
    exit 1
fi
echo "PASS: Model ${MODEL} available"
echo ""

# Helper: send a request and validate the response is parseable JSON.
# Prints the parsed JSON and exits 0 on success, 1 on failure.
# Usage: echo '{"request body"}' | validate_json_response
validate_json_response() {
    # Read the full curl response from stdin
    python3 -c "
import sys, json

raw = sys.stdin.read()
try:
    response = json.loads(raw)
except json.JSONDecodeError:
    print('FAIL: Could not parse Ollama response')
    print('Raw:', raw[:300])
    sys.exit(1)

content_str = response.get('message', {}).get('content', '')
if not content_str:
    print('FAIL: No content in response')
    sys.exit(1)

try:
    parsed = json.loads(content_str)
    print(json.dumps(parsed, indent=2))
    sys.exit(0)
except json.JSONDecodeError:
    print('FAIL: Model output is not valid JSON')
    print('Content:', content_str[:300])
    sys.exit(1)
"
}

# --- Test 1: Basic JSON mode ---
echo "--- Test 1: Basic JSON Mode ---"

RESPONSE1=$(curl -s "${OLLAMA_URL}/api/chat" \
  -d "{
    \"model\": \"${MODEL}\",
    \"messages\": [
      {\"role\": \"user\", \"content\": \"What is the nmap command to discover live hosts on a /24 subnet? Respond as JSON with keys: command, explanation.\"}
    ],
    \"format\": \"json\",
    \"stream\": false,
    \"options\": {\"temperature\": 0}
  }")

if echo "$RESPONSE1" | validate_json_response; then
    echo "PASS: Valid JSON"
else
    echo "FAIL: Test 1"
fi
echo ""

# --- Test 2: Schema-constrained mode ---
echo "--- Test 2: Schema-Constrained Mode ---"

RESPONSE2=$(curl -s "${OLLAMA_URL}/api/chat" \
  -d "{
    \"model\": \"${MODEL}\",
    \"messages\": [
      {\"role\": \"system\", \"content\": \"You are a network reconnaissance assistant. Select the appropriate recon operation for the given task.\"},
      {\"role\": \"user\", \"content\": \"Plan the first step to discover what hosts are alive on the subnet 192.168.56.0/24.\"}
    ],
    \"format\": {
      \"type\": \"object\",
      \"properties\": {
        \"operation\": {\"type\": \"string\", \"enum\": [\"host_discovery\", \"port_scan\", \"service_enum\", \"os_fingerprint\"]},
        \"tool\": {\"type\": \"string\"},
        \"command_args\": {\"type\": \"string\"},
        \"reasoning\": {\"type\": \"string\"}
      },
      \"required\": [\"operation\", \"tool\", \"command_args\", \"reasoning\"]
    },
    \"stream\": false,
    \"options\": {\"temperature\": 0}
  }")

if echo "$RESPONSE2" | validate_json_response; then
    # Validate the parsed fields via stdin
    echo "$RESPONSE2" | python3 -c "
import sys, json
resp = json.loads(sys.stdin.read())
data = json.loads(resp['message']['content'])
op = data.get('operation', '')
valid = ['host_discovery', 'port_scan', 'service_enum', 'os_fingerprint']
if op in valid:
    print(f'PASS: Operation \"{op}\" is in the allowed set')
else:
    print(f'NOTE: Operation \"{op}\" not in expected set: {valid}')
tool = data.get('tool', '') + ' ' + data.get('command_args', '')
if 'nmap' in tool.lower():
    print('PASS: Model suggested nmap')
else:
    print(f'NOTE: Model suggested: {data.get(\"tool\", \"unknown\")}')
"
else
    echo "FAIL: Test 2"
fi
echo ""

# --- Test 3: Follow-up recon prompt with timing ---
echo "--- Test 3: Timed Recon Prompt ---"

START=$(python3 -c "import time; print(time.time())")

RESPONSE3=$(curl -s "${OLLAMA_URL}/api/chat" \
  -d "{
    \"model\": \"${MODEL}\",
    \"messages\": [
      {\"role\": \"system\", \"content\": \"You are an autonomous network reconnaissance agent. Given scan results, decide the next recon step.\"},
      {\"role\": \"user\", \"content\": \"Host discovery found 192.168.56.101 is alive. What should we do next?\"}
    ],
    \"format\": {
      \"type\": \"object\",
      \"properties\": {
        \"operation\": {\"type\": \"string\"},
        \"tool\": {\"type\": \"string\"},
        \"command_args\": {\"type\": \"string\"},
        \"target_ip\": {\"type\": \"string\"},
        \"reasoning\": {\"type\": \"string\"}
      },
      \"required\": [\"operation\", \"tool\", \"command_args\", \"target_ip\", \"reasoning\"]
    },
    \"stream\": false,
    \"options\": {\"temperature\": 0}
  }")

END=$(python3 -c "import time; print(time.time())")

if echo "$RESPONSE3" | validate_json_response; then
    echo "PASS: Valid JSON"
else
    echo "FAIL: Test 3"
fi

ELAPSED=$(python3 -c "import sys; print(f'{float(sys.argv[1]) - float(sys.argv[2]):.1f}')" "$END" "$START")
echo "Wall clock: ${ELAPSED}s"

# Extract Ollama's own performance metrics from the response.
# eval_count = tokens generated, eval_duration = generation time in nanoseconds.
echo "$RESPONSE3" | python3 -c "
import sys, json
try:
    r = json.loads(sys.stdin.read())
    eval_count = r.get('eval_count', 0)
    eval_ns = r.get('eval_duration', 0)
    if eval_count and eval_ns:
        tok_s = eval_count / (eval_ns / 1e9)
        print(f'Ollama metrics: {eval_count} tokens, {tok_s:.1f} tok/s')
    thinking = r.get('message', {}).get('thinking', '')
    if thinking:
        print(f'Thinking: {thinking[:120]}...')
except Exception:
    pass
" 2>/dev/null || true
echo ""
echo "=== All Tests Complete ==="
