#!/usr/bin/env bash
# Dark Agents — tmux monitoring layout.
#
# Creates:
#   top          agent console
#   bottom-left  JSONL log viewer
#   bottom-right tcpdump on isolated NIC
#
# Usage:
#   MON_IFACE=enp2s0 ./scripts/tmux-monitor.sh
#   AGENT_CONFIG=config/remote.yaml MON_IFACE=enp2s0 ./scripts/tmux-monitor.sh
#   REPLACE_SESSION=1 MON_IFACE=enp2s0 ./scripts/tmux-monitor.sh
#
# Optional:
#   TCPDUMP_FILTER='host 192.168.56.101 or arp' MON_IFACE=enp2s0 ./scripts/tmux-monitor.sh

set -euo pipefail

SESSION="${SESSION:-darkagents}"
AGENT_CONFIG="${AGENT_CONFIG:-config/default.yaml}"
TCPDUMP_FILTER="${TCPDUMP_FILTER:-ip or arp}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="${AGENT_DIR:-${SCRIPT_DIR}/../agent}"

if [ ! -d "$AGENT_DIR" ]; then
    echo "tmux-monitor.sh: agent directory not found: $AGENT_DIR" >&2
    echo "  Override with: AGENT_DIR=/path/to/agent MON_IFACE=<nic> $0" >&2
    exit 2
fi

AGENT_DIR="$(cd -- "$AGENT_DIR" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-${AGENT_DIR}/output}"
LOG_FILE="${OUTPUT_DIR}/agent.log.jsonl"

# Quote values before injecting them into tmux pane shell commands.
q() {
    printf '%q' "$1"
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "tmux-monitor.sh: required command not found: $1" >&2
        exit 1
    fi
}

require_cmd tmux
require_cmd python3
require_cmd tcpdump

# Force the operator to choose the correct lab NIC.
if [ -z "${MON_IFACE:-}" ]; then
    echo "tmux-monitor.sh: MON_IFACE is required." >&2
    echo "  Use the isolated NIC whose IPv4 matches attacker_ip." >&2
    echo "  List NICs with: ip -br addr show" >&2
    echo "  Then run: MON_IFACE=<nic> $0" >&2
    exit 2
fi

# Validate interface when possible.
if command -v ip >/dev/null 2>&1; then
    if ! ip link show "$MON_IFACE" >/dev/null 2>&1; then
        echo "tmux-monitor.sh: interface '$MON_IFACE' not found." >&2
        echo "  List candidates with: ip -br link show" >&2
        exit 2
    fi
elif command -v ifconfig >/dev/null 2>&1; then
    if ! ifconfig "$MON_IFACE" >/dev/null 2>&1; then
        echo "tmux-monitor.sh: interface '$MON_IFACE' not found." >&2
        echo "  List candidates with: ifconfig" >&2
        exit 2
    fi
fi

mkdir -p "$OUTPUT_DIR"

# Do not kill an existing monitor unless explicitly requested.
if tmux has-session -t "=${SESSION}" 2>/dev/null; then
    if [ "${REPLACE_SESSION:-0}" = "1" ]; then
        tmux kill-session -t "=${SESSION}"
    else
        echo "tmux-monitor.sh: tmux session '$SESSION' already exists." >&2
        echo "  Reattach: tmux attach -t $SESSION" >&2
        echo "  Replace:  REPLACE_SESSION=1 MON_IFACE=$MON_IFACE $0" >&2
        exit 2
    fi
fi

# Use sudo for tcpdump unless Linux capabilities allow unprivileged capture.
TCPDUMP_BIN="$(command -v tcpdump)"
TCPDUMP_PREFIX="sudo "

if command -v getcap >/dev/null 2>&1; then
    TCPDUMP_CAPS="$(getcap "$TCPDUMP_BIN" 2>/dev/null || true)"
    if [[ "$TCPDUMP_CAPS" == *cap_net_raw* && "$TCPDUMP_CAPS" == *cap_net_admin* ]]; then
        TCPDUMP_PREFIX=""
    fi
fi

if [ -n "$TCPDUMP_PREFIX" ] && ! command -v sudo >/dev/null 2>&1; then
    echo "tmux-monitor.sh: tcpdump needs elevated privileges, but sudo is unavailable." >&2
    echo "  Alternative:" >&2
    echo "    sudo setcap cap_net_raw,cap_net_admin=eip $TCPDUMP_BIN" >&2
    exit 1
fi

LOG_FILE_Q="$(q "$LOG_FILE")"
MON_IFACE_Q="$(q "$MON_IFACE")"
TCPDUMP_BIN_Q="$(q "$TCPDUMP_BIN")"
TCPDUMP_FILTER_Q="$(q "$TCPDUMP_FILTER")"

# run.py enforces a root gate at startup (nmap SYN scans need raw sockets);
# the agent must run under sudo. The "$(command -v uv)" form expands before
# sudo so the absolute uv path is passed in directly — Ubuntu's default
# sudo secure_path does not include ~/.local/bin where uv installs.
AGENT_HINT="$(q 'sudo "$(command -v uv)" run python run.py --config '"${AGENT_CONFIG}")"
AGENT_NOTE="$(q 'sudo is required: run.py refuses unprivileged because nmap SYN scans need raw sockets. "$(command -v uv)" expands in your shell before sudo so secure_path does not hide ~/.local/bin/uv.')"

# Pretty-print one JSON object per line from the JSONL log.
PY_JSONL_READER='import json, sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        print(json.dumps(json.loads(line), indent=2, ensure_ascii=False), flush=True)
    except Exception:
        print(line, flush=True)
'
PY_JSONL_READER_Q="$(q "$PY_JSONL_READER")"

# Capture pane IDs so every command targets the intended pane.
agent_pane="$(tmux new-session -d -P -F '#{pane_id}' \
    -s "$SESSION" \
    -n "monitor" \
    -c "$AGENT_DIR")"

# tmux uses -l SIZE; SIZE can be a percentage like 55%.
log_pane="$(tmux split-window -v -l 55% -P -F '#{pane_id}' \
    -t "$agent_pane" \
    -c "$AGENT_DIR")"

net_pane="$(tmux split-window -h -l 50% -P -F '#{pane_id}' \
    -t "$log_pane" \
    -c "$AGENT_DIR")"

# Agent pane: interactive command area.
tmux send-keys -t "$agent_pane" \
    "clear; echo '=== Agent Pane ==='; echo 'Run:'; printf '  %s\n' $AGENT_HINT; echo; printf '%s\n' $AGENT_NOTE" \
    Enter

# Log pane: follow new log events only.
tmux send-keys -t "$log_pane" \
    "clear; echo '=== Log Pane ==='; echo 'Watching: ${LOG_FILE_Q}'; tail -n 0 -F ${LOG_FILE_Q} 2>/dev/null | python3 -u -c ${PY_JSONL_READER_Q}" \
    Enter

# Network pane: compact tcpdump, filtered to hide STP bridge chatter.
PANE_BANNER="=== Network Pane (${MON_IFACE}) ==="
PANE_MODE="mode: compact tcpdump (-q), not verbose"
PANE_FILTER="filter: ${TCPDUMP_FILTER}"
PANE_HINT="override: TCPDUMP_FILTER='host 192.168.56.101 or arp'"

if [ -n "$TCPDUMP_PREFIX" ]; then
    PANE_HINT="${PANE_HINT}; sudo may prompt below"
fi

PANE_BANNER_Q="$(q "$PANE_BANNER")"
PANE_MODE_Q="$(q "$PANE_MODE")"
PANE_FILTER_Q="$(q "$PANE_FILTER")"
PANE_HINT_Q="$(q "$PANE_HINT")"

tmux send-keys -t "$net_pane" \
    "clear; printf '%s\n' ${PANE_BANNER_Q}; printf '%s\n' ${PANE_MODE_Q}; printf '%s\n' ${PANE_FILTER_Q}; printf '%s\n\n' ${PANE_HINT_Q}; ${TCPDUMP_PREFIX}${TCPDUMP_BIN_Q} -i ${MON_IFACE_Q} -nn -q ${TCPDUMP_FILTER_Q}" \
    Enter

tmux select-pane -t "$agent_pane"

# Attach normally, or switch if already inside tmux.
if [ -n "${TMUX:-}" ]; then
    tmux switch-client -t "$SESSION"
else
    tmux attach -t "$SESSION"
fi