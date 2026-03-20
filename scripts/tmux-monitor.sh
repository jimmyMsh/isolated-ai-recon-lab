#!/usr/bin/env bash
# Dark Agents — tmux monitoring layout
# Three panes: agent stdout | live JSONL log | live tcpdump
# Usage: ./scripts/tmux-monitor.sh
# Key commands:
#   Ctrl-b + arrow  — switch panes
#   Ctrl-b + z      — toggle zoom (fullscreen current pane)
#   Ctrl-b + [      — scroll mode (q to exit)
#   Ctrl-b + d      — detach (session continues)
#   tmux attach -t darkagents  — reattach

set -euo pipefail

SESSION="darkagents"
AGENT_DIR="$(cd "$(dirname "$0")/../agent" && pwd)"
OUTPUT_DIR="${AGENT_DIR}/output"

# Create output directory if needed
mkdir -p "${OUTPUT_DIR}"

# Kill existing session if present
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Create session with top pane (agent)
tmux new-session -d -s "$SESSION" -n "monitor" -c "$AGENT_DIR"
tmux send-keys -t "$SESSION" "echo '=== Agent Pane ===' && echo 'Run: uv run python run.py'" Enter

# Bottom-left pane (live log)
tmux split-window -v -t "$SESSION" -c "$AGENT_DIR"
tmux send-keys -t "$SESSION" "echo '=== Log Pane ===' && tail -f ${OUTPUT_DIR}/agent.log.jsonl 2>/dev/null | python3 -m json.tool --no-ensure-ascii" Enter

# Bottom-right pane (tcpdump)
tmux split-window -h -t "$SESSION" -c "$AGENT_DIR"
tmux send-keys -t "$SESSION" "echo '=== Network Pane ===' && sudo tcpdump -i enp2s0 -nn -q 2>/dev/null" Enter

# Focus top pane
tmux select-pane -t "$SESSION:0.0"

# Attach
tmux attach -t "$SESSION"
