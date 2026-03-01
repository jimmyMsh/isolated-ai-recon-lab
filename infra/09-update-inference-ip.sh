#!/usr/bin/env bash
# Script: 09-update-inference-ip.sh
# Run on: Attacker VM
# Purpose: Update iptables when the inference server IP changes.
#          Finds the existing inference rule, replaces it with the new IP,
#          saves, and verifies connectivity.
#
# Usage: sudo bash 09-update-inference-ip.sh <NEW_INFERENCE_IP>
#
# When to use:
#   - Your Mac's DHCP lease changed and it has a new IP
#   - You switched to a different inference machine (e.g., Mac Mini M4)
#   - At the start of a work session if unsure about the current IP

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run with sudo"
    exit 1
fi

if [ $# -lt 1 ]; then
    echo "Usage: sudo bash $0 <NEW_INFERENCE_IP>"
    echo ""
    if [ -f /etc/darkagents/inference.conf ]; then
        source /etc/darkagents/inference.conf
        echo "Current inference IP: $INFERENCE_IP"
    fi
    exit 1
fi

NEW_IP="$1"

# Basic IP validation
if ! echo "$NEW_IP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "ERROR: '$NEW_IP' does not look like a valid IPv4 address."
    exit 1
fi

# Load current config
if [ ! -f /etc/darkagents/inference.conf ]; then
    echo "ERROR: /etc/darkagents/inference.conf not found."
    echo "Run 06-setup-iptables.sh first."
    exit 1
fi

source /etc/darkagents/inference.conf
if [ -z "${INFERENCE_IP:-}" ] || [ -z "${INFERENCE_PORT:-}" ] || [ -z "${NAT_NIC:-}" ]; then
    echo "ERROR: /etc/darkagents/inference.conf is missing required variables."
    echo "Re-run 06-setup-iptables.sh to regenerate it."
    exit 1
fi
OLD_IP="$INFERENCE_IP"

if [ "$OLD_IP" = "$NEW_IP" ]; then
    echo "Inference IP is already $NEW_IP. Nothing to do."
    exit 0
fi

echo "Updating: $OLD_IP → $NEW_IP"
echo ""

# Find the rule number matching the old inference IP
RULE_NUM=$(iptables -L OUTPUT -n --line-numbers | grep "$OLD_IP" | grep "dpt:${INFERENCE_PORT}" | awk '{print $1}')

if [ -z "$RULE_NUM" ]; then
    echo "ERROR: Could not find existing rule for $OLD_IP:$INFERENCE_PORT"
    echo "Current OUTPUT rules:"
    iptables -L OUTPUT -v -n --line-numbers
    exit 1
fi

echo "Found rule at position $RULE_NUM. Replacing..."

# Delete old rule, insert new one at same position
iptables -D OUTPUT "$RULE_NUM"
iptables -I OUTPUT "$RULE_NUM" \
    -o "$NAT_NIC" \
    -p tcp \
    -d "$NEW_IP" --dport "$INFERENCE_PORT" \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# Persist
netfilter-persistent save

# Update config file
sed -i "s/^INFERENCE_IP=.*/INFERENCE_IP=\"$NEW_IP\"/" /etc/darkagents/inference.conf
sed -i "s/^# Updated:.*/# Updated: $(date -Iseconds)/" /etc/darkagents/inference.conf

echo ""
echo "=== Updated Rules ==="
iptables -L OUTPUT -v -n --line-numbers
echo ""
echo "=== Connectivity Check ==="
echo "Attempting curl http://$NEW_IP:$INFERENCE_PORT (timeout 5s)..."
curl -s --connect-timeout 5 "http://${NEW_IP}:${INFERENCE_PORT}" 2>&1 | head -3 || echo "(Timeout — Ollama may not be running)"
echo ""
echo "Done. Config saved to /etc/darkagents/inference.conf"
