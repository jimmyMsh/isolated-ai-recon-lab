#!/usr/bin/env bash
# Script: 06-setup-iptables.sh
# Run on: Attacker VM
# Purpose: Lock down NAT interface to ONLY allow inference server access.
#
# Usage: sudo bash 06-setup-iptables.sh <NAT_NIC> <INFERENCE_IP>
#
# To find NAT_NIC:
#   ip -br addr show
#   The interface with 192.168.122.10 is your NAT NIC.
#
# To find INFERENCE_IP:
#   On your inference server. Example for macOS: ipconfig getifaddr en0
#
# What this does:
#   1. Allows return traffic for established connections (ESTABLISHED,RELATED)
#   2. Allows NEW TCP connections to inference server on Ollama port (11434)
#   3. Allows DHCP (broadcast discover + unicast renew to gateway)
#   4. DROPs everything else on the NAT interface
#   5. Saves rules for persistence across reboots
#
# Design decisions:
#   - Uses -m conntrack (modern) not -m state (legacy alias)
#   - No DNS allowed: agent uses IP directly, maximum lockdown
#   - DHCP to broadcast + gateway only (not any destination)
#   - Rules target NAT interface only; isolated interface is unrestricted
#   - OUTPUT chain default policy stays ACCEPT (so isolated + loopback work)

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run with sudo"
    exit 1
fi

if [ $# -lt 2 ]; then
    echo "Usage: sudo bash $0 <NAT_NIC> <INFERENCE_IP>"
    echo ""
    echo "Example: sudo bash $0 enp1s0 192.168.1.50"
    echo ""
    echo "Your interfaces:"
    ip -br addr show
    exit 1
fi

NAT_NIC="$1"
INFERENCE_IP="$2"
INFERENCE_PORT=11434
LIBVIRT_GW="192.168.122.1"

# --- Validate inputs ---
if ! ip link show "$NAT_NIC" &>/dev/null; then
    echo "ERROR: Interface '$NAT_NIC' does not exist."
    echo "Available interfaces:"
    ip -br link show
    exit 1
fi

if ! echo "$INFERENCE_IP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "ERROR: '$INFERENCE_IP' does not look like a valid IPv4 address."
    exit 1
fi

echo "=== iptables Lockdown Configuration ==="
echo "NAT interface:    $NAT_NIC"
echo "Inference server: $INFERENCE_IP:$INFERENCE_PORT"
echo "Libvirt gateway:  $LIBVIRT_GW"
echo ""

# --- Flush existing OUTPUT rules ---
# Safe because default policy is ACCEPT; flushing just removes restrictions.
echo "Flushing existing OUTPUT rules..."
iptables -F OUTPUT

echo "Applying rules..."

# Rule 1: Allow return traffic for established connections on NAT.
# Response packets from the inference server arrive as ESTABLISHED.
# RELATED covers ICMP error messages tied to tracked connections.
iptables -A OUTPUT -o "$NAT_NIC" \
    -m conntrack --ctstate ESTABLISHED,RELATED \
    -j ACCEPT

# Rule 2: Allow NEW TCP connections to inference server only.
# This is the one outbound connection the agent needs: → Ollama API.
iptables -A OUTPUT -o "$NAT_NIC" \
    -p tcp \
    -d "$INFERENCE_IP" --dport "$INFERENCE_PORT" \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# Rule 3: Allow DHCP discover (broadcast).
# DHCPDISCOVER: src=0.0.0.0:68 → dst=255.255.255.255:67
# Needed for the VM to acquire its initial DHCP lease.
iptables -A OUTPUT -o "$NAT_NIC" \
    -p udp --sport 68 --dport 67 \
    -d 255.255.255.255 \
    -j ACCEPT

# Rule 4: Allow DHCP renew (unicast to gateway).
# Once leased, renewals are unicast to dnsmasq at the gateway.
iptables -A OUTPUT -o "$NAT_NIC" \
    -p udp --sport 68 --dport 67 \
    -d "$LIBVIRT_GW" \
    -j ACCEPT

# Rule 5: DROP everything else on NAT interface.
# Blocks: internet, LAN scanning, DNS, all other outbound.
iptables -A OUTPUT -o "$NAT_NIC" \
    -j DROP

echo ""
echo "=== Rules Applied ==="
iptables -L OUTPUT -v -n --line-numbers
echo ""

# --- Save rules for persistence across reboots ---
echo "Saving rules with netfilter-persistent..."
netfilter-persistent save

echo ""
echo "=== Saving configuration for helper scripts ==="
mkdir -p /etc/darkagents
cat > /etc/darkagents/inference.conf << CONF
# Dark Agents inference server configuration
# Updated: $(date -Iseconds)
INFERENCE_IP="$INFERENCE_IP"
INFERENCE_PORT="$INFERENCE_PORT"
NAT_NIC="$NAT_NIC"
LIBVIRT_GW="$LIBVIRT_GW"
CONF

echo "Config saved to /etc/darkagents/inference.conf"
echo ""
echo "=== Lockdown Complete ==="
echo "Attacker VM can now ONLY reach $INFERENCE_IP:$INFERENCE_PORT via NAT."
echo "All other outbound on $NAT_NIC is dropped."
echo "Isolated interface is unrestricted (for recon)."
