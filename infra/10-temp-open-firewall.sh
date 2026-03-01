#!/usr/bin/env bash
# Script: 10-temp-open-firewall.sh
# Run on: Attacker VM
# Purpose: Temporarily open NAT for package installation, then re-lock.
#
# Usage:
#   sudo bash 10-temp-open-firewall.sh open    # Opens firewall (allows internet)
#   sudo bash 10-temp-open-firewall.sh close   # Re-applies lockdown
#
# Typical workflow:
#   sudo bash 10-temp-open-firewall.sh open
#   sudo apt update && sudo apt install -y <package>
#   sudo bash 10-temp-open-firewall.sh close

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run with sudo"
    exit 1
fi

if [ $# -lt 1 ] || { [ "$1" != "open" ] && [ "$1" != "close" ]; }; then
    echo "Usage: sudo bash $0 open|close"
    echo ""
    echo "  open:  Flush NAT lockdown (allows internet)"
    echo "  close: Re-apply lockdown from saved config"
    exit 1
fi

if [ "$1" = "open" ]; then
    echo "=== Opening firewall ==="
    echo "WARNING: NAT interface is now unrestricted."
    iptables -F OUTPUT
    iptables -L OUTPUT -v -n
    echo ""
    echo "Firewall OPEN. Run your apt commands, then: sudo bash $0 close"

elif [ "$1" = "close" ]; then
    if [ ! -f /etc/darkagents/inference.conf ]; then
        echo "ERROR: /etc/darkagents/inference.conf not found."
        echo "Run 06-setup-iptables.sh instead."
        exit 1
    fi

    source /etc/darkagents/inference.conf
    if [ -z "${NAT_NIC:-}" ] || [ -z "${INFERENCE_IP:-}" ] || [ -z "${INFERENCE_PORT:-}" ] || [ -z "${LIBVIRT_GW:-}" ]; then
        echo "ERROR: /etc/darkagents/inference.conf is missing required variables."
        echo "Re-run 06-setup-iptables.sh to regenerate it."
        exit 1
    fi
    echo "=== Re-applying lockdown ==="
    echo "NAT NIC: $NAT_NIC | Inference: $INFERENCE_IP:$INFERENCE_PORT"

    iptables -F OUTPUT

    iptables -A OUTPUT -o "$NAT_NIC" \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o "$NAT_NIC" \
        -p tcp -d "$INFERENCE_IP" --dport "$INFERENCE_PORT" \
        -m conntrack --ctstate NEW -j ACCEPT
    iptables -A OUTPUT -o "$NAT_NIC" \
        -p udp --sport 68 --dport 67 -d 255.255.255.255 -j ACCEPT
    iptables -A OUTPUT -o "$NAT_NIC" \
        -p udp --sport 68 --dport 67 -d "$LIBVIRT_GW" -j ACCEPT
    iptables -A OUTPUT -o "$NAT_NIC" -j DROP

    netfilter-persistent save

    echo ""
    iptables -L OUTPUT -v -n --line-numbers
    echo ""
    echo "Lockdown re-applied."
fi
