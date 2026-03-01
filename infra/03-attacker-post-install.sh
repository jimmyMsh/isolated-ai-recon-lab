#!/usr/bin/env bash
# Script: 03-attacker-post-install.sh
# Run on: Attacker VM (via SSH)
# Purpose: Install all required packages BEFORE iptables lockdown
# IMPORTANT: Run this while the attacker VM still has unrestricted internet access

set -euo pipefail

echo "=== Updating package lists ==="
sudo apt update

echo ""
echo "=== Upgrading installed packages ==="
sudo apt upgrade -y

echo ""
echo "=== Installing recon tools ==="
# nmap: port scanning, service/version detection, OS fingerprinting
# nikto: web server scanner
# NOTE: enum4linux omitted — unavailable in Ubuntu 24.04 repos (enum4linux-ng via pip if needed)
# snmp: snmpwalk for SNMP enumeration
# netcat-openbsd: TCP/UDP connections (nc)
# curl: HTTP client
# dnsutils: dig, nslookup for DNS enumeration
# whois: domain/IP registration lookup
# tcpdump: network packet capture (for logging/debugging)
# tmux: terminal multiplexer (for monitoring layout)
sudo apt install -y \
    nmap \
    nikto \
    snmp \
    netcat-openbsd \
    curl \
    dnsutils \
    whois \
    tcpdump \
    tmux

echo ""
echo "=== Installing Python development tools ==="
# python3-pip: package installer
# python3-venv: virtual environment support
# python3-dev: C headers for compiled Python packages
# build-essential: gcc/make for compiling C extensions
sudo apt install -y \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential

echo ""
echo "=== Installing iptables-persistent ==="
# This package saves and restores iptables rules across reboots.
# IMPORTANT: We install it NOW (while internet is open) but configure rules LATER.
# During install, it will ask if you want to save current rules — say YES to both
# (IPv4 and IPv6). The current rules are basically empty/default, which is fine.
# We'll overwrite them after configuring our lockdown rules.
sudo apt install -y iptables-persistent

echo ""
echo "=== Verifying installations ==="
echo "Python: $(python3 --version)"
echo "nmap: $(nmap --version | head -1)"
echo "curl: $(curl --version | head -1)"
echo "iptables: $(sudo iptables --version)"
echo "netfilter-persistent: $(dpkg -l | grep netfilter-persistent | awk '{print $2, $3}')"

echo ""
echo "=== All packages installed successfully ==="
echo "You can now proceed to create the target VM and configure iptables."
