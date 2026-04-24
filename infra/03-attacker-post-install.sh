#!/usr/bin/env bash
# Script: 03-attacker-post-install.sh
# Run on: Attacker VM (via SSH)
# Purpose: Install all required packages BEFORE iptables lockdown
# IMPORTANT: Run this while the attacker VM still has unrestricted internet access
#
# This script expects to run as the operator user with sudo privileges —
# NOT as root. The apt calls sudo themselves; uv's installer must land in
# the operator's ~/.local/bin, not /root/.local/bin. Running the whole
# script with sudo is a footgun and is refused below.

set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    echo "ERROR: run this as the operator user, not as root." >&2
    echo "  The apt commands below sudo internally, and uv must install" >&2
    echo "  for the operator user (not /root)." >&2
    echo "  Re-run without wrapping the whole script in sudo." >&2
    exit 1
fi

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
# git: clone the agent repo during the temp-open firewall window;
#      not in Ubuntu Server 24.04 minimal by default, so install here
#      while the VM still has internet.
sudo apt install -y \
    nmap \
    nikto \
    snmp \
    netcat-openbsd \
    curl \
    dnsutils \
    whois \
    tcpdump \
    tmux \
    git

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
echo "=== Installing uv (Python project/package manager) ==="
# uv owns the agent's virtualenv and dependency lock. At port time the
# operator runs 'uv sync --extra dev' inside agent/ to materialize .venv
# from uv.lock. The official installer drops the binary into
# $HOME/.local/bin for the current user (intentional — do NOT sudo this).
if command -v uv >/dev/null 2>&1; then
    echo "uv already installed: $(uv --version)"
else
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # The installer writes $HOME/.local/bin/env and amends ~/.bashrc /
    # ~/.profile to put ~/.local/bin on PATH for new shells. Source the
    # env file so the verification step below finds uv without requiring
    # the operator to start a fresh SSH session first.
    if [ -f "$HOME/.local/bin/env" ]; then
        # shellcheck disable=SC1091
        . "$HOME/.local/bin/env"
    fi
    echo "uv installed: $(uv --version)"
fi
echo "NOTE: in a new SSH session, uv is on PATH automatically. In THIS"
echo "      session, either 'source ~/.local/bin/env' first or invoke"
echo "      uv as \$HOME/.local/bin/uv until you re-login."

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
echo "git: $(git --version)"
echo "iptables: $(sudo iptables --version)"
echo "netfilter-persistent: $(dpkg -l | grep netfilter-persistent | awk '{print $2, $3}')"
if command -v uv >/dev/null 2>&1; then
    echo "uv: $(uv --version)"
elif [ -x "$HOME/.local/bin/uv" ]; then
    echo "uv: $("$HOME/.local/bin/uv" --version) (not yet on PATH for this shell)"
else
    echo "uv: MISSING — install did not complete" >&2
    exit 1
fi

echo ""
echo "=== All packages installed successfully ==="
echo "You can now proceed to create the target VM and configure iptables."
echo "If uv is missing from your PATH, run: source ~/.local/bin/env"
