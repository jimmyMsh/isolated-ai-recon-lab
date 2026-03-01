#!/usr/bin/env bash
# Script: 05-pre-lockdown-verify.sh
# Run on: Attacker VM (via SSH)
# Purpose: Verify network connectivity before iptables lockdown.
#          All tests should pass at this stage (including internet).

echo "=== Attacker VM Network Interfaces ==="
ip -br addr show
echo ""

echo "=== Test 1: Attacker → Target (isolated network) ==="
echo "Pinging 192.168.56.101 (target VM)..."
ping -c 3 -W 2 192.168.56.101 && echo "✓ PASS" || echo "✗ FAIL — target may not be running"
echo ""

echo "=== Test 2: Attacker → Host gateway (NAT network) ==="
echo "Pinging 192.168.122.1 (libvirt host gateway)..."
ping -c 3 -W 2 192.168.122.1 && echo "✓ PASS" || echo "✗ FAIL"
echo ""

echo "=== Test 3: Attacker → Internet (should work before lockdown) ==="
echo "Pinging 1.1.1.1..."
ping -c 3 -W 2 1.1.1.1 && echo "✓ PASS (expected before lockdown)" || echo "✗ FAIL"
echo ""

echo "=== Test 4: Target isolation — run FROM target VM console ==="
echo "Commands to run on the target VM directly (via virt-viewer/virt-manager):"
echo "  ping -c 2 192.168.56.10    # Should SUCCEED (attacker on isolated net)"
echo "  ping -c 2 192.168.122.1    # Should FAIL (no route to NAT network)"
echo "  ping -c 2 1.1.1.1          # Should FAIL (no internet)"
echo ""
echo "Run those on the target and verify only the first one succeeds."
