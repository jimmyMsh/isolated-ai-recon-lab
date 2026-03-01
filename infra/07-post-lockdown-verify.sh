#!/usr/bin/env bash
# Script: 07-post-lockdown-verify.sh
# Run on: Attacker VM (via SSH)
# Purpose: Verify iptables lockdown is working correctly.
#          Tests that allowed traffic passes and blocked traffic is dropped.

echo "=== Current iptables OUTPUT rules ==="
sudo iptables -L OUTPUT -v -n --line-numbers
echo ""

# Load config if available
INFERENCE_IP=""
INFERENCE_PORT=""
NAT_NIC=""
if [ -f /etc/darkagents/inference.conf ]; then
    source /etc/darkagents/inference.conf
    echo "Configured inference server: $INFERENCE_IP:$INFERENCE_PORT"
    echo "NAT interface: $NAT_NIC"
    echo ""
fi

echo "=== Test 1: Attacker → Target (isolated, should PASS) ==="
ping -c 2 -W 2 192.168.56.101 && echo "✓ PASS" || echo "✗ FAIL"
echo ""

echo "=== Test 2: Attacker → Internet via ICMP (should FAIL) ==="
echo "Pinging 1.1.1.1 (timeout 3s)..."
ping -c 2 -W 3 1.1.1.1 && echo "✗ UNEXPECTED PASS — lockdown not working!" || echo "✓ PASS (blocked as expected)"
echo ""

echo "=== Test 3: Attacker → Internet via TCP (should FAIL) ==="
echo "Attempting nc -vz 1.1.1.1 443 (timeout 3s)..."
nc -vz -w 3 1.1.1.1 443 2>&1 && echo "✗ UNEXPECTED PASS — lockdown not working!" || echo "✓ PASS (blocked as expected)"
echo ""

echo "=== Test 4: Attacker → LAN scan (should FAIL) ==="
if [ -n "$INFERENCE_IP" ]; then
    LAN_SUBNET=$(echo "$INFERENCE_IP" | sed 's/\.[0-9]*$/.0\/24/')
else
    LAN_SUBNET="192.168.1.0/24"
fi
echo "Attempting nmap host discovery on $LAN_SUBNET (timeout 10s)..."
timeout 10 nmap -sn "$LAN_SUBNET" 2>&1 | tail -5
echo "(0 hosts up or timeout = ✓ PASS)"
echo ""

echo "=== Test 5: Attacker → Inference server (should PASS when Ollama runs) ==="
if [ -n "$INFERENCE_IP" ]; then
    echo "Attempting curl http://$INFERENCE_IP:$INFERENCE_PORT (timeout 5s)..."
    curl -s --connect-timeout 5 "http://$INFERENCE_IP:$INFERENCE_PORT" 2>&1 | head -3
    echo ""
    echo "(Connection or 'Ollama is running' = ✓ PASS)"
    echo "(Timeout = expected if Ollama not yet installed)"
else
    echo "No inference config found. Skipping."
fi
echo ""

echo "=== Test 6: DNS blocked on NAT (should FAIL) ==="
echo "Attempting dig google.com @8.8.8.8 (timeout 3s)..."
dig +time=3 +tries=1 google.com @8.8.8.8 2>&1 | grep -E "status:|timed out" || echo "✓ PASS (blocked)"
echo ""

echo "=== Tests for TARGET VM (run manually via console) ==="
echo "Login to target (msfadmin/msfadmin) and run:"
echo "  ping -c 2 192.168.56.10    → should SUCCEED"
echo "  ping -c 2 192.168.122.1    → should FAIL (no route)"
echo "  ping -c 2 1.1.1.1          → should FAIL (no route)"
