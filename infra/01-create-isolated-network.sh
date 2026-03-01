#!/usr/bin/env bash
# Script: 01-create-isolated-network.sh
# Run on: Host (laptop)
# Purpose: Create the isolated libvirt network for attacker↔target recon.
#          No <forward> element = isolated from external networks. Traffic stays on the bridge.
#          DHCP reservations pin VM IPs to specific MAC addresses.

set -euo pipefail

NETWORK_NAME="darkagents-isolated"
NEXT_SCRIPT="02-create-attacker-vm.sh"

# Check if network already exists
if virsh net-info "$NETWORK_NAME" &>/dev/null; then
    echo "Step 01 already complete: network '$NETWORK_NAME' is already defined."
    echo ""
    echo "Current network status:"
    virsh net-info "$NETWORK_NAME"
    echo ""
    echo "Next step:"
    echo "  ./$NEXT_SCRIPT"
    echo ""
    echo "To recreate: virsh net-destroy $NETWORK_NAME && virsh net-undefine $NETWORK_NAME"
    exit 0
fi

# Create a temporary XML file
TMPXML=$(mktemp /tmp/darkagents-net-XXXX.xml)
trap 'rm -f "$TMPXML"' EXIT

cat > "$TMPXML" << 'EOF'
<network>
  <name>darkagents-isolated</name>
  <!--
    No <forward> element = isolated from external networks.
    Traffic stays on the bridge; guests can communicate with each other,
    and the host can reach this network via the gateway address below.
  -->
  <bridge name='virbr-iso'/>
  <ip address='192.168.56.1' netmask='255.255.255.0'>
    <dhcp>
      <!-- General DHCP range for any future VMs -->
      <range start='192.168.56.100' end='192.168.56.200'/>
      <!-- Attacker VM: pinned to 192.168.56.10 via MAC reservation -->
      <host mac='52:54:00:DA:00:10' ip='192.168.56.10'/>
      <!-- Target VM: pinned to 192.168.56.101 via MAC reservation -->
      <host mac='52:54:00:DA:01:01' ip='192.168.56.101'/>
    </dhcp>
  </ip>
</network>
EOF

echo "Defining network '$NETWORK_NAME' from XML..."
virsh net-define "$TMPXML"

echo "Setting network to autostart on host boot..."
virsh net-autostart "$NETWORK_NAME"

echo "Starting network..."
virsh net-start "$NETWORK_NAME"

echo ""
echo "=== Verification ==="
virsh net-list --all | grep "$NETWORK_NAME"
echo ""
echo "Network XML:"
virsh net-dumpxml "$NETWORK_NAME"
