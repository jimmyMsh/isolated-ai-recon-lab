#!/usr/bin/env bash
# Script: 04-create-target-vm.sh
# Run on: Host (laptop)
# Purpose: Import Metasploitable 2 as a KVM VM on the isolated network

set -euo pipefail

VM_NAME="darkagents-target"

# --- Discover disk path  ---
POOL_PATH=$(virsh pool-dumpxml default 2>/dev/null | grep -oP '(?<=<path>).*(?=</path>)')
DISK_PATH="${POOL_PATH}/metasploitable2.qcow2"

if [ ! -f "$DISK_PATH" ]; then
    echo "ERROR: Metasploitable disk not found at $DISK_PATH"
    echo "Did you run Step 3 (convert and move the QCOW2)?"
    exit 1
fi

echo "Importing Metasploitable 2 from: $DISK_PATH"
echo ""

# --- Create the VM ---
# NIC: MAC 52:54:00:DA:01:01 → will get 192.168.56.101 via DHCP reservation
# CRITICAL: bus=ide (old kernel lacks VirtIO drivers)
# CRITICAL: model=e1000 (old kernel may lack VirtIO net drivers)
virt-install \
  --name "$VM_NAME" \
  --ram 1024 \
  --vcpus 1 \
  --import \
  --disk "path=${DISK_PATH},format=qcow2,bus=ide" \
  --os-variant generic \
  --network network=darkagents-isolated,mac=52:54:00:DA:01:01,model=e1000 \
  --graphics vnc,listen=127.0.0.1 \
  --noautoconsole

echo ""
echo "VM '$VM_NAME' created and booting."
echo "Connect to verify it boots: virt-viewer $VM_NAME"
echo ""
echo "Login credentials: msfadmin / msfadmin"
echo "DO NOT update or patch this VM — the vulnerabilities are the point."
