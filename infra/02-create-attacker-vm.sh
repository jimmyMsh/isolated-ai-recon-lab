#!/usr/bin/env bash
# Script: 02-create-attacker-vm.sh
# Run on: Host (laptop)
# Purpose: Create the attacker VM with two NICs (NAT + isolated)

set -euo pipefail

VM_NAME="darkagents-attacker"

# --- Discover paths ---
UBUNTU_ISO=$(ls ~/darkagents-downloads/ubuntu-24.04*-live-server-amd64.iso 2>/dev/null | head -1)
POOL_PATH=$(virsh pool-dumpxml default 2>/dev/null | grep -oP '(?<=<path>).*(?=</path>)')

if [ -z "$UBUNTU_ISO" ]; then
    echo "ERROR: Ubuntu ISO not found in ~/darkagents-downloads/"
    echo "Download it first (like using wget https://releases.ubuntu.com/24.04/ubuntu-24.04.2-live-server-amd64.iso)."
    exit 1
fi

if [ -z "$POOL_PATH" ]; then
    echo "ERROR: Could not determine libvirt storage pool path."
    exit 1
fi

# --- Ensure ISO is accessible to the hypervisor (libvirt-qemu) ---
# QEMU under qemu:///system often can't read from /home. Stage ISO into /var/lib/libvirt/boot.
ISO_BASENAME="$(basename "$UBUNTU_ISO")"
STAGE_DIR="/var/lib/libvirt/boot"
STAGED_ISO="${STAGE_DIR}/${ISO_BASENAME}"

if [ ! -r "$UBUNTU_ISO" ]; then
    echo "ERROR: ISO exists but is not readable: $UBUNTU_ISO"
    exit 1
fi

# Create stage dir + copy if needed (copy when missing or size differs)
sudo mkdir -p "$STAGE_DIR"

SRC_SIZE="$(stat -c%s "$UBUNTU_ISO")"
DST_SIZE="0"
if [ -f "$STAGED_ISO" ]; then
    DST_SIZE="$(stat -c%s "$STAGED_ISO" 2>/dev/null || echo 0)"
fi

if [ ! -f "$STAGED_ISO" ] || [ "$SRC_SIZE" != "$DST_SIZE" ]; then
    echo "Staging ISO for libvirt access:"
    echo "  From: $UBUNTU_ISO"
    echo "  To:   $STAGED_ISO"
    sudo cp "$UBUNTU_ISO" "$STAGED_ISO"
    sudo chmod 0644 "$STAGED_ISO"
fi

UBUNTU_ISO="$STAGED_ISO"

echo "ISO: $UBUNTU_ISO"
echo "Disk will be created at: $POOL_PATH/${VM_NAME}.qcow2"
echo ""

# Check for os-variant support
# Ubuntu 24.04 may be listed as 'ubuntu24.04' or 'ubuntu-lts-latest'
OS_VARIANT=$(osinfo-query os short-id=ubuntu24.04 2>/dev/null | tail -1 | awk '{print $1}')
if [ -z "$OS_VARIANT" ]; then
    echo "WARN: os-variant 'ubuntu24.04' not found in osinfo database."
    echo "Trying 'ubuntu22.04' as fallback (affects only default device choices, not functionality)."
    OS_VARIANT="ubuntu22.04"
fi
echo "Using os-variant: $OS_VARIANT"
echo ""

# --- Create the VM ---
# NIC1 (NAT): MAC 52:54:00:DA:00:11 → will get 192.168.122.10 via DHCP reservation
# NIC2 (Isolated): MAC 52:54:00:DA:00:10 → will get 192.168.56.10 via DHCP reservation
virt-install \
  --name "$VM_NAME" \
  --ram 8192 \
  --vcpus 4 \
  --disk "path=${POOL_PATH}/${VM_NAME}.qcow2,size=40,format=qcow2" \
  --cdrom "$UBUNTU_ISO" \
  --os-variant "$OS_VARIANT" \
  --network network=default,mac=52:54:00:DA:00:11 \
  --network network=darkagents-isolated,mac=52:54:00:DA:00:10 \
  --graphics vnc,listen=127.0.0.1 \
  --noautoconsole \
  --boot uefi

echo ""
echo "VM '$VM_NAME' created. Connect to its console to begin installation:"
echo "  Option 1 (GUI): virt-manager  (double-click the VM)"
echo "  Option 2 (CLI): virt-viewer $VM_NAME"
echo ""
echo "The VM is booting from the Ubuntu ISO. Proceed to Step 5 for installation guidance."
