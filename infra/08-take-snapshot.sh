#!/usr/bin/env bash
# Script: 08-take-snapshot.sh
# Purpose: Take baseline snapshots of both VMs (disk-only, external; UEFI-safe)

set -euo pipefail

# Verify both VMs exist before attempting snapshots
for vm in darkagents-attacker darkagents-target; do
    if ! virsh dominfo "$vm" &>/dev/null; then
        echo "ERROR: VM '$vm' is not defined. Create it first."
        exit 1
    fi
done

echo "=== Snapshotting attacker VM (vda) ==="
virsh snapshot-create-as darkagents-attacker \
  --name "baseline-post-setup" \
  --description "Ubuntu 24.04 Server installed, all packages, iptables configured" \
  --disk-only --atomic \
  --diskspec vda,snapshot=external

echo ""
echo "=== Snapshotting target VM (hda) ==="
virsh snapshot-create-as darkagents-target \
  --name "baseline-clean" \
  --description "Metasploitable 2, unmodified, isolated network only" \
  --disk-only --atomic \
  --diskspec hda,snapshot=external

echo ""
echo "=== Verify snapshots ==="
echo "Attacker:"
virsh snapshot-list darkagents-attacker
echo ""
echo "Target:"
virsh snapshot-list darkagents-target

echo ""
echo "To revert later:"
echo "  virsh snapshot-revert <vm-name> <snapshot-name>"
