# Dark Agents — Lab Setup

Creates a KVM/libvirt lab for AI-driven recon research: an attacker VM that can only reach a local LLM inference server over its NAT interface, and an intentionally-vulnerable target with no routed LAN or internet access.

The lab uses two layers of separation:
1. A libvirt NAT network for controlled attacker → inference-server access.
2. A separate libvirt isolated network for attacker → target recon traffic.

## Architecture

```
[Mac / Inference Server] ──── LAN (192.168.1.x) ────┐
                                                      │ (NAT through host)
[Host: Ubuntu 24.04 + KVM]                             │
  ├── virbr0   (default NAT, 192.168.122.0/24) ──────┘
  └── virbr-iso (isolated,   192.168.56.0/24)
         ├── Attacker VM  192.168.56.10
         └── Target VM    192.168.56.101
```

The attacker VM has two NICs: one NAT (for inference server access only, locked by iptables) and one isolated (for unrestricted recon against the target). The target has one NIC on the isolated network only.

## IP and MAC Reference

> **Setup-specific values:** Everything *inside* the libvirt boundary (MACs, the two libvirt subnets, attacker/target IPs) is hard-coded by `infra/01–04` and you should not change it unless you also edit those scripts. The **inference server IP is the only value you must set yourself** — it's whatever IP your Mac (or other inference host) currently has on your home LAN. Wherever this guide writes a concrete inference IP, treat it as illustrative; substitute your own.

| Component | MAC | IP | Network |
|---|---|---|---|
| Attacker (NAT NIC) | `52:54:00:DA:00:11` | `192.168.122.10` | default NAT |
| Attacker (Isolated NIC) | `52:54:00:DA:00:10` | `192.168.56.10` | darkagents-isolated |
| Target | `52:54:00:DA:01:01` | `192.168.56.101` | darkagents-isolated |
| Libvirt gateway (NAT) | — | `192.168.122.1` | default NAT |
| Libvirt gateway (Isolated) | — | `192.168.56.1` | darkagents-isolated |
| Inference server | — | *Your Mac's LAN IP — DHCP, will vary* | Home LAN |

---

## Phase 1 — Host Setup (Ubuntu + KVM)

> Skip this phase if your host already has Ubuntu 24.04 and KVM/libvirt running.

### 1.1 Create Bootable USB

Download the **Ubuntu 24.04 LTS Desktop** ISO from [ubuntu.com](https://ubuntu.com/download/desktop) and flash it to a USB stick (8 GB minimum):
- Windows: [Rufus](https://rufus.ie)
- Mac/Linux: balenaEtcher or `dd`

### 1.2 BIOS Setup

Before booting from USB, enter BIOS (typically F2, F12, or Del at boot) and confirm:
- **Intel VT-x / AMD-V** — **must be enabled**
- **VT-d / AMD-Vi / IOMMU** — enable if available (required for device passthrough; useful to have on even if this lab does not use passthrough)
- Boot order: USB first

### 1.3 Install Ubuntu

Boot from USB and choose **"Erase disk and install Ubuntu"** pointed at your target drive. Let the installer auto-partition. Set your username, hostname, and timezone. Eject USB and reboot when done.

> Desktop edition is recommended for the host — virt-manager GUI is useful for VM console access and debugging.

### 1.4 System Updates

```bash
sudo apt update && sudo apt upgrade -y
sudo reboot
```

Reboot to pick up any kernel updates before installing KVM.

### 1.5 Install Essential Packages

```bash
sudo apt install -y git curl wget net-tools build-essential openssh-server
```

OpenSSH lets you work from another machine on the LAN; the rest are standard dev dependencies.

> **GPU note:** If your host has an NVIDIA GPU, skip proprietary NVIDIA drivers for this project. The default `nouveau` driver is sufficient for display. NVIDIA drivers add complexity for zero benefit here.

### 1.6 Install KVM / QEMU / libvirt

```bash
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients \
  bridge-utils virt-manager virtinst virt-viewer libosinfo-bin cpu-checker
```

| Package | Purpose |
|---|---|
| `qemu-kvm` | KVM-enabled emulator |
| `libvirt-daemon-system` | Virtualization management daemon |
| `libvirt-clients` | CLI tools (`virsh`) |
| `bridge-utils` | Network bridge utilities |
| `virt-manager` | GUI for VM management |
| `virtinst` | `virt-install` CLI for creating VMs |
| `virt-viewer` | Lightweight VM console viewer |
| `libosinfo-bin` | OS variant database used by virt-install |
| `cpu-checker` | Provides `kvm-ok` for checking KVM acceleration |

### 1.7 Add User to Groups

```bash
sudo usermod -aG libvirt $USER
sudo usermod -aG kvm $USER
```

Log out and back in (or reboot) for group membership to take effect. This lets you manage VMs without sudo.

### 1.8 Verify Host Setup

Run each command and confirm the expected output:

```bash
# KVM modules loaded — should see kvm plus either kvm_intel or kvm_amd
lsmod | grep kvm

# KVM acceleration available — should say "KVM acceleration can be used"
kvm-ok

# CPU virtualization flag present — vmx = Intel VT-x, svm = AMD-V
grep -E 'vmx|svm' /proc/cpuinfo | head -1

# libvirt daemon running
systemctl status libvirtd || systemctl status virtqemud

# libvirt and QEMU versions
virsh version

# Group membership — should list libvirt and kvm
id $USER

# Default NAT network active
virsh net-list --all
# Expected: default  active  yes  yes
# If inactive, run:
#   sudo virsh net-start default && sudo virsh net-autostart default
```

---

## Phase 2 — VM Lab Setup

### Prerequisites

- Ubuntu 24.04 host with KVM/libvirt installed and working (Phase 1 complete)
- User in `kvm` and `libvirt` groups
- Default libvirt NAT network active
- Ubuntu 24.04 Server ISO downloaded to `~/darkagents-downloads/`
- Metasploitable 2 VMDK converted to QCOW2 and placed in the libvirt storage pool

### Download and Convert Metasploitable 2

```bash
mkdir -p ~/darkagents-downloads && cd ~/darkagents-downloads
wget https://releases.ubuntu.com/24.04/ubuntu-24.04.4-live-server-amd64.iso
wget https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip/download -O metasploitable-linux-2.0.0.zip
unzip metasploitable-linux-2.0.0.zip

# Convert VMDK → QCOW2 and move to libvirt pool
POOL_PATH=$(virsh pool-dumpxml default | grep -oP '(?<=<path>).*(?=</path>)')
qemu-img convert -O qcow2 Metasploitable2-Linux/Metasploitable.vmdk Metasploitable2-Linux/metasploitable2.qcow2
sudo mv Metasploitable2-Linux/metasploitable2.qcow2 "$POOL_PATH/metasploitable2.qcow2"
sudo chown libvirt-qemu:kvm "$POOL_PATH/metasploitable2.qcow2"
sudo chmod 0600 "$POOL_PATH/metasploitable2.qcow2"
virsh pool-refresh default
```

### Add DHCP Reservation for the Attacker's NAT Interface

```bash
virsh net-update default add ip-dhcp-host \
  "<host mac='52:54:00:DA:00:11' ip='192.168.122.10'/>" \
  --live --config
```

---

### Step 1 — Create the Isolated Network (Host)

```bash
bash infra/01-create-isolated-network.sh
```

Defines `darkagents-isolated`: a libvirt bridge with no `<forward>` element. This means the network does not forward traffic to the LAN or internet. Guests on this network can communicate with each other, and they may also be able to reach the host-side bridge IP (`192.168.56.1`) unless you add separate host firewall rules.

Verify:
```bash
virsh net-list --all
virsh net-dumpxml darkagents-isolated
ip link show virbr-iso
```

---

### Step 2 — Create the Attacker VM (Host)

```bash
bash infra/02-create-attacker-vm.sh
```

Creates `darkagents-attacker` (Ubuntu 24.04, 8 GB RAM, 4 vCPUs, 40 GB disk) with two NICs using the MAC addresses in the reference table above. The script stages the ISO to `/var/lib/libvirt/boot/` so QEMU can access it.

Connect to the console to install Ubuntu Server:
```bash
virt-manager   # GUI — double-click darkagents-attacker
# OR
virt-viewer darkagents-attacker
```

**Installation choices that matter:**
- Installation type: **Ubuntu Server** (not minimized)
- SSH: **Install OpenSSH server** ← required
- Storage: Use entire disk (default)
- Profile: hostname `darkagent`, create your user

After installation, SSH in from the host:
```bash
ssh <your-username>@192.168.122.10
```

Inside the attacker VM, verify both NICs and routes:
```bash
ip -br addr show
ip route

# Expected shape:
# default via 192.168.122.1 dev <NAT_NIC>
# 192.168.122.0/24 dev <NAT_NIC>
# 192.168.56.0/24 dev <ISO_NIC>
```

---

### Step 3 — Install Packages on Attacker VM (Attacker VM, via SSH)

**Do this before iptables lockdown — apt needs internet access.**

```bash
bash infra/03-attacker-post-install.sh
```

Installs recon tooling (`nmap`, `nikto`, `snmp`, `netcat-openbsd`, `curl`, `dnsutils`, `whois`, `tcpdump`, `tmux`, `git`), Python dev packages (`python3-pip`, `python3-venv`, `python3-dev`, `build-essential`), the `uv` project/package manager (into `~/.local/bin` via the official installer), and `iptables-persistent`.

> **Run as the operator user, not root.** The script installs `uv` into the operator's `~/.local/bin`; running the whole script under `sudo` would land `uv` in `/root/.local/bin` instead and break the agent's `uv run` invocations. The script refuses to run as root.
>
> After it finishes, either start a fresh SSH session or run `source ~/.local/bin/env` in the current session so `uv` is on `PATH`.

> **Note:** `enum4linux` is unavailable in Ubuntu 24.04 repos. Install `enum4linux-ng` via pip if needed.

---

### Step 4 — Create the Target VM (Host)

```bash
bash infra/04-create-target-vm.sh
```

Imports Metasploitable 2 as `darkagents-target` (1 GB RAM, 1 vCPU) on the isolated network only. Uses `bus=ide` and `model=e1000` for maximum compatibility with the old Metasploitable 2 image and kernel. Do not switch this VM to VirtIO unless you have tested it on a clone.

Verify it boots:
```bash
virt-viewer darkagents-target
# Login: msfadmin / msfadmin
# Check IP: ifconfig  → should show 192.168.56.101 on eth0
```

> **Do not patch or update Metasploitable 2.** The vulnerabilities are intentional.

---

### Step 5 — Pre-Lockdown Verification (Attacker VM)

```bash
bash infra/05-pre-lockdown-verify.sh
```

Confirms that before iptables is applied:
- Attacker → Target (isolated): **PASS**
- Attacker → Gateway (NAT): **PASS**
- Attacker → Internet: **PASS** (expected; will be blocked after lockdown)

Also verify target isolation manually via `virt-viewer darkagents-target`:
```bash
ping -c 2 192.168.56.10   # PASS (can reach attacker)
ping -c 2 192.168.56.1    # MAY PASS (host-side bridge IP for isolated network)
ping -c 2 192.168.122.1   # FAIL (target is not attached to NAT network)
ping -c 2 1.1.1.1          # FAIL (no internet forwarding)
```

---

### Step 6 — iptables Lockdown (Attacker VM)

First, identify your NAT interface (the one with IP `192.168.122.10`):
```bash
ip -br addr show
```

Find your Mac's current LAN IP (run on Mac):
```bash
ipconfig getifaddr en0   # or en1 for Wi-Fi
```

Apply the lockdown:
```bash
sudo bash infra/06-setup-iptables.sh <NAT_NIC> <INFERENCE_IP>
# Example (this lab): sudo bash infra/06-setup-iptables.sh enp1s0 192.168.1.182
# Replace `enp1s0` with whatever the previous `ip -br addr show` reported, and
# replace `192.168.1.182` with your own Mac's LAN IP from `ipconfig getifaddr`.
```

Locks outbound traffic on the NAT interface to only allow TCP to the inference server on port 11434 and DHCP. The script should not block established traffic or SSH management unless you are prepared to use `virt-manager` / `virt-viewer` console access instead. Saves config to `/etc/darkagents/inference.conf` for use by helper scripts.

---

### Step 7 — Post-Lockdown Verification (Attacker VM)

```bash
bash infra/07-post-lockdown-verify.sh
```

Expected results:

| Test | Expected |
|---|---|
| Attacker → Target (isolated) | PASS |
| Attacker → 1.1.1.1 (ping) | BLOCKED |
| Attacker → 1.1.1.1:443 (TCP) | BLOCKED |
| Attacker → LAN scan | BLOCKED |
| Attacker → Inference IP:11434 | PASS (or timeout if Ollama not yet running) |
| DNS to 8.8.8.8 | BLOCKED |

If you intend to keep SSH management available from the host, verify it from the host after lockdown:
```bash
ssh <your-username>@192.168.122.10
# Expected: PASS, unless you intentionally made the VM console-only after lockdown
```

---

### Step 8 — Take Baseline Snapshots (Host)

```bash
bash infra/08-take-snapshot.sh
```

Creates external, disk-only baseline snapshots of both VMs. In this workflow, the snapshot becomes the saved baseline point and later VM changes are written into external overlay files.

Check what snapshots exist:
```bash
virsh snapshot-list darkagents-attacker
virsh snapshot-list darkagents-target
```

Inspect the active disk files if needed:
```bash
virsh domblklist --details darkagents-attacker
virsh domblklist --details darkagents-target
```

## Helper Scripts

### Update Inference Server IP (Attacker VM)

When your Mac's DHCP lease changes:
```bash
sudo bash infra/09-update-inference-ip.sh <NEW_INFERENCE_IP>
```

Finds and replaces the inference server rule in iptables, saves, and updates `/etc/darkagents/inference.conf`.

### Temporarily Open Firewall (Attacker VM)

When you need to install packages after lockdown:
```bash
sudo bash infra/10-temp-open-firewall.sh open
sudo apt update && sudo apt install -y <package>
sudo bash infra/10-temp-open-firewall.sh close
```

---

## Troubleshooting

**Metasploitable won't boot / kernel panic**
```bash
virsh dumpxml darkagents-target | grep -A3 "<disk"
# Must show bus='ide' — if virtio, recreate the VM
```

**Target VM has wrong IP or no IP**
```bash
virsh domiflist darkagents-target   # verify MAC is 52:54:00:DA:01:01
virsh net-dhcp-leases darkagents-isolated
```

**DHCP fails after iptables lockdown**
```bash
sudo dhclient -r <NAT_NIC> && sudo dhclient <NAT_NIC>
```

**iptables rules gone after reboot**
```bash
sudo systemctl status netfilter-persistent
cat /etc/iptables/rules.v4
# If empty, re-run: sudo netfilter-persistent save
```

**Can't SSH to attacker VM**
```bash
virsh net-dhcp-leases default          # confirm 192.168.122.10 is leased
virsh list --all                       # confirm VM is running
virsh start darkagents-attacker        # start if needed
```

If this only fails after lockdown, use `virt-manager` / `virt-viewer` console access and inspect the VM firewall rules.

---

## Scripts Reference

| Script | Run On | Purpose | Needs Internet? |
|---|---|---|---|
| `01-create-isolated-network.sh` | Host | Create isolated libvirt network | No |
| `02-create-attacker-vm.sh` | Host | Create attacker VM | No |
| `03-attacker-post-install.sh` | Attacker VM | Install packages | **Yes** |
| `04-create-target-vm.sh` | Host | Import Metasploitable 2 | No |
| `05-pre-lockdown-verify.sh` | Attacker VM | Verify connectivity before lockdown | Some tests |
| `06-setup-iptables.sh` | Attacker VM | Apply NAT lockdown | No |
| `07-post-lockdown-verify.sh` | Attacker VM | Verify lockdown works | No |
| `08-take-snapshot.sh` | Host | Baseline snapshots | No |
| `09-update-inference-ip.sh` | Attacker VM | Update inference server IP | No |
| `10-temp-open-firewall.sh` | Attacker VM | Temporarily open/close firewall | Opens temporarily |
| `11-install-ollama.sh` | Mac (inference server) | Verify Ollama CLI and server after manual install | No |
| `12-start-ollama-session.sh` | Mac (inference server) | Start Ollama bound to `0.0.0.0:11434` so the attacker VM can reach it | No |
| `13-test-structured-output.sh` | Mac or any host reachable to Ollama | Verify the configured model returns valid structured JSON | No |
| `14-verify-connectivity.sh` | Attacker VM | Confirm Ollama reachable through NAT and isolation blocks everything else | No |
| `15-stop-ollama-session.sh` | Mac (inference server) | Unload models, quit Ollama, free GPU memory | No |

After lab setup is complete, see [`docs/porting-guide.md`](./porting-guide.md) for porting the reconnaissance agent onto the attacker VM.
