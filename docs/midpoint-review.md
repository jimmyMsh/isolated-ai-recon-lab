# Dark Agents — Midpoint Review (Phases 1–3)

Reference document for the project review covering host setup, network architecture, and inference server configuration. Talking points are in normal text; supporting detail for later reference is in blockquotes and code blocks.

---

## Phase 1: Host Setup — Ubuntu + KVM

**Why KVM instead of VirtualBox:** On Ubuntu 24.04, the KVM kernel module loads by default and claims VT-x. VirtualBox cannot acquire VT-x when KVM holds it. Rather than fighting the kernel, we use KVM — a Type 1 hypervisor built into Linux, standard in production and cloud environments.

> **Host specs:**
> - Ubuntu 24.04.4 LTS (kernel 6.17.0-14-generic)
> - QEMU 8.2.2, libvirt 10.0.0
> - Intel i7-8850H, Quadro P600 (GPU unused — no local inference)
> - Hostname: `DarkHost`, LAN: Wi-Fi (`wlo1`), IP `192.168.1.191`

**What was done:**
- Installed Ubuntu 24.04 LTS Desktop (clean install, USB boot)
- Enabled VT-x and VT-d in BIOS
- Installed KVM/QEMU/libvirt stack (`qemu-kvm`, `libvirt-daemon-system`, `virt-manager`, etc.)
- Added user to `libvirt` and `kvm` groups
- Verified: KVM modules loaded, `kvm-ok` passes, libvirtd running, default NAT network active

**Demo commands (host):**
```bash
kvm-ok                    # "KVM acceleration can be used"
virsh version             # libvirt + QEMU versions
virsh net-list --all      # shows default + darkagents-isolated
```

---

## Phase 2: Network Architecture & VM Setup

### Core Topology: Two libvirt networks

The attacker VM straddles two networks. The target VM is on the isolated network only.

- **Isolated network** (`darkagents-isolated`, `192.168.56.0/24`): No `<forward>` element in the libvirt XML — traffic stays on the bridge. The target has no route out. This is where recon happens.
- **NAT network** (`default`, `192.168.122.0/24`): Provides outbound access through the host's IP via masquerading. Used exclusively for reaching the inference server.

> **IP/MAC Reference:**
> | Component | MAC | IP | Network |
> |---|---|---|---|
> | Attacker (NAT) | `52:54:00:DA:00:11` | `192.168.122.10` | default NAT |
> | Attacker (Isolated) | `52:54:00:DA:00:10` | `192.168.56.10` | darkagents-isolated |
> | Target | `52:54:00:DA:01:01` | `192.168.56.101` | darkagents-isolated |
> | Libvirt gateway (NAT) | — | `192.168.122.1` | default NAT |
> | Libvirt gateway (Isolated) | — | `192.168.56.1` | darkagents-isolated |
> | Inference server (Mac) | — | `192.168.1.182` (DHCP) | Home LAN |

### Why NAT Instead of Bridging

Standard Linux bridging is incompatible with most Wi-Fi drivers — they enforce a single-MAC-per-association limit. NAT/masquerading lets the VM share the host's wireless connection seamlessly. This hardware constraint drove the iptables-based isolation approach.

### Dual-Layer Isolation Strategy

1. **NAT boundary** — stateful firewall preventing unsolicited inbound connections from the LAN
2. **iptables on attacker VM** — restricts outbound traffic so the VM can only reach the inference server at `<IP>:11434`

### Why iptables Inside the VM (Not nwfilter at Hypervisor)

The iptables lockdown lives inside the attacker VM because it's part of the agent's operational environment — visible, auditable, and demonstrable from within the VM.

> **Alternative considered — nwfilter (hypervisor-level):**
> More secure (VM cannot modify filters), but less visible to auditors, libvirt-specific, and cumbersome to update. Rules would live in host XML rather than inside the environment being demonstrated.
>
> **Defensible position:** "For a production deployment, defense-in-depth would add hypervisor-level nwfilter rules as a second layer. The current approach prioritizes transparency and demonstrability for this POC."

### Deterministic IPs via DHCP Reservations

IPs are pinned to MAC addresses in libvirt's DHCP config (not static config inside VMs). Rebuilding a VM with the same MAC gives the same IP automatically.

> Only one variable address in the system: the inference server's LAN IP (Mac DHCP lease). Everything else is controlled by libvirt.

### The iptables Lockdown (Script 06)

Five rules on the OUTPUT chain, scoped to the NAT interface only:

> ```
> 1. ACCEPT ESTABLISHED,RELATED on NAT NIC  (return traffic)
> 2. ACCEPT NEW TCP to <inference-IP>:11434  (Ollama API)
> 3. ACCEPT UDP 68→67 to 255.255.255.255    (DHCP discover)
> 4. ACCEPT UDP 68→67 to 192.168.122.1      (DHCP renew)
> 5. DROP everything else on NAT NIC
> ```

These rules only apply to the NAT interface (`enp1s0`). The isolated interface has no iptables rules — it is completely open for recon. The OUTPUT chain's default policy is ACCEPT (not DROP), so traffic on the isolated interface and localhost passes through unaffected. Rules 3-4 keep DHCP working so the VM retains its IP after lease renewal.

> **What each rule does:**
> - **Rule 1 (ESTABLISHED,RELATED):** If the VM started a connection (e.g., sent a prompt to Ollama), allow the response packets back through. Standard stateful firewall behavior.
> - **Rule 2 (NEW TCP to inference:11434):** The single pinhole — allow new outbound connections, but only to the Ollama server on its specific port. Nothing else.
> - **Rules 3-4 (DHCP):** Allow the VM to request and renew its IP address. Port 68 (client) → port 67 (server). Rule 3 is the initial broadcast discovery; rule 4 is direct renewal to the known gateway.
> - **Rule 5 (DROP):** Block all other outbound traffic on the NAT interface. No internet, no DNS, no LAN scanning.
> - **Default policy ACCEPT:** The DROP in rule 5 targets only the NAT interface. The chain's default is ACCEPT so that isolated-network traffic (recon) and localhost traffic pass through with no restrictions.
>
> **Additional notes:**
> - No DNS allowed — the agent addresses the inference server by IP directly
> - Rules persist across reboots via `netfilter-persistent`
> - Inference server IP saved to `/etc/darkagents/inference.conf` for helper scripts

### Attacker VM (`darkagents-attacker`)

- Ubuntu 24.04 Server (no GUI — lighter footprint, SSH access from host)
- 8 GB RAM, 4 vCPUs, 40 GB disk, UEFI boot
- Two NICs: NAT (`enp1s0`) + Isolated (`enp2s0`)
- Installed tools: nmap, nikto, snmp, netcat, curl, dnsutils, whois, tcpdump, tmux, Python 3 dev stack

> **Packages-before-lockdown ordering:** Once iptables locks the NAT interface, `apt` can't reach mirrors. All packages must be installed before lockdown (script 03). `10-temp-open-firewall.sh` exists as an escape hatch for later installs.

### Target VM (`darkagents-target`)

- Metasploitable 2 (Ubuntu 8.04, kernel 2.6.24)
- 1 GB RAM, 1 vCPU, IDE disk bus + e1000 NIC (old kernel lacks VirtIO drivers)
- Isolated network only — no route out, no internet, no LAN
- Login: `msfadmin/msfadmin` — intentionally vulnerable, never patched

### Baseline Snapshots

External, disk-only snapshots via `--disk-only --atomic`:
- `darkagents-attacker`: `baseline-post-setup`
- `darkagents-target`: `baseline-clean`

> External disk-only snapshots are required because libvirt's internal snapshots do not support UEFI firmware VMs.

**Demo commands (host):**
```bash
virsh list --all                                  # both VMs running
virsh domiflist darkagents-attacker                # two NICs
virsh domiflist darkagents-target                  # one NIC (isolated only)
virsh net-dhcp-leases darkagents-isolated          # pinned IPs
virsh net-dumpxml darkagents-isolated | head -20   # no <forward> element
virsh snapshot-list darkagents-attacker            # baseline snapshot
```

**Demo commands (attacker VM):**
```bash
sudo iptables -L OUTPUT -v -n --line-numbers  # show the 5 rules
ping -c 1 192.168.56.101                       # target reachable (isolated)
ping -c 1 -W 2 1.1.1.1                         # blocked (NAT locked)
```

---

## Phase 3: Ollama & Inference Server

### Model Selection: Qwen3 8B

Selected `qwen3:8b` (Q4_K_M quantization, ~5 GB on disk) for:
- Top-ranked tool calling in Docker's practical evaluation of local LLMs
- Structured JSON output enforced server-side via Ollama's `format` parameter
- 32K context window (vs Llama 3.1's 16K) — more room for accumulated scan results
- Less aggressive safety filters for recon task prompts (Apache 2.0 license)

> **Why not Llama 3.1 8B:** Meta's safety training is more aggressive — meaningful risk of refusing nmap/recon commands even with a well-crafted system prompt. Also has a smaller context window (16K vs 32K).

> **Fallback model:** `qwen2.5:7b` — slightly smaller, faster, battle-tested longer. Available if Qwen3 proves problematic.

### Inference Server Setup

- **Device:** Apple Silicon Mac (~10-12 GB available for inference after OS and apps)
- **Ollama version:** 0.16.2
- **Listening on:** All interfaces (`0.0.0.0:11434`) — set per session via script 12
- **Auto-start disabled** — Ollama runs only during dev sessions

### Structured Output

Ollama's `format` parameter accepts a JSON schema and enforces it server-side via grammar-guided generation. Output is guaranteed valid JSON matching the schema — the model cannot produce malformed responses. This is what the agent will use to get structured commands from the LLM.

> **Example:** The schema can constrain `operation` to an enum like `["host_discovery", "port_scan", "service_enum", "os_fingerprint"]` and require fields like `tool`, `command_args`, and `reasoning`.

### Thinking Mode & Performance

Qwen3 defaults to thinking ON — it reasons through decisions before responding. This is togglable per request.

| Mode | Response Time | Notes |
|---|---|---|
| Thinking ON | ~14-17s | Better reasoning quality; raw generation ~40 tok/s |
| Thinking OFF | ~2-5s | Append `/no_think` to user message |

> **Context window:** Ollama defaults to 2048 tokens. The agent should set 4096-8192 via the `options.num_ctx` parameter. Larger context uses more memory (KV cache grows linearly).

> **Model memory footprint:** ~6-7 GB total (5 GB weights + KV cache at 4K context). Fits comfortably on a 16 GB+ Apple Silicon Mac.

### Session Workflow

1. **Start session (Mac):** `bash infra/12-start-ollama-session.sh` — configures network listening, opens Ollama, verifies binding
2. **If Mac IP changed:** `sudo bash infra/09-update-inference-ip.sh <NEW_IP>` on attacker VM
3. **End session (Mac):** `bash infra/15-stop-ollama-session.sh` — unloads models, stops server, frees memory

### End-to-End Verification (All Passed)

| Test | Result |
|---|---|
| Attacker → Ollama (curl + generation) | PASS |
| Structured JSON output (schema-constrained) | PASS |
| Attacker → Internet (post-lockdown) | BLOCKED |
| Attacker → DNS | BLOCKED |
| Attacker → LAN scan | BLOCKED |
| Target → Internet | BLOCKED (no route) |
| Non-inference ports on Mac | BLOCKED |
| Target reachable on isolated network | PASS |

> **Security note:** Ollama has no built-in authentication. Acceptable in this isolated lab — iptables ensures only the attacker VM can reach it, and only on port 11434.

**Demo commands (Mac):**
```bash
bash infra/13-test-structured-output.sh  # 3 tests: basic JSON, schema-constrained, timed
```

**Demo commands (attacker VM) — single best demo script:**
```bash
bash infra/14-verify-connectivity.sh  # 8-test suite: inference works + everything else blocked
```

---

## Next Steps

With the infrastructure verified end-to-end, the remaining work focuses on the autonomous agent itself.

**MITRE ATT&CK mapping** — Research the specific reconnaissance techniques (from the MITRE ATT&CK framework) that apply to the target environment, and map them to concrete tool commands the agent can execute (nmap scans, service enumeration, OS fingerprinting, etc.).

**Agent design and logging** — Design the agent's decision loop: how it receives scan results, reasons about what to do next via the LLM, and selects the next operation. This includes defining the structured schemas the LLM will respond with, the prompt engineering strategy, and a logging specification so every agent action, LLM response, and scan result is recorded for analysis and reproducibility.

**Implementation** — Build and test the agent on the attacker VM, running against the target through the verified infrastructure.

> **More detail for reference:**
> - The agent will run as a Python process on the attacker VM, sending prompts to Ollama over the NAT network and executing recon tools on the isolated network
> - Each agent "cycle" is: observe scan results → send to LLM with context → receive structured JSON command → execute tool → log everything → repeat
> - Thinking mode (ON/OFF) will be tuned per operation type — complex decisions (what to scan next) may benefit from thinking, while simple parsing does not
> - Logging captures the full chain: raw LLM responses (including thinking), tool commands executed, tool output, and timing — enabling post-hoc analysis of the agent's reasoning
> - The baseline snapshots (script 08) allow resetting the target to a clean state between test runs

---

## All Scripts Reference

Scripts 01-08 run once during setup. Scripts 09-10 are helpers. Scripts 11-15 are Phase 3 (Ollama).

| # | Script | Runs On | Purpose |
|---|---|---|---|
| 01 | `create-isolated-network.sh` | Host | Create isolated libvirt network (no routing) |
| 02 | `create-attacker-vm.sh` | Host | Create attacker VM with dual NICs |
| 03 | `attacker-post-install.sh` | Attacker VM | Install packages (before lockdown) |
| 04 | `create-target-vm.sh` | Host | Import Metasploitable 2 |
| 05 | `pre-lockdown-verify.sh` | Attacker VM | Verify pre-lockdown connectivity |
| 06 | `setup-iptables.sh` | Attacker VM | Apply NAT lockdown |
| 07 | `post-lockdown-verify.sh` | Attacker VM | Verify lockdown effectiveness |
| 08 | `take-snapshot.sh` | Host | Baseline snapshots |
| 09 | `update-inference-ip.sh` | Attacker VM | Update inference server IP in iptables |
| 10 | `temp-open-firewall.sh` | Attacker VM | Temporary firewall open/close |
| 11 | `install-ollama.sh` | Mac | Verify Ollama installation |
| 12 | `start-ollama-session.sh` | Mac | Start session (configure listening, open app) |
| 13 | `test-structured-output.sh` | Mac / Any | Test JSON + schema-constrained output |
| 14 | `verify-connectivity.sh` | Attacker VM | Full 8-test end-to-end verification |
| 15 | `stop-ollama-session.sh` | Mac | Stop Ollama, free memory |

---

## Architecture Diagram

```mermaid
graph LR
    MAC["Mac Inference Server<br/>Ollama :11434 · Qwen3 8B<br/>192.168.1.182 (DHCP)<br/><i>only variable IP in system</i>"]

    subgraph HOST["Host: DarkHost — Ubuntu 24.04 + KVM/libvirt"]
        direction LR
        NAT["NAT Network · virbr0<br/>192.168.122.0/24<br/>masquerades to LAN"]
        ATK["Attacker VM · Ubuntu 24.04<br/>enp1s0: .122.10 (NAT)<br/>enp2s0: .56.10 (Isolated)<br/><b>iptables: NAT → inference only</b>"]
        ISO["Isolated Network · virbr-iso<br/>192.168.56.0/24<br/>no forwarding"]
        TGT["Target VM · Metasploitable 2<br/>192.168.56.101<br/><i>no route out</i>"]
    end

    MAC -- "TCP :11434 only<br/>(NAT masquerade)" --> NAT
    NAT --- ATK
    ATK -- "unrestricted recon" --> ISO
    ISO --- TGT

    style MAC fill:#4a9,stroke:#333,color:#fff
    style ATK fill:#47a,stroke:#333,color:#fff
    style TGT fill:#a44,stroke:#333,color:#fff
    style NAT fill:#ffd,stroke:#aa8
    style ISO fill:#fdd,stroke:#a88
```

> **Key visual story:** The attacker VM is the only component that touches both networks. Its NAT side is locked to a single IP:port (Ollama). The target is completely walled off. Only the Mac's DHCP IP is variable — everything inside the libvirt boundary is stable and deterministic.
