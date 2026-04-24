# Ollama Setup Guide — LLM Inference Server

## Overview

This guide covers installing Ollama on macOS (Apple Silicon), selecting a model for the recon agent, configuring network listening, and verifying end-to-end connectivity from the attacker VM.

**What this project uses:** A Mac with Apple Silicon serving as the LLM inference server over the LAN. The attacker VM sends prompts to the Ollama API and parses structured JSON responses. Ollama was chosen because it wraps llama.cpp behind a simple REST API with built-in model management and Metal GPU acceleration.

**Inference server IP:** Your Mac's LAN IP (DHCP — may change between sessions). Replace `<INFERENCE_IP>` throughout.

Tested with Ollama 0.16.2.

---

## Part 1: Installing Ollama

Direct download from [ollama.com](https://ollama.com/download) is recommended. This installs `Ollama.app` as a menu bar application that manages the server process automatically. Homebrew (`brew install --cask ollama`) works too but the direct download receives automatic updates and provides a clean start/stop from the menu bar.

Run script `11-install-ollama.sh` on your Mac (see `infra/` folder), or follow these manual steps:

1. **Download:** Go to https://ollama.com/download and click "Download for macOS".

2. **Extract and install:** Unzip it, drag `Ollama.app` to `/Applications`.

3. **First launch:** Open `Ollama.app` from Applications. It will:
   - Ask to install the `ollama` command-line tool (say yes)
   - Start the Ollama server as a background process
   - Appear as a llama icon in your menu bar

4. **Verify:**
   ```bash
   ollama --version
   curl http://localhost:11434    # should return "Ollama is running"
   ```

### Controlling Auto-Start

By default, Ollama adds itself to Login Items (starts at every login). To disable:

1. Open **System Settings** → **General** → **Login Items & Extensions**
2. Find **Ollama** and remove it

**Session workflow:**
- **Start:** Open `Ollama.app` from Applications or Spotlight (⌘+Space → "Ollama")
- **End:** Click the llama icon in the menu bar → "Quit Ollama"
- **Check:** Look for the menu bar icon, or `curl http://localhost:11434`

For persistent auto-start with network listening (e.g., a dedicated inference machine), see Appendix A.

---

## Part 2: Configuring Network Listening

By default, Ollama binds to `127.0.0.1:11434` (localhost only). The attacker VM needs to reach it over the LAN, so Ollama must listen on `0.0.0.0:11434` (all interfaces).

The Ollama macOS app reads environment variables via `launchctl setenv`. This does not persist across reboots — you set it each session before opening Ollama.

### Session Start Script

Use `12-start-ollama-session.sh` at the start of each dev session. It sets `OLLAMA_HOST`, opens the app, waits for the server, and verifies interface binding.

**Manual equivalent:**
```bash
launchctl setenv OLLAMA_HOST "0.0.0.0:11434"
# Quit Ollama if already running (menu bar → Quit)
open -a Ollama
# Wait a few seconds, then verify:
curl http://localhost:11434
lsof -i :11434   # look for *:11434 (LISTEN)
```

### macOS Firewall Note

If you have the macOS firewall enabled, allow incoming connections for Ollama when prompted. Fix a denied setting in System Settings → Network → Firewall → Options.

---

## Part 3: Model Selection

### Hardware Sizing

Apple Silicon Macs use unified memory — the same RAM serves as VRAM. The default Ollama tags used here are Q4_K_M quantized, which balances quality, speed, and memory. Reserve ~4-6GB for macOS and apps; the rest is available for inference.

| Available RAM | Max Model Size (Q4_K_M) | Recommended Models | Approx. Speed |
|---|---|---|---|
| **8GB** (e.g., 16GB Mac, light usage) | 7-8B | `qwen3:8b`, `llama3.1:8b`, `mistral:7b` | 15-25 tok/s |
| **12-16GB** (e.g., 24GB Mac, or 16GB dedicated) | 12-14B | `qwen3:14b`, `gemma3:12b`, `phi4:14b` | 10-20 tok/s |
| **20-28GB** (e.g., 32GB Mac) | 27-32B | `qwen3:32b`, `gemma3:27b` | 5-12 tok/s |
| **48GB+** (e.g., 64GB Mac/Studio) | 70B+ | `llama3.3:70b`, `qwen2.5:72b` | 3-8 tok/s |

Speed varies by chip variant — M3 Pro/Max with more GPU cores runs ~2x faster than M1 base at the same model size. Context window size also affects memory: the KV cache grows with context length, and at 32K context an 8B model uses ~4.5GB additional for KV cache alone. Ollama picks a default context length based on available VRAM/unified memory (see "Adjustments" below to set it explicitly).

### Model Comparison for Recon Agent Use

| Model | Size (default Ollama tag) | Structured-output fit | Ollama-listed context | Project note |
|---|---:|---|---:|---|
| **Qwen3 8B** | ~5.2GB, Q4_K_M | Primary observed model; still requires parse, retry, and guardrails | 40K | Used for current runtime findings; validate behavior from JSONL logs and reports |
| Qwen2.5 7B | ~4.7GB, Q4_K_M | Candidate fallback; validate against the same prompts before relying on it | 32K | Smaller alternative if memory or speed is tight |
| Llama 3.1 8B | ~4.9GB, Q4_K_M | Candidate fallback; validate structured output and refusal behavior locally | 128K | Larger advertised context than Qwen3 in Ollama, but behavior must be tested |
| Mistral 7B v0.3 | ~4.4GB, Q4_K_M | Candidate fallback; validate structured output locally | 32K | Lightweight option for constrained hardware |

### What This Project Uses

**Primary: `qwen3:8b`** — Selected for this project because:
- Structured JSON support via Ollama's `format` parameter
- 40K context window as packaged by Ollama (Llama 3.1 8B's tag is larger at 128K, but Qwen3's structured-output and recon-planning behavior fit this lab better)
- Runtime observations show it will attempt the lab's recon planning tasks, with guardrails catching invalid parameters
- Apache 2.0 license

At Q4_K_M quantization (~5GB weights), total memory usage is ~6-7GB with a 4K context window. Fits comfortably on a 16GB+ Mac with moderate other usage.

**Thinking mode:** Qwen3 has thinking ON by default — it reasons through decisions before responding. This adds latency and can improve some free-form reasoning tasks. The current agent does not use thinking mode for planning or interpretation: it sends schema-constrained `/api/chat` requests with `think: false`, `stream: false`, and `/no_think` in the prompt text so responses stay structured and concise.

**Fallback candidate: `qwen2.5:7b`** — Slightly smaller and often faster. Validate it against the same planning and interpretation prompts before relying on it for this agent.

### Adjustments

- **More RAM available?** Try `qwen3:14b` on a 24GB+ Mac and compare its planning quality against `qwen3:8b`; expect slower responses (~10-15 tok/s).
- **Speed is critical?** Use `qwen2.5:7b` or disable thinking mode (`/no_think`).
- **Different quantization?** Ollama pulls Q4_K_M by default. For higher quality on machines with headroom: `ollama pull qwen3:8b-q8_0` (~8.9GB, noticeably better output at the cost of speed and memory).
- **Context window:** Current Ollama versions choose a default context length based on available VRAM/unified memory. On machines with less than 24 GiB available VRAM, Ollama defaults to ~4K context; with 24–48 GiB it defaults to ~32K; with 48 GiB+ it may default to ~256K. For predictable agent behavior, explicitly set `num_ctx` in the API `options` field, e.g. 4096 or 8192 to start.
---

## Part 4: Pulling the Model

After Ollama is installed and running:

```bash
# Pull the primary model (~5GB download)
ollama pull qwen3:8b

# Verify
ollama list

# Quick smoke test
ollama run qwen3:8b "Respond with only: hello"
```

Optional fallback: `ollama pull qwen2.5:7b`

### Testing Structured JSON Output

Run `13-test-structured-output.sh` to verify the model produces valid structured JSON and measure response times. Or test manually:

```bash
curl -s http://localhost:11434/api/chat \
  -d '{
    "model": "qwen3:8b",
    "messages": [
      {"role": "system", "content": "You are a network reconnaissance planning assistant."},
      {"role": "user", "content": "Plan the first recon step for subnet 192.168.56.0/24."}
    ],
    "format": {
      "type": "object",
      "properties": {
        "operation": {"type": "string"},
        "tool": {"type": "string"},
        "command_args": {"type": "string"},
        "reasoning": {"type": "string"}
      },
      "required": ["operation", "tool", "command_args", "reasoning"]
    },
    "stream": false
  }' | python3 -m json.tool
```

The `"format"` parameter with a JSON schema tells Ollama to constrain output
toward the schema using Ollama’s structured-output/constrained-output support. The agent still parses,
validates, retries, and guardrails responses because schema-shaped output can
still be semantically invalid.

This smoke test verifies API reachability and structured-output capability. It
does not prove that the model will make good reconnaissance decisions in a full
run. Runtime behavior should still be reviewed from the JSONL log and generated
report after an end-to-end agent run.

---

## Part 5: Verifying Connectivity from the Attacker VM

### Step 1: Check/Update the Inference Server IP

On your Mac:
```bash
ipconfig getifaddr en0
```

If the IP changed since initial setup, SSH into the attacker VM and update:
```bash
sudo bash infra/09-update-inference-ip.sh <NEW_IP>
```

### Step 2: Test Connectivity from Attacker VM

Run `14-verify-connectivity.sh` on the attacker VM (8-test suite covering connectivity, inference, and isolation), or test manually:

```bash
# Basic connectivity
curl -s --connect-timeout 5 http://<INFERENCE_IP>:11434
# Expected: "Ollama is running"

# Model list
curl -s http://<INFERENCE_IP>:11434/api/tags | python3 -m json.tool

# Test generation
curl -s http://<INFERENCE_IP>:11434/api/generate \
  -d '{"model": "qwen3:8b", "prompt": "Say hello in one word.", "stream": false}' \
  | python3 -m json.tool
```

### Step 3: Re-verify Isolation

From the attacker VM, confirm iptables lockdown is intact:

```bash
# Should FAIL:
curl -s --connect-timeout 5 http://8.8.8.8       # internet blocked
nmap -sn <LAN_SUBNET>/24                          # LAN scan blocked
curl -s --connect-timeout 5 http://<HOST_LAN_IP>:80  # non-inference ports blocked
```

---

## Part 6: Security Notes

1. **Ollama has no built-in authentication.** Acceptable in this isolated lab because the attacker VM's iptables restricts NAT access to only the inference server, the target has no route to it, and the inference server is on a private LAN.

2. **The inference server IP is DHCP-assigned.** Use `09-update-inference-ip.sh` when it changes. The architecture supports switching inference devices with a single script.

3. **Model quantization trade-off.** Q4_K_M (4-bit) quantization trades some output quality for memory efficiency. A dedicated machine with more memory could run Q8 or larger models (14B+).

---

## Appendix A: Re-apply Ollama Network Environment at Login

The Ollama macOS app reads `OLLAMA_HOST` from its launchd environment when it starts. Setting it once with `launchctl setenv` only lasts for the current login session. This LaunchAgent re-applies `launchctl setenv OLLAMA_HOST` at every user login so the Ollama app inherits it when you open it.

**This LaunchAgent does not start Ollama.** It only sets the environment variable. Open the Ollama app yourself (Login Item, Dock, Spotlight) — it will pick up the value on launch. If Ollama is set as a Login Item, quit and reopen it after login to avoid a startup race with the environment job.

> **Note:** A LaunchAgent runs at GUI login, not at system boot. If you need the Ollama API reachable before any user logs in (true headless server), use `brew install ollama` + `brew services start ollama` instead — that installs a LaunchDaemon that runs the `ollama` binary directly with the env var baked in.

### Install

```bash
mkdir -p ~/Library/LaunchAgents

cat > ~/Library/LaunchAgents/com.darkagents.ollama-env.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.darkagents.ollama-env</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/launchctl</string>
        <string>setenv</string>
        <string>OLLAMA_HOST</string>
        <string>0.0.0.0:11434</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

# Validate
plutil -lint ~/Library/LaunchAgents/com.darkagents.ollama-env.plist

# Load into the current GUI session (modern replacement for `launchctl load`)
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.darkagents.ollama-env.plist

# Run it now instead of waiting for next login
launchctl kickstart -k "gui/$(id -u)/com.darkagents.ollama-env"
```

Then quit and reopen Ollama (or re-enable it under **System Settings → General → Login Items**).

### Verify

```bash
# Should print: 0.0.0.0:11434
launchctl getenv OLLAMA_HOST

# Local check
curl http://127.0.0.1:11434/api/tags

# From another machine on the same LAN
curl http://MAC_LAN_IP:11434/api/tags
```

Per [Ollama's FAQ](https://docs.ollama.com/faq#how-can-i-expose-ollama-on-my-network), the server binds to `127.0.0.1:11434` by default and is exposed on the network by setting `OLLAMA_HOST`.

### Remove

```bash
launchctl bootout "gui/$(id -u)" ~/Library/LaunchAgents/com.darkagents.ollama-env.plist
rm ~/Library/LaunchAgents/com.darkagents.ollama-env.plist
launchctl unsetenv OLLAMA_HOST
```