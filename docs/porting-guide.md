# Porting & Troubleshooting Guide — Dark Agents on the Attacker VM

This guide covers porting the reconnaissance agent onto the isolated
attacker VM after the `infra/` scripts have built the lab. It is the
attacker-VM-side companion to `docs/infra-setup-guide.md`, which covers
host-side lab bring-up. Every step is manual and has a confirmation
command you run before moving on.

---

## 0. Before you start

Assumes the attacker VM has been built by `infra/01`–`infra/08` and is
reachable via SSH over the NAT network:

```bash
# on the host
virsh list                              # expect: darkagents-attacker running
ssh op@192.168.122.10 uptime            # adjust user/IP for your VM
```

Also assumes an inference server reachable at the IP stored in
`/etc/darkagents/inference.conf`, a target VM on the isolated network,
and a git remote the attacker VM can reach during a brief
`infra/10-temp-open-firewall.sh open` window.

---

## 1. Port the agent with `git clone` during a temp-open window

All commands in this section run **on the attacker VM** over SSH.

### 1.1 Confirm your starting state

```bash
# on the attacker VM
whoami                                  # expect your operator user
which nmap                              # expect /usr/bin/nmap (from infra/03)
sudo iptables -L OUTPUT -v -n | head -10   # expect lockdown rules present
ls /etc/darkagents/inference.conf       # expect the file to exist
```

If any of those fail, re-run the relevant `infra/` script on the host
or the attacker VM before continuing. Do NOT continue until they pass.

### 1.2 Temporarily open the NAT lockdown

You need outbound TCP to your git remote for the clone. That is
blocked by `infra/06`. Open it:

```bash
sudo bash /path/to/infra/10-temp-open-firewall.sh open
# confirm
curl -sI https://github.com | head -n 1    # expect: HTTP/2 200 or similar
```

**Stop here if that curl fails** — either the NAT NIC is misconfigured
or you don't have `infra/10` on the VM yet. Do not proceed until it
succeeds.

> You need `infra/10` present on the VM to close the firewall again. If
> it isn't there because this is a fresh VM, scp just that one script
> from the host first:
>
> ```bash
> # on the host
> scp infra/10-temp-open-firewall.sh op@192.168.122.10:~/
> scp infra/06-setup-iptables.sh op@192.168.122.10:~/   # needed by 10-close
> ```

### 1.3 Clone the repo

Pick a working directory. The guide uses `~/darkagents/` throughout;
adjust to taste but stay consistent.

```bash
cd ~
git clone <your-git-remote-url> darkagents
cd darkagents
git status                              # expect: clean working tree
git log --oneline -5                    # sanity-check you got the right branch
```

A fresh clone contains `agent/`, `infra/`, `docs/`,
`scripts/tmux-monitor.sh`, and the standard top-level files.

### 1.4 Confirm Python and uv are present

`infra/03-attacker-post-install.sh` installs Python development packages
(`python3-pip`, `python3-venv`, `python3-dev`, `build-essential`) and
`uv` (via the official astral.sh installer into `~/.local/bin`). Confirm
both are reachable:

```bash
python3 --version                       # expect 3.10 or newer
command -v uv                           # expect /home/<user>/.local/bin/uv
uv --version
```

If `uv` is missing — for example on a VM built from an older snapshot
that predates the uv-install line in `infra/03` — install it manually
during the temp-open window:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.local/bin/env                 # or start a new SSH session
command -v uv                           # confirm
```

Do NOT run the install with `sudo` — uv is a per-user tool and needs to
land in the operator's `~/.local/bin`, not `/root/.local/bin`.

### 1.5 Build the agent's venv

```bash
cd ~/darkagents/agent
uv sync --extra dev                     # creates .venv from uv.lock
PYTHONPATH=src uv run python -c "import agent, config; print('import OK')"
```

Expect `import OK` on stdout. `PYTHONPATH=src` is required because
`agent/` and `config.py` live under `agent/src/`; plain `uv run python
-c` does not add `src/` to `sys.path`. `run.py` inserts it itself at
boot, so runtime invocations do not need the prefix — only one-off
`python -c` smoke checks do. If `uv sync` reaches out for packages not
already cached, that's why the firewall is temporarily open.

### 1.6 Close the NAT lockdown

Now that the clone and `uv sync` are done, re-lock:

```bash
sudo bash ~/darkagents/infra/10-temp-open-firewall.sh close
# confirm
curl -sI --max-time 3 https://github.com     # expect: timeout / no response
```

The lockdown is back on. From here, only inference traffic to
`$INFERENCE_IP:11434` and isolated-network traffic to the target are
allowed.

### 1.7 Confirm Ollama is reachable through the lockdown

```bash
source /etc/darkagents/inference.conf
echo "INFERENCE_IP=$INFERENCE_IP"
curl -sS "http://${INFERENCE_IP}:11434/api/tags" | head -c 400
```

Expect a JSON payload listing available models. If this times out,
either the inference server isn't running (`infra/12` on the Mac) or
DHCP changed its IP (run `sudo bash infra/09-update-inference-ip.sh
<NEW_IP>` on the attacker VM).

---

## 2. Create `agent/config/remote.yaml` (don't touch `default.yaml`)

`default.yaml` is the shipped baseline and should stay pristine on
every checkout. Per-host values live in a separate file:
`agent/config/remote.yaml`. You will pass `--config config/remote.yaml`
at runtime.

### 2.1 Add `remote.yaml` to `.git/info/exclude`

This keeps you from ever accidentally `git add`-ing it:

```bash
cd ~/darkagents
echo "agent/config/remote.yaml" >> .git/info/exclude
# confirm
grep remote.yaml .git/info/exclude
git check-ignore -v agent/config/remote.yaml   # expect: excluded
```

### 2.2 Copy `default.yaml` to `remote.yaml` and edit the per-host fields

```bash
cp agent/config/default.yaml agent/config/remote.yaml
```

Open `agent/config/remote.yaml` and review each field below. The shipped
defaults may be fine — but confirm, don't assume.

| Field | Check |
|---|---|
| `ollama_url` | Set to the inference server's actual IP:port. Must match the NAT lockdown exception. Verify with `cat /etc/darkagents/inference.conf` on the VM, then **substitute the values manually** into a literal URL such as `ollama_url: "http://192.168.122.1:11434"` — `AgentConfig.from_yaml()` does not expand `${...}` env vars in YAML; only the `OLLAMA_URL` env var is honored at load time (see §2.3 below). |
| `model` | Must be pulled on the inference server. Verify (after `source /etc/darkagents/inference.conf` from §1.7, or after the §2.3 export): `curl -sS "http://${INFERENCE_IP}:11434/api/tags" \| grep -o '"name":"[^"]*"'`. |
| `target_subnet` | `192.168.56.0/24` by default; only change if `infra/01` was run with different CIDR. Confirm: `ip -br addr show \| grep 192.168.56`. |
| `attacker_ip` | `192.168.56.10` by default. Confirm: `ip -4 addr show \| grep 192.168.56`. |
| `nmap_path` | `/usr/bin/nmap` on Ubuntu 24.04. Confirm: `which nmap`. |
| `output_dir` | `./output` (resolves relative to CWD, which the first-run checklist pins as `agent/`). Confirm: `ls agent/output/` is writable. |
| `max_total_duration_seconds` | `600`. Hard ceiling across all stages. Tune up if the target VM is slow; tune down if you want the agent to fail fast. |

### 2.3 Optional: `OLLAMA_URL` env override

If the inference IP changes mid-session and you don't want to edit
`remote.yaml` each time, export `OLLAMA_URL`:

```bash
export OLLAMA_URL="http://${INFERENCE_IP}:11434"
```

The loader prefers `OLLAMA_URL` over the YAML value. Both dry-run and
real run pick it up.

### 2.4 Validate the config with a dry-run (no root, no scans)

```bash
cd ~/darkagents/agent
uv run python run.py --config config/remote.yaml --dry-run
echo "exit=$?"                          # expect 0
```

Expect stdout to list `target_subnet`, `attacker_ip`, `ollama_url`,
`model`, `pipeline_stages`, `max_total_duration_seconds`, `output_dir`,
`log_file`, and `nmap_path`. If any value is wrong, fix `remote.yaml`
and re-run this step. The dry-run never touches nmap, Ollama, or the
network — it is the cheapest way to catch config drift.

---

## 3. First real run

Only after the dry-run is clean.

### 3.1 Confirm the root gate fires when expected

```bash
cd ~/darkagents/agent
uv run python run.py --config config/remote.yaml
echo "exit=$?"                          # expect 1
```

Expect a stderr line about root and exit code `1`. No files should
land in `./output/`:

```bash
ls -la output/                          # expect only .gitkeep
```

If the agent DID create log/XML files under `./output/` on a non-root
run, stop and file an issue — the root gate is broken.

### 3.2 Run with sudo against the isolated subnet

**PATH gotcha.** `uv` was installed into `~/.local/bin` in §1.4, which
is NOT on Ubuntu's default `sudo secure_path`. A bare `sudo uv run …`
will exit with `sudo: uv: command not found`. Expand the path *before*
sudo consumes the argv so sudo sees the absolute binary directly:

```bash
cd ~/darkagents/agent
sudo "$(command -v uv)" run python run.py --config config/remote.yaml
echo "exit=$?"                          # expect 0 (or 130 if you ^C'd)
```

If you want to avoid re-typing `"$(command -v uv)"` every session,
either drop an alias (`alias sudouv='sudo "$(command -v uv)"'`) or add
`~/.local/bin` to sudo's `secure_path` via `sudo visudo` — the alias is
the less-invasive choice. Confirm first that the pattern works:

```bash
sudo "$(command -v uv)" --version
```

If that prints a uv version, you are set. If it still says "command
not found", re-check §1.4 and make sure `command -v uv` prints a path
in your own shell.

On completion, the last line of stdout is the path to the Markdown
report. With the shipped `output_dir: "./output"` it is relative to
the agent's CWD (i.e. `output/recon_report_<trace_id>.md` when invoked
from `~/darkagents/agent`); set `output_dir` to an absolute path in
`remote.yaml` if you want the printed path to be absolute. Confirm
artifacts landed:

```bash
ls -la output/
# expect: agent.log.jsonl, one or more *.xml per stage, recon_report_<trace_id>.md
```

### 3.3 Confirm subnet bounding held

Grep the JSONL log for every nmap invocation and confirm every target
is inside `192.168.56.0/24` (or whatever your `target_subnet` is).
`attacker_ip` must NEVER appear as a scan target.

```bash
grep '"event_type": "command_exec"' output/agent.log.jsonl \
  | python3 -c "import sys, json
for line in sys.stdin:
    ev = json.loads(line)
    cmd = ev.get('command', [])
    print(' '.join(cmd))" \
  | head -20
```

---

## 4. Troubleshooting matrix

Exit codes from `agent/run.py`: `0` success or dry-run (also: any
unhandled exception inside the stage loop is **absorbed** into a
partial report and the run still exits `0` — see `docs/architecture.md`
§8); `1` root missing, or a fatal failure during `ReconAgent`
construction or report generation that escapes `agent.run()`; `2`
config error (missing required field, YAML parse error, file not
found); `130` operator SIGINT.

| Symptom | Likely cause | Confirmation command | Fix |
|---|---|---|---|
| `run.py` exits `2`, stderr: `FileNotFoundError` | `--config` path wrong for the CWD. | `pwd; ls -la config/remote.yaml` | Pass an absolute path, or `cd agent` first. |
| Exit `2`, stderr: `ValueError: Missing required config fields: ...` or YAML parse error | `remote.yaml` is missing one of the five code-required fields, or the YAML is syntactically broken. | `diff agent/config/default.yaml agent/config/remote.yaml` | Code-required fields (raise on missing or null): `ollama_url`, `model`, `target_subnet`, `attacker_ip`, `nmap_path`. The other top-level keys in `default.yaml` (`allowed_tools`, `pipeline_stages`, `default_stage`, `stage_configs`, `interpretation`, `output_dir`, `max_total_duration_seconds`, `num_ctx`) are optional and use defaults from `agent/src/config.py` if omitted, but copying `default.yaml`'s structure verbatim and editing values is the lowest-risk approach. |
| Exit `1`, stderr: "root privileges required" | Running without sudo. | `id -u` (expect 0 under sudo) | Re-run with `sudo "$(command -v uv)" run python run.py …`. The `$(command -v uv)` expansion sidesteps Ubuntu's `sudo secure_path` which does NOT include `~/.local/bin`. |
| `sudo: uv: command not found` when invoking the run | Bare `sudo uv run …` hit Ubuntu's `sudo secure_path`, which does not include `~/.local/bin`. | `sudo "$(command -v uv)" --version` (expect a version line) | Always invoke as `sudo "$(command -v uv)" run python run.py …`, OR add `~/.local/bin` to `secure_path` via `sudo visudo`. The `$(…)` expansion happens in the calling shell, so sudo receives an absolute path and doesn't look it up. |
| JSONL `error_type: "permission_error"` on every host, `stage_complete` shows `post_attempt_skip` for them, run still exits `0` with a partial report | nmap lacked raw-socket privileges (the executor detects `requires root privileges` / `operation not permitted` / `permission denied` in nmap stderr and skips the unit instead of escalating). | `grep '"error_type": "permission_error"' output/agent.log.jsonl; sudo nmap -sn 192.168.56.101` | Re-run with `sudo "$(command -v uv)" run python run.py …`; verify `which nmap` matches `nmap_path`; check the binary has the right caps (`getcap $(which nmap)` should show `cap_net_raw,cap_net_admin,cap_net_bind_service+eip` on systems that use capabilities instead of root). If `./output` is not writable by the EUID, the executor's `mkdir` will raise an unhandled exception, which `ReconAgent.run()` absorbs into a `state.errors` entry with `reason: "unexpected_exception"` and the run still exits `0` — fix by `sudo chown` of the dir, or set `output_dir` to a writable absolute path. |
| `which nmap` returns empty | `infra/03` not run, or lockdown hit before install finished. | `apt list --installed 2>/dev/null \| grep nmap` | `sudo bash infra/10-temp-open-firewall.sh open; sudo apt install -y nmap; sudo bash infra/10-temp-open-firewall.sh close`. |
| `curl $OLLAMA_URL/api/tags` → Connection refused / timeout | Ollama down, or iptables dropping the NAT NIC. | `sudo iptables -L OUTPUT -v -n \| grep 11434` | On the Mac: `infra/12-start-ollama-session.sh`. On the VM: confirm `/etc/darkagents/inference.conf` matches; re-point with `sudo bash infra/09-update-inference-ip.sh <NEW_IP>`. |
| Ollama reachable, but JSONL shows `model not found` | Configured `model` not pulled on the inference server. | `curl -sS $OLLAMA_URL/api/tags \| grep qwen3` | On the inference server: `ollama pull qwen3:8b` (or whatever your `model` field says). |
| All stages report "timed out" in JSONL | `stage_configs.<stage>.timeout_seconds` too low, OR nmap stuck on unreachable hosts. | `grep '"error_type": "nmap_timeout"' output/agent.log.jsonl` (or `grep '"return_code": -1'` to see the executor-side sentinel). The `command_exec` event does not emit a `timed_out` boolean field; use one of these instead. | Increase the stage's `timeout_seconds`, or narrow `target_subnet` to hosts that actually exist. `max_total_duration_seconds` is a hard ceiling across all stages. |
| Report exists but a stage has no per-stage XML | Stage was skipped, timed out, or parser saw no matches. Empty parser output is a sentinel — not distinguishable from "no findings" without log context. | `grep '"stage_complete"' output/agent.log.jsonl` | Inspect the corresponding `command_exec` and `error` events. `return_code: -1` + an `error_type: "nmap_timeout"` event means the subprocess timed out; `return_code: 0` with no XML means nmap ran but wrote nothing; a `skip_category` on the `stage_complete` event (`deterministic_skip` / `post_attempt_skip`) tells you whether the stage was ever attempted. There is no `timed_out` field on `command_exec` — use the pair above instead. |
| `^C` during a run | Operator SIGINT. | `echo $?` → `130` | Expected. `ReconAgent.run()` closes the logger and writes a partial Markdown report before exiting. Check `ls -t output/*.md \| head -1`. |
| Guardrail violation in JSONL ("target outside subnet") | LLM hallucinated an IP; guardrail blocked it. | `grep '"guardrail_violation"' output/agent.log.jsonl` | Expected one-off; the agent retries with reinforced instructions and falls back to a deterministic command. Worry only if every stage trips it. |
| `./output/` empty after apparent success | CLI was invoked from a CWD other than `agent/`. | `pwd` at time of invocation | `cd agent` first, or set `output_dir:` to an absolute path in `remote.yaml`. |
| JSONL shows `guardrail_violation` with `rule: target_outside_subnet` and an IP like `192.163.56.x` or `192.16.56.x` | Model hallucinated an IP in the planning payload. The guardrail caught it before dispatch; the agent retried and recovered via fallback. | `grep '"target_outside_subnet"' output/agent.log.jsonl` | Expected behavior on `qwen3:8b`; see `docs/runtime-findings.md` for model-behavior context. Worry only if the violation fires on every stage of every host. |
| JSONL shows repeated `guardrail_violation` with `rule: missing_ports_for_stage` on every `service_enum` attempt, then `action_taken: use_fallback` | Model consistently omits the `ports` field in `service_enum` planning; the fallback is the primary planner for this stage on this model. | `grep '"missing_ports_for_stage"' output/agent.log.jsonl` | Expected behavior on `qwen3:8b`; see `docs/runtime-findings.md` for model-behavior context. The fallback uses the ports collected in the prior `port_scan` stage, so results are complete. |

If a failure is not in this table, capture: exact command, exit code,
last 20 lines of `output/agent.log.jsonl`, and stderr tail.

---

## 5. Safety reminder (non-negotiable)

These are enforced by code (`guardrails.py`, `command_builder.py`),
but they are your responsibility first:

- **Never scan outside `target_subnet`.** Every nmap command is
  checked against it; the agent refuses to run scans that fall
  outside. Do not widen the subnet to "test reachability" — use
  `ping` or `curl` from the attacker shell instead.
- **The attacker IP is excluded from every target list.** Do not
  remove that filter.
- **No real scans until scope is confirmed.** Use `--dry-run` first.
  After a run, grep the JSONL log's `command_exec` events and verify
  every target was inside the subnet.
- **`shell=True` is never used.** If you extend the agent, preserve
  `list[str]` subprocess invocation. It is the primary defense against
  command injection from LLM output.
