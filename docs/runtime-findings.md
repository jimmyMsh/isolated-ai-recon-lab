# Runtime Findings

Observations from running the agent against a Metasploitable 2 target
on the isolated lab network with Ollama serving `qwen3:8b`. Specifics
may vary with model version, network, and target.

Every substantive claim below is hedged to "in observed test runs" and
has been verified from `agent/output/agent.log.jsonl` for a run that
reproduces the behavior. The agent's core invariant — **state is
code-built, never LLM-built** — has held across every observed run.
The authoritative report tables are built from parsed nmap XML and
structured runtime events. The `Agent Analysis` section is different:
free-text LLM assessment, included for operator review, that can
contain mistakes.

Cross-references to specific log events use the common envelope fields
present on every event in `output/agent.log.jsonl`: `timestamp`,
`trace_id`, `span_id`, `parent_span_id`, `surface`, `event_type`,
`stage`, `stage_attempt`, and `host_target`. Fields such as `rule` and
`action_taken` are event-specific.

For design-reserved surfaces, trade-offs, and configured-but-not-
authoritative knobs, see `docs/current-limitations.md` — the
design-keyed complement to this observation log.

---

## 1. The LLM may produce wrong-subnet target IPs

**Finding.** On `qwen3:8b`, the planning LLM may produce target IPs
with one octet substituted — for example `192.163.56.1` or
`192.16.56.1` in place of `192.168.56.1`. These appear inside
`guardrail_violation` events, not `command_exec` events:

```json
{
  "event_type": "guardrail_violation",
  "rule": "target_outside_subnet",
  "detail": "Target 192.163.56.1 is outside allowed subnet 192.168.56.0/24",
  "action_taken": "retry_planning",
  "original_output": {
    "target": "192.163.56.1",
    "scan_intensity": "aggressive",
    "reasoning": "..."
  }
}
```

**Cause.** `Guardrails.validate_planning_response()` rejects any target
that falls outside the configured `target_subnet` or equals the attacker
IP. The orchestrator records the violation, appends the violation
detail as a user turn in the next planning prompt ("Previous attempt
rejected: ..."), and retries. After the configured retry budget is
exhausted, a deterministic fallback command is built from code-held
state.

**Meaning.** No hallucinated IP reached nmap in any observed run.
Every executed command is recorded as a `list[str]` in `command_exec`
events; the attacker IP appears only as the value of `--exclude` in
the `host_discovery` command. Grep the log and eyeball the targets to
confirm:

```bash
grep '"event_type": "command_exec"' output/agent.log.jsonl \
  | python3 -c "import sys, json
for line in sys.stdin:
    ev = json.loads(line)
    print(' '.join(ev.get('command', [])))"
```

Worry only if violations fire on every stage of every host — that
would indicate a model-quality regression.

---

## 2. `qwen3:8b` may consistently fail `service_enum` planning

**Finding.** In observed test runs, every attempted `service_enum`
host-stage exhausted planning because the model omitted `ports`, then
ran via fallback. Rejected planning payloads look like:

```json
{
  "target": "192.168.56.101",
  "scan_intensity": "aggressive",
  "reasoning": "The target has 29 open TCP ports, which is a high number...
                Aggressive intensity will enable version detection (-sV)
                and default NSE scripts (-sC)..."
}
```

The model explicitly acknowledges the open ports in `reasoning`, but
never populates the structured `ports` field. The guardrail rejects
the plan because `service_enum` requires a non-empty `ports` list —
running `-sV` without explicit ports would fall back to nmap's default
~1000-port probe set, which contradicts the pipeline's "scan what the
prior stage discovered" contract.

**Cause.** After three rejections, `planning._plan()` calls
`command_builder.build_fallback("service_enum", state, target_ip=host)`.
The fallback reads `state.get_open_ports_csv(host)` — the CSV of ports
parsed from the prior `port_scan` XML — and constructs:

```
nmap -sV --version-intensity 5 -p <ports-from-prior-stage> <host>
```

The resulting `command_exec` event carries
`"command_source": "fallback"`, which is the audit tag that confirms
the LLM did not author this command.

**Meaning.** On this model, the LLM contributes effectively nothing to
`service_enum` planning — the deterministic fallback is the primary
planner. Results are complete because the fallback uses ports from the
prior stage. Confirm from the log:

```bash
grep '"action_taken": "use_fallback"' output/agent.log.jsonl
grep '"command_source": "fallback"' output/agent.log.jsonl
```

**High-value future fix.** Strengthen `service_enum` planning so the
LLM reliably populates `ports`, keeping it as the primary planner:

- Add few-shot `service_enum` examples to the planning prompt that
  show `ports` populated from prior `port_scan` state.
- Tighten the `format` JSON schema to require a non-empty `ports`
  field for `service_enum`; Ollama's grammar-guided decoding then
  enforces the constraint server-side.

A larger local model (Qwen3-14B or similar) is worth trying after
these land, to separate "prompt/schema under-specified" from "model
under-capable."

---

## 3. Requested scan intensity may not be the executed scan intensity

**Finding.** In observed test runs, `service_enum` planning payloads
consistently requested `"scan_intensity": "aggressive"` (which would
map to `-sV -sC` with the full NSE script category). What actually
executed was the fallback:

```
nmap -sV --version-intensity 5 -p <ports> <host>
```

— a `standard` scan, pinned by `command_builder.build_fallback()`
regardless of what the LLM suggested. This asymmetry is not currently
surfaced in the Markdown report's Agent Analysis section; the raw
JSONL is the only place a reader can see that the model's requested
intensity was ignored.

**Cause.** Because `service_enum` plans are consistently rejected for
missing ports (see §2), the stage runs via the deterministic fallback.
The fallback pins `scan_intensity: "standard"` for `service_enum`
regardless of the LLM's request.

**Meaning.** The per-stage timeout has been comfortably met in every
observed completed run because the fallback's `standard` intensity is
lighter than the model's `aggressive` request. In test runs against a
29-port Metasploitable 2 target, total `service_enum` stage durations
have fallen in roughly the 146–160s range — comfortably under the
current `service_enum.timeout_seconds: 180` budget. If the model ever
started producing valid `aggressive` plans, the per-stage timeout may
need resizing.

**High-value future fix.** Let the LLM's `aggressive` intensity
actually execute instead of being silently overridden:

- With the §2 schema tightening, an `aggressive` plan carries a valid
  `ports` list and survives the guardrail.
- Emit `requested_intensity` and `executed_intensity` on
  `stage_complete` and surface both in the report, so overrides are
  visible without grepping JSONL.

Resize `service_enum.timeout_seconds` if valid `aggressive` plans
start to hit the current 180s budget.

---

## 4. `os_fingerprint` match confidence varies across runs

**Finding.** In observed test runs on the same host, two runs of
`os_fingerprint` may produce very different numbers of match rows.
One run of `-O --osscan-guess 192.168.56.1` produced ten candidate OS
matches ranked by confidence; a later run of the same command on the
same host produced a single high-confidence match.

**Cause.** `-O --osscan-guess` asks nmap to emit a ranked list of
candidate OS fingerprints. The ranking depends on the TCP/IP packet
responses nmap observes at probe time. Those responses vary with
network conditions, target kernel scheduling, and background load, so
the candidate set and its ranking are not fully deterministic across
runs.

**Meaning.** Not an agent-layer issue — nothing in the agent influences
this. The agent renders whatever nmap writes. If consistent OS
fingerprints become important, ensure nmap sees both open and closed
port evidence, and avoid `--osscan-limit` unless that evidence is
present.

---

## 5. Agent Analysis free text can misstate facts

**Finding.** In one observed report, nmap identified `52:54:00` MAC
addresses as QEMU virtual NICs in the command output. The
LLM-generated Agent Analysis described the same prefix as VMware.

**Cause.** `Agent Analysis` is built from `interpretation_call` events,
which are free-text LLM assessments. No guardrail enforces factual
alignment with the authoritative nmap output or parsed state.

**Meaning.** The mistake did not affect command execution, parsed
state, MITRE sections, discovered-host tables, port tables, service
inventory, or pipeline summaries — those are code-built from nmap XML
and structured JSONL events. `Agent Analysis` is advisory commentary
and should be independently checked against the authoritative tables
in the same report.

---

## 6. Empty or unreachable subnets skip cleanly

**Finding.** When the configured `target_subnet` contains no live
hosts, `host_discovery` reaches its per-stage timeout without finding
anything — nmap keeps probing the unreachable address space until the
budget is spent. The pipeline then emits a `post_attempt_skip` for
`host_discovery` and a `deterministic_skip` for every downstream
stage. The Markdown report's Executive Summary reads "Pipeline
completed with 4 failure/skip event(s)" rather than overstating
success.

Example event sequence (from a run against a subnet with no live
hosts):

```
planning_call   host_discovery
command_exec    host_discovery   return_code=-1   # nmap hit the stage timeout
error           host_discovery   error_type=nmap_timeout
stage_complete  host_discovery   success=False   skip_category=post_attempt_skip
stage_complete  port_scan        success=False   skip_category=deterministic_skip
stage_complete  service_enum     success=False   skip_category=deterministic_skip
stage_complete  os_fingerprint   success=False   skip_category=deterministic_skip
```

**Cause.** `skip_category` is emitted on `stage_complete` for every
skipped stage. Two values are currently emitted:

- `post_attempt_skip` — the stage ran, produced no usable output, and
  will not be retried (for example, `host_discovery` on a subnet with
  no responders).
- `deterministic_skip` — the stage was not attempted because an earlier
  stage's outcome makes it impossible to run (for example, `port_scan`
  has no hosts to target when `host_discovery` returned empty).

```bash
grep '"event_type": "stage_complete"' output/agent.log.jsonl \
  | python3 -c "import sys, json
for line in sys.stdin:
    ev = json.loads(line)
    if not ev.get('success'):
        print(ev.get('stage'), ev.get('host_target') or '-', ev.get('skip_category'))"
```

**Meaning.** Three outcomes that look similar at a glance — "the run
found nothing" — are distinguishable from the log without guesswork:

1. The subnet really was empty (`post_attempt_skip` on host_discovery
   plus `deterministic_skip` downstream).
2. The run was interrupted (an `error` event with
   `error_type="operator_interrupt"` is emitted on SIGINT; the partial
   report's Executive Summary names the interruption directly).
3. A genuine bug prevented the agent from scanning (other `error_type`
   values).

---

## Positive invariants worth stating

Across observed runs:

- Every nmap target was inside the configured subnet; the attacker IP
  was never a scan target.
- Every `stage_complete` with `success: true` corresponds to an XML
  file nmap actually wrote and a parser that actually produced
  findings.
- JSONL integrity has held under normal exit (trailing newline, final
  event is a complete `stage_complete`) and under operator-triggered
  SIGINT (every written line remains parseable; the final event is
  whatever completed before the interrupt).
- Report Findings tables (Discovered Hosts, Port Scan Findings,
  Service Enumeration Findings, Detailed Service Inventory, OS
  classifications) have always been code-built from parsed XML.
- Agent Analysis is advisory model commentary; useful context, not the
  authoritative evidence source.
