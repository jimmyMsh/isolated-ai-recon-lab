# Current Limitations and Design Considerations

This document describes current boundaries of the reconnaissance agent
that are important for operators and future maintainers. It is not a
bug list. The items below are design trade-offs, observed model
behavior, or intentionally reserved configuration surfaces in the
current package.

See `docs/runtime-findings.md` for model-behavior observations from
test runs; specifics may vary with model, network, and target. This
document is the design-keyed complement to that observation log —
where the two overlap, runtime-findings holds the live-log detail and
this document holds the design posture and the forward-facing options.

## Authoritative vs Advisory Output

The authoritative evidence sources are:

- nmap XML files in `agent/output/`
- structured JSONL events in `agent/output/agent.log.jsonl`
- deterministic Markdown report sections built from parsed XML and JSONL
  events, including Discovered Hosts, MITRE mappings, Port Scan Findings,
  Service Enumeration Findings, Detailed Service Inventory, OS classifications,
  and Pipeline Execution Summary

The `Agent Analysis` section of the Markdown report is advisory. It is
generated from LLM interpretation calls and can contain incorrect or
unsupported free-text claims. A concrete example observed in a test run:
the model mislabeled a QEMU MAC prefix as VMware even though the nmap
output identified QEMU. Treat that section as operator commentary to
review, not as authoritative evidence.

## Pipeline Configuration Caveat

`pipeline_stages` is accepted by the YAML config and displayed in
dry-run and reports. The current orchestrator still executes the fixed
sequence:

1. `host_discovery`
2. `port_scan`
3. `service_enum`
4. `os_fingerprint`

Until the orchestrator is changed to validate and run the configured
sequence, `pipeline_stages` should be treated as descriptive. The safe
future design is to either make the field authoritative with
validation, or remove it from the runtime config surface.

## Deterministic Fallbacks Are Normal

Fallback commands are part of the safety model, not an exceptional
failure path. If the LLM produces invalid planning output, guardrails
reject it and the agent either retries or builds a deterministic
command from code-held state.

In test runs on `qwen3:8b`, `service_enum` has consistently executed
via fallback because the model omits the required `ports` field. The
fallback uses ports discovered by the prior `port_scan` stage and
executes a bounded `-sV` scan against those ports only. See
`docs/runtime-findings.md` §2 for the observation detail.

## Current Model Behavior

The current model is useful for proposing scan intent and producing
analysis text, but it should not be treated as a source of truth.
Observed behavior (see `docs/runtime-findings.md` for details)
includes:

- wrong-subnet planning targets such as `192.163.56.1`, caught by
  guardrails
- missing `ports` in `service_enum` planning, causing deterministic
  fallback
- aggressive scan requests that are not always executed because
  fallback pins safer defaults
- free-text analysis mistakes that do not affect parsed state

The package design intentionally prevents these issues from reaching
nmap or poisoning authoritative state.

## Reserved Configuration Surfaces

`allowed_tools` currently lists `nmap`, and the code only builds nmap
commands. It is not a plugin mechanism.

`StageConfig.think` is loaded from YAML, but current LLM requests
always send `think: false` and prompts include `/no_think`. Treat
`think` as reserved for a future thinking-mode implementation.

## Scan Coverage Trade-offs

`service_enum` uses nmap version detection without `--allports`. Nmap
may skip some printer-related ports, especially TCP 9100-9107, unless
`--allports` is used. This is acceptable for the current lab but
should be revisited if those ports matter.

`os_fingerprint` results can vary across runs because nmap OS
detection depends on observed network responses. The aggressive
mapping includes `--osscan-limit`, which can reduce OS detection if
nmap lacks both open and closed port evidence. Standard OS
fingerprinting has worked in observed runs.

## Future Design Options

The highest-value future improvements keep the LLM as the primary
planner and expand what the agent can autonomously do:

- Make `pipeline_stages` authoritative (load → validate → drive the
  orchestrator loop) rather than descriptive.
- Strengthen `service_enum` planning so the LLM reliably populates
  `ports`: few-shot examples in the prompt that pull from prior-stage
  state, and a tighter `format` schema that requires non-empty
  `ports` for `service_enum` (enforced by grammar-guided decoding).
- Surface fallback use and intensity overrides in the report
  (`requested_intensity` vs `executed_intensity` on `stage_complete`),
  so operators can see when code overrode a model-proposed plan
  without parsing JSONL.
- Evaluate a larger local model (Qwen3-14B or similar) after the
  prompt/schema work lands, to separate under-specified inputs from
  under-capable models.

## Extending the Agent

The "Future Design Options" above are tactical improvements to the
current pipeline. This section describes three strategic extension
paths that would change the agent's shape. Each is framed against the
module boundaries described in [`docs/architecture.md`](./architecture.md) so the
discussion is grounded in shipped code rather than speculation.

### Autonomous planning

Today the agent iterates a fixed four-stage pipeline defined as a
module-level tuple in `agent/src/agent/recon_agent.py`. The LLM
chooses parameters *inside* each stage; it does not choose *which*
stage runs next. A more autonomous mode would let the LLM propose the
next action from a larger menu — for example "scan this new host for
ports", "re-run service enumeration on host X with `--version-all`",
or "stop because the current findings are sufficient".

The pieces that would have to change:

- `_PIPELINE_STAGES` would become a runtime decision instead of a
  compile-time constant. `config.pipeline_stages` would become
  authoritative (see the tactical note above).
- The planning schema in
  [`agent/src/prompt_templates.py`](../agent/src/prompt_templates.py)
  and its consumers would need a `next_action` field.
- Stage-aware guardrails in
  [`agent/src/guardrails.py`](../agent/src/guardrails.py) would stay
  as-is, but a new validator for the menu of allowed next actions
  would sit in front of the stage-parameter validator.
- The orchestration loop in `ReconAgent.run()` would stop being a
  `for stage in _PIPELINE_STAGES` loop and become an outer planning
  loop bounded by `max_total_duration_seconds` and by an explicit
  "stop" action in the menu.

Pieces that would not need to change: `command_builder`, `tool_executor`,
`tool_parser`, `state`, `logger`, `report_generator`. Those are the
hardened core and are already agnostic to pipeline shape.

The scope of this change is bounded by the existing security model.
No autonomous-planning design should remove the subnet or attacker-IP
guardrails, move command construction out of code, or introduce
`shell=True`.

### Multi-tool support

`allowed_tools` in YAML is a list with a single entry, `"nmap"`, and
the codebase only builds nmap commands. Nothing in the architecture
forces that. A second tool — for example `masscan` for faster port
discovery, `nikto` for a very scoped web probe, or an `nmap` NSE
subset — could be added by extending three places:

- [`agent/src/command_builder.py`](../agent/src/command_builder.py) — a
  second intensity map and a second `build_<tool>()` / `build_fallback_<tool>()`
  pair per new tool.
- [`agent/src/tool_parser.py`](../agent/src/tool_parser.py) — per-tool
  parsers returning the same empty-sentinel contract so state updates
  stay safe when a run produces nothing.
- [`agent/src/tool_executor.py`](../agent/src/tool_executor.py) — a
  small routing layer that chooses the configured path for the tool
  (`nmap_path`, `masscan_path`, ...) and keeps the existing list-form
  subprocess invariant (`shell` never set to `True`), `-oX` /
  output-path traversal checks.

The LLM planning layer would gain a `tool` field in the schema; the
guardrail layer would gain a check that `tool` is in the configured
`allowed_tools`. Stage-aware invariants stay per-stage, not per-tool,
so `port_scan` still requires a single-host target whether it is
driven by nmap or masscan.

MITRE mappings in
[`agent/src/report_generator.py`](../agent/src/report_generator.py)
remain keyed by stage, not by tool; no new technique is needed for a
new tool running the same stage.

### Thinking-mode reasoning

Every current `/api/chat` request forces `think: false`, with
`/no_think` appended in prompt text as a second layer. `StageConfig`
carries a `think` field that is loaded from YAML and passed through
the config surface, but the transport layer in
[`agent/src/llm_client.py`](../agent/src/llm_client.py) currently
ignores it. `LLMResponse` likewise has a reserved `thinking: str |
None` slot that is always `None` today.

Turning thinking on is not a one-line change because the response
handling differs. An interim step is a dedicated `call_with_thinking()`
method on `LLMClient` that issues a two-phase request: a first call
without `format` to get a reasoning trace, then a second call with
the original `format` schema for the structured answer. The reasoning
trace is logged as a new `thinking_call` event on the cognitive
surface (or added to the existing `planning_call` / `interpretation_call`
payloads), and `LLMResponse.thinking` carries the trace.

The call sites worth evaluating first are `interpretation_call`
(where the value of the extra latency is highest — free-text analysis
benefits most from an explicit reasoning step) and the per-host
planning call for `port_scan` or `service_enum` on harder targets.
For simple `host_discovery` planning the single-pass structured call
is likely sufficient.

No guardrail, command-builder, executor, or parser change is implied
by thinking mode. The work is contained inside the LLM boundary.
