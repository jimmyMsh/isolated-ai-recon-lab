"""Tests for ReconAgent — pipeline orchestrator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent import ReconAgent
from config import AgentConfig, StageConfig
from guardrails import Guardrails
from llm_client import LLMResponse
from logger import AgentLogger
from tool_executor import ExecutionResult

from .fakes import FakeLLMClient, FakeToolExecutor

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _stage_configs_default() -> dict[str, StageConfig]:
    return {
        "host_discovery": StageConfig(timeout_seconds=120),
        "port_scan": StageConfig(timeout_seconds=120),
        "service_enum": StageConfig(timeout_seconds=120),
        "os_fingerprint": StageConfig(timeout_seconds=120),
    }


@pytest.fixture()
def config(tmp_path):
    output = tmp_path / "output"
    return AgentConfig(
        ollama_url="http://localhost:11434",
        model="qwen3:8b",
        target_subnet="192.168.56.0/24",
        attacker_ip="192.168.56.10",
        nmap_path="/usr/bin/nmap",
        output_dir=str(output),
        log_file=str(output / "agent.log.jsonl"),
        stage_configs=_stage_configs_default(),
    )


def _planning_response() -> LLMResponse:
    parsed = {
        "target": "192.168.56.0/24",
        "scan_intensity": "standard",
        "reasoning": "Full-subnet discovery on isolated LAN.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _interpretation_response() -> LLMResponse:
    parsed = {
        "findings": [
            {
                "description": "192.168.56.101 is alive",
                "severity": "informational",
                "mitre_technique": "T1595.001",
            }
        ],
        "summary": "Discovered 2 hosts on the subnet.",
        "recommendations": "Proceed with port scanning.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _exec_result_ok(command: list[str]) -> ExecutionResult:
    return ExecutionResult(
        command=command,
        return_code=0,
        stdout="",
        stderr="",
        xml_output_path=None,  # overwritten by FakeToolExecutor
        duration_seconds=0.1,
        timed_out=False,
    )


def _read_log_events(log_path: str) -> list[dict]:
    path = Path(log_path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# -- Phase 5.1: host_discovery in isolation -----------------------------------


@pytest.fixture()
def host_discovery_run(config):
    """Exercise only the host_discovery stage, without per-host iteration.

    Calls ``agent._run_host_discovery()`` directly so Phase 5.1 assertions stay
    scoped to the single-stage pipeline. Per-host stages and report generation
    are not driven from this fixture — those belong to the Phase 5.2
    full-pipeline fixture.
    """
    llm = FakeLLMClient([_planning_response(), _interpretation_response()])
    exec_dummy_cmd = ["/usr/bin/nmap", "-sn", "192.168.56.0/24"]
    tool = FakeToolExecutor(
        results=[(FIXTURES_DIR / "host_discovery.xml", _exec_result_ok(exec_dummy_cmd))],
        output_dir=Path(config.output_dir),
    )
    logger = AgentLogger(config)
    trace_id = logger.trace_id

    agent = ReconAgent(config, llm_client=llm, tool_executor=tool, logger=logger)
    agent._run_host_discovery()
    logger.close()

    events = [e for e in _read_log_events(config.log_file) if e.get("trace_id") == trace_id]
    return {
        "agent": agent,
        "llm": llm,
        "tool": tool,
        "trace_id": trace_id,
        "events": events,
        "state": agent._state,
    }


class TestHostDiscoveryHappyPath:
    """Phase 5.1: single-stage end-to-end for host_discovery."""

    def test_state_contains_discovered_hosts(self, host_discovery_run):
        """AgentState owns durable recon findings.

        After host_discovery, state.discovered_hosts reflects the two up hosts
        from the fixture (attacker IP 192.168.56.10 is excluded).
        """
        state = host_discovery_run["state"]
        assert set(state.discovered_hosts.keys()) == {"192.168.56.1", "192.168.56.101"}

    def test_stages_completed_has_only_host_discovery(self, host_discovery_run):
        """stages_completed is a progress marker — only host_discovery in 5.1 scope."""
        state = host_discovery_run["state"]
        assert state.stages_completed == ["host_discovery"]

    def test_current_stage_set_to_host_discovery_during_run(self, host_discovery_run):
        """Current stage is set before prompt construction; the first planning_call
        observes it.
        """
        events = host_discovery_run["events"]
        planning = next(e for e in events if e["event_type"] == "planning_call")
        assert planning["stage"] == "host_discovery"
        state_update = next(e for e in events if e["event_type"] == "state_update")
        assert state_update["state_snapshot"]["current_stage"] == "host_discovery"

    def test_log_contains_all_pipeline_events(self, host_discovery_run):
        """host_discovery emits planning_call, command_exec, state_update,
        interpretation_call, stage_complete in order.
        """
        events = host_discovery_run["events"]
        types = [e["event_type"] for e in events]
        assert types == [
            "planning_call",
            "command_exec",
            "state_update",
            "interpretation_call",
            "stage_complete",
        ]

    def test_span_parent_chain_matches_precedence(self, host_discovery_run):
        """Canonical causal chain for a host-stage:

        planning → command_exec → state_update → interpretation_call → stage_complete.
        """
        events = host_discovery_run["events"]
        by_type = {e["event_type"]: e for e in events}

        assert by_type["planning_call"]["parent_span_id"] is None
        assert by_type["command_exec"]["parent_span_id"] == by_type["planning_call"]["span_id"]
        assert by_type["state_update"]["parent_span_id"] == by_type["command_exec"]["span_id"]
        assert (
            by_type["interpretation_call"]["parent_span_id"] == by_type["state_update"]["span_id"]
        )
        assert (
            by_type["stage_complete"]["parent_span_id"] == by_type["interpretation_call"]["span_id"]
        )

    def test_state_update_uses_sparse_delta_and_snapshot(self, host_discovery_run):
        """state_update emits update_source=tool_parser, a sparse state_delta,
        and a state_snapshot sourced from to_log_snapshot().
        """
        events = host_discovery_run["events"]
        state_update = next(e for e in events if e["event_type"] == "state_update")
        assert state_update["update_source"] == "tool_parser"
        delta = state_update["state_delta"]
        assert set(delta.keys()) == {"hosts_added"}
        assert set(delta["hosts_added"]) == {"192.168.56.1", "192.168.56.101"}
        snapshot = state_update["state_snapshot"]
        assert snapshot["target_subnet"] == "192.168.56.0/24"
        assert snapshot["attacker_ip"] == "192.168.56.10"
        assert "errors" in snapshot
        assert set(snapshot["discovered_hosts"].keys()) == {
            "192.168.56.1",
            "192.168.56.101",
        }

    def test_command_exec_has_command_source_llm(self, host_discovery_run):
        """Happy-path command_exec includes command_source="llm"."""
        events = host_discovery_run["events"]
        cmd_exec = next(e for e in events if e["event_type"] == "command_exec")
        assert cmd_exec["command_source"] == "llm"

    def test_stage_complete_counters(self, host_discovery_run):
        """Happy path: retries=0, llm_calls=2 (planning + interpretation);
        mitre_technique comes from STAGE_TO_MITRE.
        """
        events = host_discovery_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is True
        assert stage_complete["llm_calls"] == 2
        assert stage_complete["retries"] == 0
        assert stage_complete["mitre_technique"] == "T1595.001"

    def test_interpretation_not_stored_in_state(self, host_discovery_run):
        """Design principle: state is code-built, never LLM-built.

        The LLM's interpretation summary and recommendations must not leak
        into AgentState — state is populated exclusively by tool_parser.
        """
        state = host_discovery_run["state"]
        snapshot_json = json.dumps(state.to_log_snapshot())
        assert "Discovered 2 hosts on the subnet." not in snapshot_json
        assert "Proceed with port scanning." not in snapshot_json

    def test_shared_guardrails_injected_into_executor(self, config):
        """One shared Guardrails instance is injected into ToolExecutor."""
        agent = ReconAgent(config)
        assert isinstance(agent._guardrails, Guardrails)
        assert agent._executor._guardrails is agent._guardrails

    def test_planning_call_uses_host_discovery_stage_config(self, host_discovery_run):
        """The LLM planning call is made with the host_discovery stage config."""
        llm = host_discovery_run["llm"]
        planning_record = llm.history[0]
        assert planning_record.stage_config is not None
        assert planning_record.stage_config.temperature == 0.0

    def test_host_discovery_executed_once(self, host_discovery_run):
        """host_discovery runs exactly one nmap invocation (subnet-level scan)."""
        tool = host_discovery_run["tool"]
        assert len(tool.history) == 1
        assert "-sn" in tool.history[0].args


# -- Phase 5.2: multi-host orchestration --------------------------------------

EXPECTED_HOSTS = ["192.168.56.1", "192.168.56.101"]


def _port_scan_plan(host: str) -> LLMResponse:
    parsed = {
        "target": host,
        "scan_intensity": "standard",
        "reasoning": f"Full port scan for {host}.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _service_enum_plan(host: str, ports: str) -> LLMResponse:
    parsed = {
        "target": host,
        "ports": ports,
        "scan_intensity": "standard",
        "reasoning": f"Version detection on known-open ports of {host}.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _os_fingerprint_plan(host: str) -> LLMResponse:
    parsed = {
        "target": host,
        "scan_intensity": "standard",
        "reasoning": f"OS fingerprint for {host}.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _interpretation_generic(summary: str) -> LLMResponse:
    parsed = {
        "findings": [],
        "summary": summary,
        "recommendations": "Continue pipeline.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _four_stage_llm_queue() -> list[LLMResponse]:
    """Queue of LLM responses for a full four-stage happy-path run.

    host_discovery contributes 2 calls (planning + interpretation);
    per-host stages iterate hosts in sorted order with 2 calls each.
    Total: 2 + (3 stages * 2 hosts * 2 calls) = 14.
    """
    queue: list[LLMResponse] = [
        _planning_response(),
        _interpretation_response(),
    ]
    known_ports_csv = "21,22,80,445"
    for host in EXPECTED_HOSTS:
        queue.extend(
            [
                _port_scan_plan(host),
                _interpretation_generic(f"Ports for {host}."),
            ]
        )
    for host in EXPECTED_HOSTS:
        queue.extend(
            [
                _service_enum_plan(host, known_ports_csv),
                _interpretation_generic(f"Services for {host}."),
            ]
        )
    for host in EXPECTED_HOSTS:
        queue.extend(
            [
                _os_fingerprint_plan(host),
                _interpretation_generic(f"OS for {host}."),
            ]
        )
    return queue


def _four_stage_exec_queue() -> list:
    """Queue of executor results for a full four-stage happy-path run.

    host_discovery once, then per-host port_scan, service_enum, os_fingerprint
    in that order. The same single-host fixture is reused for every per-host
    call — state.update_from_* scopes results to the target_ip passed in,
    so the XML content lines up with the expected per-host state delta.
    """
    exec_queue: list = [
        (FIXTURES_DIR / "host_discovery.xml", _exec_result_ok(["/usr/bin/nmap", "-sn"])),
    ]
    for _ in EXPECTED_HOSTS:
        exec_queue.append(
            (FIXTURES_DIR / "port_scan.xml", _exec_result_ok(["/usr/bin/nmap", "-sS"]))
        )
    for _ in EXPECTED_HOSTS:
        exec_queue.append(
            (FIXTURES_DIR / "service_enum.xml", _exec_result_ok(["/usr/bin/nmap", "-sV"]))
        )
    for _ in EXPECTED_HOSTS:
        exec_queue.append(
            (FIXTURES_DIR / "os_fingerprint.xml", _exec_result_ok(["/usr/bin/nmap", "-O"]))
        )
    return exec_queue


@pytest.fixture()
def multi_host_run(config):
    """Run ReconAgent through all four stages across two discovered hosts."""
    llm = FakeLLMClient(_four_stage_llm_queue())
    tool = FakeToolExecutor(
        results=_four_stage_exec_queue(),
        output_dir=Path(config.output_dir),
    )
    logger = AgentLogger(config)
    trace_id = logger.trace_id

    agent = ReconAgent(config, llm_client=llm, tool_executor=tool, logger=logger)
    report_path = agent.run()

    events = [e for e in _read_log_events(config.log_file) if e.get("trace_id") == trace_id]
    return {
        "agent": agent,
        "llm": llm,
        "tool": tool,
        "trace_id": trace_id,
        "report_path": report_path,
        "events": events,
        "state": agent._state,
    }


class TestMultiHostOrchestration:
    """Per-host iteration across port_scan, service_enum, os_fingerprint."""

    def test_run_returns_existing_report_path(self, multi_host_run):
        """run() returns a path to a generated report file."""
        report_path = multi_host_run["report_path"]
        assert isinstance(report_path, str)
        assert Path(report_path).exists()

    def test_report_references_trace_id(self, multi_host_run):
        """Report generation uses the logger's trace_id explicitly."""
        trace_id = multi_host_run["trace_id"]
        report_path = multi_host_run["report_path"]
        assert trace_id in Path(report_path).name

    def test_logger_closed_after_run(self, multi_host_run):
        """logger.close() is called in run()'s finally block."""
        agent = multi_host_run["agent"]
        assert agent._logger._closed is True

    def test_stages_completed_has_exactly_one_entry_per_stage(self, multi_host_run):
        """stages_completed is a progress marker — exactly one entry per stage."""
        state = multi_host_run["state"]
        assert state.stages_completed == [
            "host_discovery",
            "port_scan",
            "service_enum",
            "os_fingerprint",
        ]

    def test_stage_complete_emitted_per_host_for_per_host_stages(self, multi_host_run):
        """Per-host stages emit one stage_complete per host; host_discovery emits one total."""
        events = multi_host_run["events"]
        by_stage: dict[str, list[dict]] = {}
        for event in events:
            if event["event_type"] == "stage_complete":
                by_stage.setdefault(event["stage"], []).append(event)
        assert len(by_stage["host_discovery"]) == 1
        assert len(by_stage["port_scan"]) == 2
        assert len(by_stage["service_enum"]) == 2
        assert len(by_stage["os_fingerprint"]) == 2

    def test_per_host_events_carry_host_target(self, multi_host_run):
        """Every log event emitted during a per-host stage carries host_target=current host."""
        events = multi_host_run["events"]
        per_host_stages = {"port_scan", "service_enum", "os_fingerprint"}
        for event in events:
            if event["stage"] in per_host_stages:
                assert event["host_target"] in EXPECTED_HOSTS, (
                    f"{event['event_type']} for {event['stage']} missing host_target"
                )

    def test_hosts_iterated_in_sorted_order(self, multi_host_run):
        """Hosts iterated in sorted order across every per-host stage for stable logs."""
        events = multi_host_run["events"]
        for stage in ("port_scan", "service_enum", "os_fingerprint"):
            stage_completes = [
                e for e in events if e["event_type"] == "stage_complete" and e["stage"] == stage
            ]
            hosts_in_order = [e["host_target"] for e in stage_completes]
            assert hosts_in_order == sorted(EXPECTED_HOSTS)

    def test_current_target_lifecycle(self, multi_host_run):
        """Shared Semantic #9: current_target lifecycle across the pipeline.

        - host_discovery never touches current_target (stays None).
        - Within a per-host stage loop, each state_update's snapshot shows
          current_target == that event's host_target.
        - Hosts iterate host1 → host2 directly; no intermediate None between
          hosts inside a stage loop.
        """
        events = multi_host_run["events"]
        state_updates = [e for e in events if e["event_type"] == "state_update"]

        hd = next(e for e in state_updates if e["stage"] == "host_discovery")
        assert hd["state_snapshot"]["current_target"] is None

        for stage in ("port_scan", "service_enum", "os_fingerprint"):
            stage_updates = [e for e in state_updates if e["stage"] == stage]
            observed = [e["state_snapshot"]["current_target"] for e in stage_updates]
            assert observed == sorted(EXPECTED_HOSTS), (
                f"{stage}: current_target did not track host iteration cleanly"
            )
            for event in stage_updates:
                assert event["state_snapshot"]["current_target"] == event["host_target"]

    def test_current_target_and_stage_reset_at_report_time(self, multi_host_run):
        """At report-generation time: current_target is None, current_stage == 'report'."""
        state = multi_host_run["state"]
        assert state.current_target is None
        assert state.current_stage == "report"

    def test_per_host_state_updates_scoped_to_current_host(self, multi_host_run):
        """state.update_from_* scopes findings to the current host.

        After all four stages, each discovered host carries ports, services,
        and OS matches — no per-host stage bleeds into another host's state.
        """
        state = multi_host_run["state"]
        for ip in EXPECTED_HOSTS:
            host = state.discovered_hosts[ip]
            assert host.open_ports, f"{ip} missing ports"
            assert host.services, f"{ip} missing services"
            assert host.os_matches, f"{ip} missing OS matches"

    def test_stage_complete_parent_is_interpretation(self, multi_host_run):
        """Per-host stage_complete parents to the preceding interpretation_call."""
        events = multi_host_run["events"]
        per_host_stages = {"port_scan", "service_enum", "os_fingerprint"}
        for event in events:
            if event["event_type"] != "stage_complete":
                continue
            if event["stage"] not in per_host_stages:
                continue
            parent = event["parent_span_id"]
            assert parent is not None
            parent_event = next(e for e in events if e["span_id"] == parent)
            assert parent_event["event_type"] == "interpretation_call"
            assert parent_event["host_target"] == event["host_target"]
            assert parent_event["stage"] == event["stage"]

    def test_stage_complete_counters_on_happy_path(self, multi_host_run):
        """Per-host happy-path stage_complete: success=true, llm_calls=2, retries=0."""
        events = multi_host_run["events"]
        per_host_stages = {"port_scan", "service_enum", "os_fingerprint"}
        for event in events:
            if event["event_type"] != "stage_complete":
                continue
            if event["stage"] not in per_host_stages:
                continue
            assert event["success"] is True
            assert event["llm_calls"] == 2
            assert event["retries"] == 0

    def test_total_executor_and_llm_call_counts(self, multi_host_run):
        """Accounting check: 7 executor calls, 14 LLM calls for the full 4-stage run."""
        assert len(multi_host_run["tool"].history) == 7
        assert len(multi_host_run["llm"].history) == 14

    def test_state_errors_empty_on_happy_path(self, multi_host_run):
        """Happy path: no failure/skip events recorded in state.errors."""
        assert multi_host_run["state"].errors == []


# -- zero-hosts-discovered skip ------------------------------------------------


@pytest.fixture()
def zero_hosts_run(config):
    """Run ReconAgent when host_discovery finds no live hosts.

    Uses empty.xml (no <host> elements). host_discovery itself succeeds
    (the scan ran, just no hosts were up), and subsequent per-host stages
    must deterministic_skip.
    """
    llm = FakeLLMClient([_planning_response(), _interpretation_response()])
    tool = FakeToolExecutor(
        results=[(FIXTURES_DIR / "empty.xml", _exec_result_ok(["/usr/bin/nmap", "-sn"]))],
        output_dir=Path(config.output_dir),
    )
    logger = AgentLogger(config)
    trace_id = logger.trace_id

    agent = ReconAgent(config, llm_client=llm, tool_executor=tool, logger=logger)
    report_path = agent.run()

    events = [e for e in _read_log_events(config.log_file) if e.get("trace_id") == trace_id]
    return {
        "agent": agent,
        "llm": llm,
        "tool": tool,
        "trace_id": trace_id,
        "report_path": report_path,
        "events": events,
        "state": agent._state,
    }


class TestZeroHostsDiscovered:
    """Per-host stages deterministic-skip when host_discovery finds no hosts."""

    def test_stages_completed_still_has_all_four(self, zero_hosts_run):
        """Progress-marker semantics: every stage advances, even when skipped."""
        state = zero_hosts_run["state"]
        assert state.stages_completed == [
            "host_discovery",
            "port_scan",
            "service_enum",
            "os_fingerprint",
        ]

    def test_skipped_stage_complete_events_deterministic_skip(self, zero_hosts_run):
        """Each skipped stage emits one stage_complete with deterministic_skip shape."""
        events = zero_hosts_run["events"]
        skipped = [
            e
            for e in events
            if e["event_type"] == "stage_complete"
            and e["stage"] in {"port_scan", "service_enum", "os_fingerprint"}
        ]
        assert len(skipped) == 3
        for event in skipped:
            assert event["success"] is False
            assert event["llm_calls"] == 0
            assert event["retries"] == 0
            assert event["findings_count"] == 0
            assert event["host_target"] is None

    def test_state_errors_populated_with_no_hosts_discovered(self, zero_hosts_run):
        """One state.errors entry per skipped stage, reason=no_hosts_discovered."""
        errors = zero_hosts_run["state"].errors
        stages = [e["stage"] for e in errors]
        assert stages == ["port_scan", "service_enum", "os_fingerprint"]
        for entry in errors:
            assert entry["reason"] == "no_hosts_discovered"
            assert entry["host"] is None

    def test_no_per_host_llm_or_executor_calls(self, zero_hosts_run):
        """No LLM / executor calls for skipped per-host stages."""
        assert len(zero_hosts_run["llm"].history) == 2
        assert len(zero_hosts_run["tool"].history) == 1

    def test_report_still_generated(self, zero_hosts_run):
        """Report is generated even when no hosts were discovered."""
        report_path = zero_hosts_run["report_path"]
        assert Path(report_path).exists()
