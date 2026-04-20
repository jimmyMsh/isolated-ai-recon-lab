"""Tests for ReconAgent — Phase 5 pipeline orchestrator.

Phase 5.1 scope: happy path for the ``host_discovery`` stage only. No multi-host
iteration, retry/fallback logic, or time-budget handling yet.
"""

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


@pytest.fixture()
def happy_path_run(config):
    """Run ReconAgent through the host_discovery happy path exactly once.

    Tests in this module share this fixture so assertions target observable
    outputs (state, logs, report) without re-running the pipeline.
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


class TestHostDiscoveryHappyPath:
    """Sub-phase 5.1: single-stage end-to-end for host_discovery."""

    def test_run_returns_existing_report_path(self, happy_path_run):
        """run() returns a path to a generated report file."""
        report_path = happy_path_run["report_path"]
        assert isinstance(report_path, str)
        assert Path(report_path).exists()

    def test_state_contains_discovered_hosts(self, happy_path_run):
        """Shared Semantic #6: AgentState owns durable recon findings.

        After host_discovery, state.discovered_hosts reflects the two up hosts
        from the fixture (attacker IP 192.168.56.10 is excluded).
        """
        state = happy_path_run["state"]
        assert set(state.discovered_hosts.keys()) == {"192.168.56.1", "192.168.56.101"}

    def test_stages_completed_includes_host_discovery(self, happy_path_run):
        """Shared Semantic #1: stages_completed is a progress marker."""
        state = happy_path_run["state"]
        assert state.stages_completed == ["host_discovery"]

    def test_current_stage_set_to_host_discovery_during_run(self, happy_path_run):
        """Current stage is set before prompt construction; the first planning_call
        observes it.
        """
        events = happy_path_run["events"]
        planning = next(e for e in events if e["event_type"] == "planning_call")
        assert planning["stage"] == "host_discovery"
        # State snapshot captured on state_update must carry the stage too
        state_update = next(e for e in events if e["event_type"] == "state_update")
        assert state_update["state_snapshot"]["current_stage"] == "host_discovery"

    def test_log_contains_all_pipeline_events(self, happy_path_run):
        """Acceptance: JSONL log contains planning_call, command_exec, state_update,
        interpretation_call, stage_complete (5 events for 5.1 happy path).
        """
        events = happy_path_run["events"]
        types = [e["event_type"] for e in events]
        assert types == [
            "planning_call",
            "command_exec",
            "state_update",
            "interpretation_call",
            "stage_complete",
        ]

    def test_span_parent_chain_matches_precedence(self, happy_path_run):
        """Shared Semantic #8: canonical chain
        planning → command_exec → state_update → interpretation_call → stage_complete.
        stage_complete parents to interpretation_call (precedence 1).
        """
        events = happy_path_run["events"]
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

    def test_state_update_uses_sparse_delta_and_snapshot(self, happy_path_run):
        """Acceptance: state_update emits update_source=tool_parser, a sparse
        state_delta, and a state_snapshot sourced from to_log_snapshot().
        """
        events = happy_path_run["events"]
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

    def test_command_exec_has_command_source_llm(self, happy_path_run):
        """Acceptance: command_exec includes command_source="llm" on the happy path."""
        events = happy_path_run["events"]
        cmd_exec = next(e for e in events if e["event_type"] == "command_exec")
        assert cmd_exec["command_source"] == "llm"

    def test_stage_complete_counters(self, happy_path_run):
        """Shared Semantic #7: happy-path retries=0, llm_calls=2 (planning + interp).
        mitre_technique comes from STAGE_TO_MITRE.
        """
        events = happy_path_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is True
        assert stage_complete["llm_calls"] == 2
        assert stage_complete["retries"] == 0
        assert stage_complete["mitre_technique"] == "T1595.001"

    def test_interpretation_not_stored_in_state(self, happy_path_run):
        """Design principle: state is code-built, never LLM-built.

        Interpretation output lives only in the log, not in AgentState.
        """
        state = happy_path_run["state"]
        # No interpretation summary/findings should have leaked into state.
        for host in state.discovered_hosts.values():
            assert host.services == []
            assert host.os_matches == []

    def test_report_references_trace_id(self, happy_path_run):
        """Acceptance: report generation uses the logger's trace_id explicitly."""
        trace_id = happy_path_run["trace_id"]
        report_path = happy_path_run["report_path"]
        assert trace_id in Path(report_path).name

    def test_logger_closed_after_run(self, happy_path_run):
        """Acceptance: logger.close() is called (finally block)."""
        agent = happy_path_run["agent"]
        # Internal attribute check — close() is observable via _closed flag.
        assert agent._logger._closed is True

    def test_shared_guardrails_injected_into_executor(self, config):
        """Acceptance: one shared Guardrails instance is injected into ToolExecutor.

        Skip the orchestration run; verify the construction-time contract.
        """
        agent = ReconAgent(config)
        assert isinstance(agent._guardrails, Guardrails)
        assert agent._executor._guardrails is agent._guardrails

    def test_planning_call_uses_host_discovery_stage_config(self, happy_path_run):
        """The LLM planning call is made with the host_discovery stage config."""
        llm = happy_path_run["llm"]
        planning_record = llm.history[0]
        assert planning_record.stage_config is not None
        # Default StageConfig used in this test → temperature 0.0
        assert planning_record.stage_config.temperature == 0.0

    def test_executor_called_once(self, happy_path_run):
        """Acceptance: host_discovery runs exactly one nmap command for 5.1."""
        tool = happy_path_run["tool"]
        assert len(tool.history) == 1
