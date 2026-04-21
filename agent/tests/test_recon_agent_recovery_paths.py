"""Retry, fallback, skip, and execution-failure cases for ReconAgent."""

from __future__ import annotations

from pathlib import Path

import pytest

from llm_client import LLMError
from tool_executor import CommandBlockedError

from .fakes import FakeLLMClient, FakeToolExecutor
from .recon_agent_test_support import (
    FIRST_HOST,
    FIXTURES_DIR,
    SECOND_HOST,
    TEST_HOST,
    _bad_plan_invalid_intensity,
    _build_agent,
    _events_for_run,
    _exec_result_nonzero_exit,
    _exec_result_ok,
    _exec_result_permission_error,
    _exec_result_timeout,
    _generic_interpretation,
    _good_os_fingerprint_plan,
    _good_port_scan_plan,
    _seed_host,
    _seed_ports,
)


@pytest.fixture()
def guardrail_retry_success_run(config):
    llm = FakeLLMClient(
        [
            _bad_plan_invalid_intensity(),
            _good_port_scan_plan(),
            _generic_interpretation("ports for host"),
        ]
    )
    tool = FakeToolExecutor(
        results=[(FIXTURES_DIR / "port_scan.xml", _exec_result_ok(["/usr/bin/nmap", "-sS"]))],
        output_dir=Path(config.output_dir),
    )
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    _seed_host(agent)
    agent._state.current_stage = "port_scan"
    agent._run_per_host_stage("port_scan", TEST_HOST)
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestGuardrailRetryThenSuccess:
    def test_two_planning_calls_recorded(self, guardrail_retry_success_run):
        events = guardrail_retry_success_run["events"]
        planning = [e for e in events if e["event_type"] == "planning_call"]
        assert len(planning) == 2
        assert [p["stage_attempt"] for p in planning] == [1, 2]
        assert all(p["parent_span_id"] is None for p in planning)

    def test_retry_prompt_uses_replace_style(self, guardrail_retry_success_run):
        llm = guardrail_retry_success_run["llm"]
        retry_messages = llm.history[1].messages
        assert len(retry_messages) == 3
        assert retry_messages[0]["role"] == "system"
        assert retry_messages[1]["role"] == "user"
        assert retry_messages[2]["role"] == "user"
        assert retry_messages[2]["content"].startswith("Previous attempt rejected:")
        snippet = retry_messages[2]["content"].removeprefix("Previous attempt rejected: ")
        assert len(snippet) <= 250
        original_messages = llm.history[0].messages
        assert retry_messages[1]["content"] == original_messages[1]["content"]

    def test_guardrail_violation_parents_to_failed_planning(self, guardrail_retry_success_run):
        events = guardrail_retry_success_run["events"]
        planning = [e for e in events if e["event_type"] == "planning_call"]
        violations = [e for e in events if e["event_type"] == "guardrail_violation"]
        assert len(violations) == 1
        assert violations[0]["parent_span_id"] == planning[0]["span_id"]
        assert violations[0]["action_taken"] == "retry_planning"
        assert violations[0]["rule"] == "invalid_scan_intensity"

    def test_command_exec_sources_from_llm(self, guardrail_retry_success_run):
        events = guardrail_retry_success_run["events"]
        cmd_exec = next(e for e in events if e["event_type"] == "command_exec")
        assert cmd_exec["command_source"] == "llm"
        planning = [e for e in events if e["event_type"] == "planning_call"]
        assert cmd_exec["parent_span_id"] == planning[1]["span_id"]

    def test_stage_complete_counters(self, guardrail_retry_success_run):
        events = guardrail_retry_success_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is True
        assert stage_complete["llm_calls"] == 3
        assert stage_complete["retries"] == 1
        assert stage_complete["mitre_technique"] == "T1046"

    def test_state_errors_empty_on_recovered_run(self, guardrail_retry_success_run):
        assert guardrail_retry_success_run["state"].errors == []


@pytest.fixture()
def retry_exhaustion_fallback_run(config):
    llm = FakeLLMClient(
        [
            _bad_plan_invalid_intensity(),
            _bad_plan_invalid_intensity(),
            _bad_plan_invalid_intensity(),
            _generic_interpretation("fallback ports"),
        ]
    )
    tool = FakeToolExecutor(
        results=[(FIXTURES_DIR / "port_scan.xml", _exec_result_ok(["/usr/bin/nmap", "-sS"]))],
        output_dir=Path(config.output_dir),
    )
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    _seed_host(agent)
    agent._state.current_stage = "port_scan"
    agent._run_per_host_stage("port_scan", TEST_HOST)
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestRetryExhaustionThenFallback:
    def test_three_planning_attempts_with_incrementing_stage_attempt(
        self, retry_exhaustion_fallback_run
    ):
        events = retry_exhaustion_fallback_run["events"]
        planning = [e for e in events if e["event_type"] == "planning_call"]
        assert [p["stage_attempt"] for p in planning] == [1, 2, 3]
        assert all(p["parent_span_id"] is None for p in planning)

    def test_three_guardrail_violations_last_uses_fallback(self, retry_exhaustion_fallback_run):
        events = retry_exhaustion_fallback_run["events"]
        violations = [e for e in events if e["event_type"] == "guardrail_violation"]
        assert len(violations) == 3
        actions = [v["action_taken"] for v in violations]
        assert actions == ["retry_planning", "retry_planning", "use_fallback"]

    def test_command_exec_has_fallback_source_and_parents_to_use_fallback(
        self, retry_exhaustion_fallback_run
    ):
        events = retry_exhaustion_fallback_run["events"]
        cmd_exec = next(e for e in events if e["event_type"] == "command_exec")
        violations = [e for e in events if e["event_type"] == "guardrail_violation"]
        use_fallback = next(v for v in violations if v["action_taken"] == "use_fallback")
        assert cmd_exec["command_source"] == "fallback"
        assert cmd_exec["parent_span_id"] == use_fallback["span_id"]

    def test_stage_complete_counters_after_fallback(self, retry_exhaustion_fallback_run):
        events = retry_exhaustion_fallback_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is True
        assert stage_complete["llm_calls"] == 4
        assert stage_complete["retries"] == 2

    def test_only_one_executor_call_no_internal_retry(self, retry_exhaustion_fallback_run):
        assert len(retry_exhaustion_fallback_run["tool"].history) == 1

    def test_state_errors_empty_when_fallback_succeeds(self, retry_exhaustion_fallback_run):
        assert retry_exhaustion_fallback_run["state"].errors == []


@pytest.fixture()
def service_enum_no_ports_run(config):
    llm = FakeLLMClient([])
    tool = FakeToolExecutor(results=[], output_dir=Path(config.output_dir))
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    _seed_host(agent)
    agent._state.current_stage = "service_enum"
    agent._run_per_host_stage("service_enum", TEST_HOST)
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestServiceEnumPrePlanningSkip:
    def test_no_planning_or_command_events(self, service_enum_no_ports_run):
        events = service_enum_no_ports_run["events"]
        planning = [e for e in events if e["event_type"] == "planning_call"]
        cmd_exec = [e for e in events if e["event_type"] == "command_exec"]
        interp = [e for e in events if e["event_type"] == "interpretation_call"]
        assert planning == []
        assert cmd_exec == []
        assert interp == []

    def test_no_llm_or_executor_calls(self, service_enum_no_ports_run):
        assert len(service_enum_no_ports_run["llm"].history) == 0
        assert len(service_enum_no_ports_run["tool"].history) == 0

    def test_stage_complete_is_deterministic_skip(self, service_enum_no_ports_run):
        events = service_enum_no_ports_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is False
        assert stage_complete["llm_calls"] == 0
        assert stage_complete["retries"] == 0
        assert stage_complete["findings_count"] == 0
        assert stage_complete["skip_category"] == "deterministic_skip"
        assert stage_complete["reason"] == "no_known_ports"
        assert stage_complete["host_target"] == TEST_HOST
        assert stage_complete["mitre_technique"] == "T1046"
        assert stage_complete["parent_span_id"] is None

    def test_state_errors_records_no_known_ports(self, service_enum_no_ports_run):
        errors = service_enum_no_ports_run["state"].errors
        assert len(errors) == 1
        entry = errors[0]
        assert entry["stage"] == "service_enum"
        assert entry["host"] == TEST_HOST
        assert entry["reason"] == "no_known_ports"


@pytest.fixture()
def service_enum_defense_in_depth_run(config, monkeypatch):
    llm = FakeLLMClient(
        [
            _bad_plan_invalid_intensity(),
            _bad_plan_invalid_intensity(),
            _bad_plan_invalid_intensity(),
        ]
    )
    tool = FakeToolExecutor(results=[], output_dir=Path(config.output_dir))
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    _seed_host(agent)
    _seed_ports(agent)

    def _raise_no_ports(stage, state, target_ip=None):
        raise ValueError(f"No known open ports for {target_ip} — cannot build {stage} fallback")

    monkeypatch.setattr(agent._command_builder, "build_fallback", _raise_no_ports)

    agent._state.current_stage = "service_enum"
    agent._run_per_host_stage("service_enum", TEST_HOST)
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestServiceEnumDefenseInDepthSkip:
    def test_planning_ran_three_times(self, service_enum_defense_in_depth_run):
        events = service_enum_defense_in_depth_run["events"]
        planning = [e for e in events if e["event_type"] == "planning_call"]
        assert len(planning) == 3

    def test_no_command_exec_or_interpretation(self, service_enum_defense_in_depth_run):
        events = service_enum_defense_in_depth_run["events"]
        cmd_exec = [e for e in events if e["event_type"] == "command_exec"]
        interp = [e for e in events if e["event_type"] == "interpretation_call"]
        assert cmd_exec == []
        assert interp == []

    def test_stage_complete_is_post_attempt_skip(self, service_enum_defense_in_depth_run):
        events = service_enum_defense_in_depth_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is False
        assert stage_complete["skip_category"] == "post_attempt_skip"
        assert stage_complete["reason"] == "no_known_ports"
        assert stage_complete["llm_calls"] == 3
        assert stage_complete["retries"] == 2
        assert stage_complete["host_target"] == TEST_HOST

    def test_state_errors_records_no_known_ports(self, service_enum_defense_in_depth_run):
        errors = service_enum_defense_in_depth_run["state"].errors
        assert len(errors) == 1
        entry = errors[0]
        assert entry["stage"] == "service_enum"
        assert entry["host"] == TEST_HOST
        assert entry["reason"] == "no_known_ports"


@pytest.fixture()
def llm_error_planning_recovery_run(config):
    llm = FakeLLMClient(
        [
            LLMError("connection refused"),
            _good_port_scan_plan(),
            _generic_interpretation("ok"),
        ]
    )
    tool = FakeToolExecutor(
        results=[(FIXTURES_DIR / "port_scan.xml", _exec_result_ok(["/usr/bin/nmap", "-sS"]))],
        output_dir=Path(config.output_dir),
    )
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    _seed_host(agent)
    agent._state.current_stage = "port_scan"
    agent._run_per_host_stage("port_scan", TEST_HOST)
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestLLMErrorPlanningRecovery:
    def test_single_planning_call_logged_on_successful_attempt(
        self, llm_error_planning_recovery_run
    ):
        events = llm_error_planning_recovery_run["events"]
        planning = [e for e in events if e["event_type"] == "planning_call"]
        assert len(planning) == 1
        assert planning[0]["stage_attempt"] == 2

    def test_no_guardrail_violation_emitted_for_llm_error(self, llm_error_planning_recovery_run):
        events = llm_error_planning_recovery_run["events"]
        violations = [e for e in events if e["event_type"] == "guardrail_violation"]
        assert violations == []

    def test_command_exec_source_is_llm_after_recovery(self, llm_error_planning_recovery_run):
        events = llm_error_planning_recovery_run["events"]
        cmd_exec = next(e for e in events if e["event_type"] == "command_exec")
        assert cmd_exec["command_source"] == "llm"

    def test_stage_complete_accounts_for_failed_attempt(self, llm_error_planning_recovery_run):
        events = llm_error_planning_recovery_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is True
        assert stage_complete["llm_calls"] == 3
        assert stage_complete["retries"] == 1


@pytest.fixture()
def execution_failure_run(config):
    llm = FakeLLMClient([_good_port_scan_plan()])
    tool = FakeToolExecutor(results=[_exec_result_timeout()], output_dir=Path(config.output_dir))
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    _seed_host(agent)
    agent._state.current_stage = "port_scan"
    agent._run_per_host_stage("port_scan", TEST_HOST)
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestExecutionFailureSkipsInterpretation:
    def test_planning_and_command_exec_run(self, execution_failure_run):
        events = execution_failure_run["events"]
        assert [e for e in events if e["event_type"] == "planning_call"]
        assert [e for e in events if e["event_type"] == "command_exec"]

    def test_state_update_and_interpretation_skipped(self, execution_failure_run):
        events = execution_failure_run["events"]
        assert [e for e in events if e["event_type"] == "state_update"] == []
        assert [e for e in events if e["event_type"] == "interpretation_call"] == []

    def test_error_event_records_nmap_timeout(self, execution_failure_run):
        events = execution_failure_run["events"]
        errors = [e for e in events if e["event_type"] == "error"]
        assert len(errors) == 1
        assert errors[0]["error_type"] == "nmap_timeout"
        assert errors[0]["recoverable"] is False

    def test_state_errors_records_execution_failed(self, execution_failure_run):
        errors = execution_failure_run["state"].errors
        assert len(errors) == 1
        entry = errors[0]
        assert entry["stage"] == "port_scan"
        assert entry["host"] == TEST_HOST
        assert entry["reason"] == "execution_failed"

    def test_stage_complete_is_post_attempt_skip(self, execution_failure_run):
        events = execution_failure_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is False
        assert stage_complete["skip_category"] == "post_attempt_skip"
        assert stage_complete["reason"] == "execution_failed"
        assert stage_complete["llm_calls"] == 1
        assert stage_complete["retries"] == 0

    def test_only_one_llm_call(self, execution_failure_run):
        assert len(execution_failure_run["llm"].history) == 1


@pytest.fixture()
def os_fingerprint_no_ports_run(config):
    llm = FakeLLMClient(
        [
            _good_os_fingerprint_plan(),
            _generic_interpretation("os guess"),
        ]
    )
    tool = FakeToolExecutor(
        results=[(FIXTURES_DIR / "os_fingerprint.xml", _exec_result_ok(["/usr/bin/nmap", "-O"]))],
        output_dir=Path(config.output_dir),
    )
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    _seed_host(agent)
    agent._state.current_stage = "os_fingerprint"
    agent._run_per_host_stage("os_fingerprint", TEST_HOST)
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestOsFingerprintWithoutKnownPorts:
    def test_full_pipeline_events_emitted(self, os_fingerprint_no_ports_run):
        events = os_fingerprint_no_ports_run["events"]
        types = [e["event_type"] for e in events]
        assert types == [
            "planning_call",
            "command_exec",
            "state_update",
            "interpretation_call",
            "stage_complete",
        ]

    def test_stage_complete_success(self, os_fingerprint_no_ports_run):
        events = os_fingerprint_no_ports_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is True
        assert stage_complete["llm_calls"] == 2
        assert stage_complete["retries"] == 0
        assert stage_complete["mitre_technique"] == "T1082"

    def test_state_errors_empty(self, os_fingerprint_no_ports_run):
        assert os_fingerprint_no_ports_run["state"].errors == []


@pytest.fixture()
def multi_host_fallback_run(config):
    llm = FakeLLMClient(
        [
            _bad_plan_invalid_intensity(SECOND_HOST),
            _bad_plan_invalid_intensity(SECOND_HOST),
            _bad_plan_invalid_intensity(SECOND_HOST),
            _generic_interpretation("fallback ok"),
        ]
    )
    tool = FakeToolExecutor(
        results=[(FIXTURES_DIR / "port_scan.xml", _exec_result_ok(["/usr/bin/nmap", "-sS"]))],
        output_dir=Path(config.output_dir),
    )
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    agent._state.update_from_discovery([{"ip": FIRST_HOST}, {"ip": SECOND_HOST}])
    agent._state.current_stage = "port_scan"
    agent._run_per_host_stage("port_scan", SECOND_HOST)
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestMultiHostFallbackScoping:
    def test_fallback_command_targets_current_host_not_first_discovered(
        self, multi_host_fallback_run
    ):
        tool = multi_host_fallback_run["tool"]
        assert len(tool.history) == 1
        call = tool.history[0]
        assert SECOND_HOST in call.args, (
            f"Fallback command missing current host {SECOND_HOST}: {call.args}"
        )
        assert FIRST_HOST not in call.args, (
            f"Fallback leaked to first-discovered host {FIRST_HOST}: {call.args}"
        )

    def test_fallback_output_filename_scoped_to_current_host(self, multi_host_fallback_run):
        tool = multi_host_fallback_run["tool"]
        filename = tool.history[0].output_filename
        assert SECOND_HOST in filename
        assert f"{FIRST_HOST}_" not in filename

    def test_command_exec_marks_fallback_provenance(self, multi_host_fallback_run):
        events = multi_host_fallback_run["events"]
        cmd_exec = next(e for e in events if e["event_type"] == "command_exec")
        assert cmd_exec["command_source"] == "fallback"
        assert cmd_exec["host_target"] == SECOND_HOST

    def test_state_update_scoped_to_current_host(self, multi_host_fallback_run):
        state = multi_host_fallback_run["state"]
        assert state.discovered_hosts[SECOND_HOST].open_ports
        assert state.discovered_hosts[FIRST_HOST].open_ports == []


@pytest.fixture()
def llm_error_exhaustion_fallback_run(config):
    llm = FakeLLMClient(
        [
            LLMError("connection refused"),
            LLMError("connection refused"),
            LLMError("connection refused"),
            _generic_interpretation("recovered via fallback"),
        ]
    )
    tool = FakeToolExecutor(
        results=[(FIXTURES_DIR / "port_scan.xml", _exec_result_ok(["/usr/bin/nmap", "-sS"]))],
        output_dir=Path(config.output_dir),
    )
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    _seed_host(agent)
    agent._state.current_stage = "port_scan"
    agent._run_per_host_stage("port_scan", TEST_HOST)
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestLLMErrorExhaustionFallback:
    def test_no_planning_call_events_logged(self, llm_error_exhaustion_fallback_run):
        events = llm_error_exhaustion_fallback_run["events"]
        assert [e for e in events if e["event_type"] == "planning_call"] == []

    def test_no_guardrail_violation_events(self, llm_error_exhaustion_fallback_run):
        events = llm_error_exhaustion_fallback_run["events"]
        assert [e for e in events if e["event_type"] == "guardrail_violation"] == []

    def test_command_exec_is_fallback_with_no_parent(self, llm_error_exhaustion_fallback_run):
        events = llm_error_exhaustion_fallback_run["events"]
        cmd_exec = next(e for e in events if e["event_type"] == "command_exec")
        assert cmd_exec["command_source"] == "fallback"
        assert cmd_exec["parent_span_id"] is None

    def test_full_pipeline_completes_and_counters_are_correct(
        self, llm_error_exhaustion_fallback_run
    ):
        events = llm_error_exhaustion_fallback_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is True
        assert stage_complete["llm_calls"] == 4
        assert stage_complete["retries"] == 2

    def test_state_errors_empty_when_fallback_succeeds(self, llm_error_exhaustion_fallback_run):
        assert llm_error_exhaustion_fallback_run["state"].errors == []

    def test_four_llm_calls_in_history(self, llm_error_exhaustion_fallback_run):
        assert len(llm_error_exhaustion_fallback_run["llm"].history) == 4


@pytest.fixture()
def command_blocked_run(config):
    llm = FakeLLMClient([_good_port_scan_plan()])
    blocked = CommandBlockedError(
        "target_outside_subnet",
        "Target 10.0.0.1 is outside allowed subnet",
        ["/usr/bin/nmap", "10.0.0.1"],
    )
    tool = FakeToolExecutor(results=[blocked], output_dir=Path(config.output_dir))
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    _seed_host(agent)
    agent._state.current_stage = "port_scan"
    agent._run_per_host_stage("port_scan", TEST_HOST)
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestCommandBlockedExecutionFailure:
    def test_no_command_exec_event_logged(self, command_blocked_run):
        events = command_blocked_run["events"]
        assert [e for e in events if e["event_type"] == "command_exec"] == []

    def test_error_event_records_command_blocked(self, command_blocked_run):
        events = command_blocked_run["events"]
        errors = [e for e in events if e["event_type"] == "error"]
        assert len(errors) == 1
        err = errors[0]
        assert err["error_type"] == "command_blocked"
        assert err["rule"] == "target_outside_subnet"
        assert err["recoverable"] is False

    def test_interpretation_skipped(self, command_blocked_run):
        events = command_blocked_run["events"]
        assert [e for e in events if e["event_type"] == "interpretation_call"] == []
        assert [e for e in events if e["event_type"] == "state_update"] == []

    def test_stage_complete_is_post_attempt_skip(self, command_blocked_run):
        events = command_blocked_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is False
        assert stage_complete["skip_category"] == "post_attempt_skip"
        assert stage_complete["reason"] == "execution_failed"
        assert stage_complete["llm_calls"] == 1
        assert stage_complete["retries"] == 0

    def test_state_errors_records_execution_failed(self, command_blocked_run):
        errors = command_blocked_run["state"].errors
        assert len(errors) == 1
        entry = errors[0]
        assert entry["stage"] == "port_scan"
        assert entry["host"] == TEST_HOST
        assert entry["reason"] == "execution_failed"
        assert "command_blocked" in (entry["detail"] or "")


@pytest.fixture()
def nonzero_exit_run(config):
    llm = FakeLLMClient([_good_port_scan_plan()])
    tool = FakeToolExecutor(
        results=[_exec_result_nonzero_exit()], output_dir=Path(config.output_dir)
    )
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    _seed_host(agent)
    agent._state.current_stage = "port_scan"
    agent._run_per_host_stage("port_scan", TEST_HOST)
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestNmapNonzeroExit:
    def test_command_exec_logged_with_nonzero_return_code(self, nonzero_exit_run):
        events = nonzero_exit_run["events"]
        cmd_exec = next(e for e in events if e["event_type"] == "command_exec")
        assert cmd_exec["return_code"] == 2

    def test_error_event_records_nmap_nonzero_exit(self, nonzero_exit_run):
        events = nonzero_exit_run["events"]
        errors = [e for e in events if e["event_type"] == "error"]
        assert len(errors) == 1
        assert errors[0]["error_type"] == "nmap_nonzero_exit"
        assert errors[0]["recoverable"] is False

    def test_interpretation_skipped(self, nonzero_exit_run):
        events = nonzero_exit_run["events"]
        assert [e for e in events if e["event_type"] == "interpretation_call"] == []
        assert [e for e in events if e["event_type"] == "state_update"] == []

    def test_stage_complete_is_post_attempt_skip(self, nonzero_exit_run):
        events = nonzero_exit_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is False
        assert stage_complete["skip_category"] == "post_attempt_skip"
        assert stage_complete["reason"] == "execution_failed"

    def test_state_errors_records_execution_failed(self, nonzero_exit_run):
        errors = nonzero_exit_run["state"].errors
        assert len(errors) == 1
        assert errors[0]["reason"] == "execution_failed"
        assert errors[0]["detail"] == "nmap_nonzero_exit"


@pytest.fixture()
def permission_error_run(config):
    llm = FakeLLMClient([_good_port_scan_plan()])
    tool = FakeToolExecutor(
        results=[_exec_result_permission_error()], output_dir=Path(config.output_dir)
    )
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    _seed_host(agent)
    agent._state.current_stage = "port_scan"
    agent._run_per_host_stage("port_scan", TEST_HOST)
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestPermissionErrorExecutionFailure:
    def test_error_event_records_permission_error(self, permission_error_run):
        events = permission_error_run["events"]
        errors = [e for e in events if e["event_type"] == "error"]
        assert len(errors) == 1
        assert errors[0]["error_type"] == "permission_error"

    def test_interpretation_skipped(self, permission_error_run):
        events = permission_error_run["events"]
        assert [e for e in events if e["event_type"] == "interpretation_call"] == []
        assert [e for e in events if e["event_type"] == "state_update"] == []

    def test_stage_complete_is_post_attempt_skip(self, permission_error_run):
        events = permission_error_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is False
        assert stage_complete["skip_category"] == "post_attempt_skip"
        assert stage_complete["reason"] == "execution_failed"
        assert stage_complete["llm_calls"] == 1

    def test_state_errors_records_execution_failed(self, permission_error_run):
        errors = permission_error_run["state"].errors
        assert len(errors) == 1
        assert errors[0]["reason"] == "execution_failed"
        assert errors[0]["detail"] == "permission_error"
