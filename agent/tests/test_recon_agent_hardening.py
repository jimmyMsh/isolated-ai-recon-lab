"""ReconAgent hardening tests.

Covers:
- Global time-budget enforcement at the three check points (before each
  stage, before each per-host iteration, between planning and execute).
- Interpretation LLMError retry-then-skip with stage_complete(success=true).
- Host-level unexpected_exception → skip_host; next host proceeds; error
  and skip events parent to the highest-priority event already logged.
- Run-level unexpected_exception → abort_pipeline; report still produced,
  logger closed exactly once even when report generation itself raises.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from llm_client import LLMError

from .fakes import FakeLLMClient, FakeToolExecutor
from .recon_agent_test_support import (
    EXPECTED_HOSTS,
    FIRST_HOST,
    FIXTURES_DIR,
    SECOND_HOST,
    TEST_HOST,
    _build_agent,
    _events_for_run,
    _exec_result_ok,
    _four_stage_exec_queue,
    _four_stage_llm_queue,
    _generic_interpretation,
    _good_port_scan_plan,
    _interpretation_response,
    _planning_response,
    _port_scan_plan,
    _read_log_events,
    _seed_host,
)

# ---------- switchable monotonic clock ----------------------------------


class _SwitchableClock:
    """Fake `time.monotonic()` with an explicit trip switch.

    Returns 0.0 until `.trip()` is called, then 500.0 forever. Tests trip
    the clock from a hook (wrapped method) to simulate the budget being
    exhausted at a specific pipeline checkpoint, independent of real time.
    """

    def __init__(self) -> None:
        self._tripped = False

    def trip(self) -> None:
        self._tripped = True

    def __call__(self) -> float:
        return 500.0 if self._tripped else 0.0


def _patch_recon_agent_clock(monkeypatch, clock: _SwitchableClock) -> None:
    monkeypatch.setattr("agent.recon_agent.time.monotonic", clock)


# =======================================================================
# Time budget — overrun before a per-host stage begins
# =======================================================================


@pytest.fixture()
def time_budget_before_stage_run(config, monkeypatch):
    """Budget exceeded just after host_discovery completes — all per-host
    stages deterministic-skip for every discovered host.
    """
    config.max_total_duration_seconds = 100
    clock = _SwitchableClock()
    _patch_recon_agent_clock(monkeypatch, clock)

    llm = FakeLLMClient([_planning_response(), _interpretation_response()])
    tool = FakeToolExecutor(
        results=[(FIXTURES_DIR / "host_discovery.xml", _exec_result_ok(["/usr/bin/nmap", "-sn"]))],
        output_dir=Path(config.output_dir),
    )
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    real_hd = agent._run_host_discovery

    def trip_after_hd():
        real_hd()
        clock.trip()

    monkeypatch.setattr(agent, "_run_host_discovery", trip_after_hd)

    report_path = agent.run()

    events = _events_for_run(config, trace_id)
    return {
        "agent": agent,
        "llm": llm,
        "tool": tool,
        "events": events,
        "state": agent._state,
        "report_path": report_path,
    }


class TestTimeBudgetBeforeStage:
    def test_host_discovery_still_succeeded(self, time_budget_before_stage_run):
        events = time_budget_before_stage_run["events"]
        hd = next(
            e
            for e in events
            if e["event_type"] == "stage_complete" and e["stage"] == "host_discovery"
        )
        assert hd["success"] is True

    def test_per_host_stages_emit_deterministic_skip_for_every_host(
        self, time_budget_before_stage_run
    ):
        events = time_budget_before_stage_run["events"]
        for stage in ("port_scan", "service_enum", "os_fingerprint"):
            completes = [
                e for e in events if e["event_type"] == "stage_complete" and e["stage"] == stage
            ]
            assert len(completes) == len(EXPECTED_HOSTS)
            for event in completes:
                assert event["success"] is False
                assert event["skip_category"] == "deterministic_skip"
                assert event["reason"] == "time_budget_exceeded"
                assert event["llm_calls"] == 0
                assert event["retries"] == 0

    def test_skipped_hosts_iterated_in_sorted_order(self, time_budget_before_stage_run):
        events = time_budget_before_stage_run["events"]
        for stage in ("port_scan", "service_enum", "os_fingerprint"):
            completes = [
                e for e in events if e["event_type"] == "stage_complete" and e["stage"] == stage
            ]
            assert [e["host_target"] for e in completes] == sorted(EXPECTED_HOSTS)

    def test_state_errors_populated_with_time_budget_exceeded(self, time_budget_before_stage_run):
        errors = time_budget_before_stage_run["state"].errors
        budget_errs = [e for e in errors if e["reason"] == "time_budget_exceeded"]
        assert len(budget_errs) == 3 * len(EXPECTED_HOSTS)

    def test_no_per_host_llm_or_executor_calls(self, time_budget_before_stage_run):
        assert len(time_budget_before_stage_run["llm"].history) == 2
        assert len(time_budget_before_stage_run["tool"].history) == 1

    def test_stages_completed_still_has_all_four(self, time_budget_before_stage_run):
        state = time_budget_before_stage_run["state"]
        assert state.stages_completed == [
            "host_discovery",
            "port_scan",
            "service_enum",
            "os_fingerprint",
        ]

    def test_report_generated(self, time_budget_before_stage_run):
        assert Path(time_budget_before_stage_run["report_path"]).exists()


# =======================================================================
# Time budget — overrun before a per-host iteration (mid-stage)
# =======================================================================


@pytest.fixture()
def time_budget_mid_iteration_run(config, monkeypatch):
    """First port_scan host runs normally; budget then trips → second host
    deterministic-skips, later stages deterministic-skip for every host.
    """
    config.max_total_duration_seconds = 100
    clock = _SwitchableClock()
    _patch_recon_agent_clock(monkeypatch, clock)

    llm_queue = [_planning_response(), _interpretation_response()]
    llm_queue.extend([_port_scan_plan(FIRST_HOST), _generic_interpretation("ports-1")])
    llm = FakeLLMClient(llm_queue)

    exec_queue = [
        (FIXTURES_DIR / "host_discovery.xml", _exec_result_ok(["/usr/bin/nmap", "-sn"])),
        (FIXTURES_DIR / "port_scan.xml", _exec_result_ok(["/usr/bin/nmap", "-sS"])),
    ]
    tool = FakeToolExecutor(results=exec_queue, output_dir=Path(config.output_dir))

    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    real_per_host = agent._run_per_host_stage

    def trip_after_first_port_scan(stage, host):
        real_per_host(stage, host)
        if stage == "port_scan" and host == FIRST_HOST:
            clock.trip()

    monkeypatch.setattr(agent, "_run_per_host_stage", trip_after_first_port_scan)

    report_path = agent.run()

    events = _events_for_run(config, trace_id)
    return {
        "agent": agent,
        "llm": llm,
        "tool": tool,
        "events": events,
        "state": agent._state,
        "report_path": report_path,
    }


class TestTimeBudgetBeforeHostIteration:
    def test_first_port_scan_host_completed_successfully(self, time_budget_mid_iteration_run):
        events = time_budget_mid_iteration_run["events"]
        first_complete = next(
            e
            for e in events
            if e["event_type"] == "stage_complete"
            and e["stage"] == "port_scan"
            and e["host_target"] == FIRST_HOST
        )
        assert first_complete["success"] is True

    def test_second_port_scan_host_deterministic_skip(self, time_budget_mid_iteration_run):
        events = time_budget_mid_iteration_run["events"]
        second_complete = next(
            e
            for e in events
            if e["event_type"] == "stage_complete"
            and e["stage"] == "port_scan"
            and e["host_target"] == SECOND_HOST
        )
        assert second_complete["success"] is False
        assert second_complete["skip_category"] == "deterministic_skip"
        assert second_complete["reason"] == "time_budget_exceeded"
        assert second_complete["llm_calls"] == 0
        assert second_complete["retries"] == 0

    def test_later_stages_deterministic_skip_for_every_host(self, time_budget_mid_iteration_run):
        events = time_budget_mid_iteration_run["events"]
        for stage in ("service_enum", "os_fingerprint"):
            completes = [
                e for e in events if e["event_type"] == "stage_complete" and e["stage"] == stage
            ]
            assert len(completes) == len(EXPECTED_HOSTS)
            for event in completes:
                assert event["skip_category"] == "deterministic_skip"
                assert event["reason"] == "time_budget_exceeded"

    def test_state_errors_has_one_entry_per_skipped_unit(self, time_budget_mid_iteration_run):
        errors = time_budget_mid_iteration_run["state"].errors
        # 1 skipped port_scan host + 2 service_enum + 2 os_fingerprint = 5
        assert sum(1 for e in errors if e["reason"] == "time_budget_exceeded") == 5

    def test_report_generated(self, time_budget_mid_iteration_run):
        assert Path(time_budget_mid_iteration_run["report_path"]).exists()


# =======================================================================
# Time budget — overrun between planning and execute (point 3)
# =======================================================================


@pytest.fixture()
def time_budget_between_plan_and_execute_run(config, monkeypatch):
    """Planning succeeds for FIRST_HOST port_scan, then the budget trips.
    Current host becomes a post_attempt_skip with preserved counters,
    no executor call; remaining units deterministic_skip.
    """
    config.max_total_duration_seconds = 100
    clock = _SwitchableClock()
    _patch_recon_agent_clock(monkeypatch, clock)

    llm_queue: list = [
        _planning_response(),
        _interpretation_response(),
        _port_scan_plan(FIRST_HOST),
    ]
    llm = FakeLLMClient(llm_queue)

    exec_queue = [
        (FIXTURES_DIR / "host_discovery.xml", _exec_result_ok(["/usr/bin/nmap", "-sn"])),
    ]
    tool = FakeToolExecutor(results=exec_queue, output_dir=Path(config.output_dir))

    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    real_plan = agent._plan

    def trip_after_first_port_scan_plan(**kwargs):
        result = real_plan(**kwargs)
        if kwargs.get("stage") == "port_scan" and kwargs.get("host") == FIRST_HOST:
            clock.trip()
        return result

    monkeypatch.setattr(agent, "_plan", trip_after_first_port_scan_plan)

    report_path = agent.run()

    events = _events_for_run(config, trace_id)
    return {
        "agent": agent,
        "llm": llm,
        "tool": tool,
        "events": events,
        "state": agent._state,
        "report_path": report_path,
    }


class TestTimeBudgetBetweenPlanAndExecute:
    def test_first_host_planning_was_logged(self, time_budget_between_plan_and_execute_run):
        events = time_budget_between_plan_and_execute_run["events"]
        planning = [
            e
            for e in events
            if e["event_type"] == "planning_call"
            and e["stage"] == "port_scan"
            and e["host_target"] == FIRST_HOST
        ]
        assert len(planning) == 1

    def test_no_command_exec_for_tripped_host(self, time_budget_between_plan_and_execute_run):
        events = time_budget_between_plan_and_execute_run["events"]
        cmd = [
            e
            for e in events
            if e["event_type"] == "command_exec"
            and e["stage"] == "port_scan"
            and e["host_target"] == FIRST_HOST
        ]
        assert cmd == []

    def test_tripped_host_emits_post_attempt_skip_with_preserved_counters(
        self, time_budget_between_plan_and_execute_run
    ):
        events = time_budget_between_plan_and_execute_run["events"]
        complete = next(
            e
            for e in events
            if e["event_type"] == "stage_complete"
            and e["stage"] == "port_scan"
            and e["host_target"] == FIRST_HOST
        )
        assert complete["success"] is False
        assert complete["skip_category"] == "post_attempt_skip"
        assert complete["reason"] == "time_budget_exceeded"
        # 1 planning call, no interpretation.
        assert complete["llm_calls"] == 1
        assert complete["retries"] == 0

    def test_second_host_is_deterministic_skip(self, time_budget_between_plan_and_execute_run):
        events = time_budget_between_plan_and_execute_run["events"]
        complete = next(
            e
            for e in events
            if e["event_type"] == "stage_complete"
            and e["stage"] == "port_scan"
            and e["host_target"] == SECOND_HOST
        )
        assert complete["skip_category"] == "deterministic_skip"
        assert complete["reason"] == "time_budget_exceeded"
        assert complete["llm_calls"] == 0

    def test_later_stages_deterministic_skip(self, time_budget_between_plan_and_execute_run):
        events = time_budget_between_plan_and_execute_run["events"]
        for stage in ("service_enum", "os_fingerprint"):
            completes = [
                e for e in events if e["event_type"] == "stage_complete" and e["stage"] == stage
            ]
            assert len(completes) == len(EXPECTED_HOSTS)
            for event in completes:
                assert event["skip_category"] == "deterministic_skip"
                assert event["reason"] == "time_budget_exceeded"

    def test_report_generated(self, time_budget_between_plan_and_execute_run):
        assert Path(time_budget_between_plan_and_execute_run["report_path"]).exists()


# =======================================================================
# Interpretation LLMError retry then skip
# =======================================================================


@pytest.fixture()
def interpretation_failure_run(config):
    """Interpretation fails with LLMError, retries once, fails again →
    stage_complete(success=true), error logged, state.errors NOT appended.
    """
    llm = FakeLLMClient(
        [
            _good_port_scan_plan(),
            LLMError("interp outage 1"),
            LLMError("interp outage 2"),
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


class TestInterpretationFailureRetryThenSkip:
    def test_two_interpretation_attempts_made(self, interpretation_failure_run):
        # 1 planning + 2 interpretation attempts = 3 LLM calls.
        assert len(interpretation_failure_run["llm"].history) == 3

    def test_no_interpretation_call_events_logged(self, interpretation_failure_run):
        events = interpretation_failure_run["events"]
        assert [e for e in events if e["event_type"] == "interpretation_call"] == []

    def test_error_event_logged_with_interp_failure(self, interpretation_failure_run):
        events = interpretation_failure_run["events"]
        errs = [e for e in events if e["event_type"] == "error"]
        assert len(errs) == 1
        err = errs[0]
        assert err["error_type"] == "llm_interpretation_failed"
        assert err["recoverable"] is False

    def test_stage_complete_success_true(self, interpretation_failure_run):
        events = interpretation_failure_run["events"]
        complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert complete["success"] is True
        # Counters include the failed interpretation retry.
        assert complete["llm_calls"] == 3
        assert complete["retries"] == 1

    def test_state_errors_not_appended(self, interpretation_failure_run):
        assert interpretation_failure_run["state"].errors == []

    def test_state_update_still_applied(self, interpretation_failure_run):
        state = interpretation_failure_run["state"]
        assert state.discovered_hosts[TEST_HOST].open_ports


@pytest.fixture()
def interpretation_retry_success_run(config):
    """Interpretation fails once then succeeds on retry."""
    llm = FakeLLMClient(
        [
            _good_port_scan_plan(),
            LLMError("interp hiccup"),
            _generic_interpretation("ok after retry"),
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


class TestInterpretationRetryThenSucceeds:
    def test_interpretation_call_event_present(self, interpretation_retry_success_run):
        events = interpretation_retry_success_run["events"]
        interp = [e for e in events if e["event_type"] == "interpretation_call"]
        assert len(interp) == 1

    def test_no_error_event_logged(self, interpretation_retry_success_run):
        events = interpretation_retry_success_run["events"]
        assert [e for e in events if e["event_type"] == "error"] == []

    def test_stage_complete_counters_reflect_retry(self, interpretation_retry_success_run):
        events = interpretation_retry_success_run["events"]
        complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert complete["success"] is True
        # 1 planning + 2 interpretation attempts
        assert complete["llm_calls"] == 3
        assert complete["retries"] == 1


# =======================================================================
# Host-level unexpected exception (skip_host)
# =======================================================================


@pytest.fixture()
def host_level_unexpected_exception_run(config, monkeypatch):
    """FIRST_HOST port_scan: parser raises RuntimeError; SECOND_HOST runs normally."""
    from agent import outcomes as outcomes_mod

    llm_queue = [
        _planning_response(),
        _interpretation_response(),
        _port_scan_plan(FIRST_HOST),
        # No interpretation for FIRST_HOST — it blew up before that.
        _port_scan_plan(SECOND_HOST),
        _generic_interpretation("ok second"),
    ]
    llm = FakeLLMClient(llm_queue)
    exec_queue = [
        (FIXTURES_DIR / "host_discovery.xml", _exec_result_ok(["/usr/bin/nmap", "-sn"])),
        (FIXTURES_DIR / "port_scan.xml", _exec_result_ok(["/usr/bin/nmap", "-sS"])),
        (FIXTURES_DIR / "port_scan.xml", _exec_result_ok(["/usr/bin/nmap", "-sS"])),
    ]
    tool = FakeToolExecutor(results=exec_queue, output_dir=Path(config.output_dir))

    original_parser = outcomes_mod._PARSERS["port_scan"]
    call_counter = {"n": 0}

    def maybe_exploding(path):
        call_counter["n"] += 1
        if call_counter["n"] == 1:
            raise RuntimeError("boom: parser exploded")
        return original_parser(path)

    monkeypatch.setitem(outcomes_mod._PARSERS, "port_scan", maybe_exploding)

    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id
    # Scope to host_discovery + port_scan to isolate the scenario — avoids
    # exhausting the queued fakes when later stages would otherwise run.
    agent._run_host_discovery()
    agent._run_per_host_stage_loop("port_scan")
    logger.close()

    events = _events_for_run(config, trace_id)
    return {"agent": agent, "llm": llm, "tool": tool, "events": events, "state": agent._state}


class TestHostLevelUnexpectedException:
    def test_error_event_for_first_host(self, host_level_unexpected_exception_run):
        events = host_level_unexpected_exception_run["events"]
        errs = [e for e in events if e["event_type"] == "error" and e["host_target"] == FIRST_HOST]
        assert len(errs) == 1
        err = errs[0]
        assert err["error_type"] == "unexpected_exception"
        assert err["action_taken"] == "skip_host"

    def test_first_host_emits_skip_stage_complete(self, host_level_unexpected_exception_run):
        events = host_level_unexpected_exception_run["events"]
        complete = next(
            e
            for e in events
            if e["event_type"] == "stage_complete"
            and e["stage"] == "port_scan"
            and e["host_target"] == FIRST_HOST
        )
        assert complete["success"] is False
        # Host-level exception is a post_attempt_skip (unit was entered).
        assert complete["skip_category"] == "post_attempt_skip"
        # 1 planning call happened before the parser blew up.
        assert complete["llm_calls"] == 1

    def test_second_host_processes_normally(self, host_level_unexpected_exception_run):
        events = host_level_unexpected_exception_run["events"]
        complete = next(
            e
            for e in events
            if e["event_type"] == "stage_complete"
            and e["stage"] == "port_scan"
            and e["host_target"] == SECOND_HOST
        )
        assert complete["success"] is True

    def test_state_errors_has_unexpected_exception_for_first_host(
        self, host_level_unexpected_exception_run
    ):
        state_errors = host_level_unexpected_exception_run["state"].errors
        match = [
            e
            for e in state_errors
            if e["host"] == FIRST_HOST and e["reason"] == "unexpected_exception"
        ]
        assert len(match) == 1

    def test_error_event_parents_to_command_exec(self, host_level_unexpected_exception_run):
        # The parser raised AFTER the command_exec event for FIRST_HOST was
        # logged. The host-level error event must preserve that causal link.
        events = host_level_unexpected_exception_run["events"]
        cmd_exec = next(
            e
            for e in events
            if e["event_type"] == "command_exec"
            and e["stage"] == "port_scan"
            and e["host_target"] == FIRST_HOST
        )
        err = next(
            e
            for e in events
            if e["event_type"] == "error"
            and e["stage"] == "port_scan"
            and e["host_target"] == FIRST_HOST
        )
        assert err["parent_span_id"] == cmd_exec["span_id"]

    def test_stage_complete_parents_to_command_exec(self, host_level_unexpected_exception_run):
        events = host_level_unexpected_exception_run["events"]
        cmd_exec = next(
            e
            for e in events
            if e["event_type"] == "command_exec"
            and e["stage"] == "port_scan"
            and e["host_target"] == FIRST_HOST
        )
        complete = next(
            e
            for e in events
            if e["event_type"] == "stage_complete"
            and e["stage"] == "port_scan"
            and e["host_target"] == FIRST_HOST
        )
        assert complete["parent_span_id"] == cmd_exec["span_id"]


# =======================================================================
# Host-level unexpected exception AFTER state_update — parents to state_update
# =======================================================================


@pytest.fixture()
def interpretation_non_llm_exception_run(config):
    """port_scan for TEST_HOST: planning + execution + parse + state_update
    all succeed; the interpretation LLM call then raises a non-LLMError
    exception, which propagates to the host-level broad catch.
    """
    llm = FakeLLMClient(
        [
            _good_port_scan_plan(),
            # Non-LLMError — slips past _run_interpretation's LLMError
            # catch and bubbles up to the host-level handler.
            RuntimeError("interp: non-llm explosion"),
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


class TestHostLevelExceptionAfterStateUpdate:
    def test_state_update_event_was_logged(self, interpretation_non_llm_exception_run):
        events = interpretation_non_llm_exception_run["events"]
        state_updates = [e for e in events if e["event_type"] == "state_update"]
        assert len(state_updates) == 1

    def test_error_event_parents_to_state_update(self, interpretation_non_llm_exception_run):
        events = interpretation_non_llm_exception_run["events"]
        state_update = next(e for e in events if e["event_type"] == "state_update")
        err = next(e for e in events if e["event_type"] == "error")
        assert err["error_type"] == "unexpected_exception"
        assert err["action_taken"] == "skip_host"
        assert err["parent_span_id"] == state_update["span_id"]

    def test_stage_complete_parents_to_state_update(self, interpretation_non_llm_exception_run):
        events = interpretation_non_llm_exception_run["events"]
        state_update = next(e for e in events if e["event_type"] == "state_update")
        complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert complete["success"] is False
        assert complete["skip_category"] == "post_attempt_skip"
        assert complete["reason"] == "unexpected_exception"
        assert complete["parent_span_id"] == state_update["span_id"]

    def test_state_errors_records_unexpected_exception(self, interpretation_non_llm_exception_run):
        errors = interpretation_non_llm_exception_run["state"].errors
        assert len(errors) == 1
        assert errors[0]["reason"] == "unexpected_exception"
        assert errors[0]["host"] == TEST_HOST


# =======================================================================
# Run-level unexpected exception (abort_pipeline)
# =======================================================================


@pytest.fixture()
def run_level_unexpected_exception_run(config, monkeypatch):
    """host_discovery runs; then the stage-loop entry raises. Pipeline aborts,
    report still generated, logger closed once.
    """
    llm = FakeLLMClient([_planning_response(), _interpretation_response()])
    tool = FakeToolExecutor(
        results=[(FIXTURES_DIR / "host_discovery.xml", _exec_result_ok(["/usr/bin/nmap", "-sn"]))],
        output_dir=Path(config.output_dir),
    )
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    def boom(stage):
        raise RuntimeError("boom: stage loop blew up at run level")

    monkeypatch.setattr(agent, "_run_per_host_stage_loop", boom)

    report_path = agent.run()

    events = _events_for_run(config, trace_id)
    return {
        "agent": agent,
        "llm": llm,
        "tool": tool,
        "events": events,
        "state": agent._state,
        "report_path": report_path,
    }


class TestRunLevelUnexpectedException:
    def test_abort_pipeline_error_logged(self, run_level_unexpected_exception_run):
        events = run_level_unexpected_exception_run["events"]
        errs = [
            e
            for e in events
            if e["event_type"] == "error" and e.get("action_taken") == "abort_pipeline"
        ]
        assert len(errs) == 1
        assert errs[0]["error_type"] == "unexpected_exception"

    def test_abort_error_attributed_to_current_stage(self, run_level_unexpected_exception_run):
        # The replacement stage runner raises before it can update
        # ``state.current_stage``. The abort should still record the stage
        # being attempted (``port_scan``), not the last stage that actually
        # ran to completion (``host_discovery``).
        events = run_level_unexpected_exception_run["events"]
        err = next(
            e
            for e in events
            if e["event_type"] == "error" and e.get("action_taken") == "abort_pipeline"
        )
        assert err["stage"] == "port_scan"
        state_errors = run_level_unexpected_exception_run["state"].errors
        abort_entries = [e for e in state_errors if e["reason"] == "unexpected_exception"]
        assert abort_entries[0]["stage"] == "port_scan"

    def test_no_stage_complete_synthesized_for_unfinished_units(
        self, run_level_unexpected_exception_run
    ):
        events = run_level_unexpected_exception_run["events"]
        per_host_complete = [
            e
            for e in events
            if e["event_type"] == "stage_complete"
            and e["stage"] in {"port_scan", "service_enum", "os_fingerprint"}
        ]
        assert per_host_complete == []

    def test_report_file_exists(self, run_level_unexpected_exception_run):
        assert Path(run_level_unexpected_exception_run["report_path"]).exists()

    def test_logger_closed(self, run_level_unexpected_exception_run):
        assert run_level_unexpected_exception_run["agent"]._logger._closed is True

    def test_state_errors_has_abort_entry(self, run_level_unexpected_exception_run):
        state_errors = run_level_unexpected_exception_run["state"].errors
        abort = [e for e in state_errors if e["reason"] == "unexpected_exception"]
        assert len(abort) == 1


# =======================================================================
# Logger close exactly once, even when report generation itself raises
# =======================================================================


@pytest.fixture()
def report_generation_failure_run(config, monkeypatch):
    llm = FakeLLMClient(_four_stage_llm_queue())
    tool = FakeToolExecutor(results=_four_stage_exec_queue(), output_dir=Path(config.output_dir))
    agent, logger = _build_agent(config, llm, tool)
    trace_id = logger.trace_id

    def explode(state, log_path, trace_id=None):
        raise RuntimeError("report generation blew up")

    monkeypatch.setattr(agent._report_generator, "generate", explode)

    close_calls = {"n": 0}
    real_close = logger.close

    def counting_close():
        close_calls["n"] += 1
        real_close()

    monkeypatch.setattr(logger, "close", counting_close)

    with pytest.raises(RuntimeError):
        agent.run()

    return {
        "agent": agent,
        "trace_id": trace_id,
        "close_calls": close_calls,
    }


class TestLoggerCloseExactlyOnceOnReportFailure:
    def test_logger_close_called_exactly_once(self, report_generation_failure_run):
        assert report_generation_failure_run["close_calls"]["n"] == 1
        assert report_generation_failure_run["agent"]._logger._closed is True


# =======================================================================
# Report always generated
# =======================================================================


class TestReportAlwaysGenerated:
    def test_report_generated_on_time_budget_overrun(self, time_budget_before_stage_run):
        path = Path(time_budget_before_stage_run["report_path"])
        assert path.exists()
        text = path.read_text()
        assert "Executive Summary" in text

    def test_log_file_has_expected_events_after_run_level_abort(
        self, run_level_unexpected_exception_run, config
    ):
        trace_id = run_level_unexpected_exception_run["agent"]._logger.trace_id
        events = [e for e in _read_log_events(config.log_file) if e.get("trace_id") == trace_id]
        stage_types = [
            e["event_type"] for e in events if e["event_type"] in {"stage_complete", "error"}
        ]
        assert "error" in stage_types
