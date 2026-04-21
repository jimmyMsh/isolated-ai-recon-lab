"""Multi-host orchestration and zero-host-discovered pipeline-flow tests."""

from __future__ import annotations

from pathlib import Path

from .recon_agent_test_support import EXPECTED_HOSTS


class TestMultiHostOrchestration:
    """Per-host iteration across port_scan, service_enum, os_fingerprint."""

    def test_run_returns_existing_report_path(self, multi_host_run):
        report_path = multi_host_run["report_path"]
        assert isinstance(report_path, str)
        assert Path(report_path).exists()

    def test_report_references_trace_id(self, multi_host_run):
        trace_id = multi_host_run["trace_id"]
        report_path = multi_host_run["report_path"]
        assert trace_id in Path(report_path).name

    def test_logger_closed_after_run(self, multi_host_run):
        agent = multi_host_run["agent"]
        assert agent._logger._closed is True

    def test_stages_completed_has_exactly_one_entry_per_stage(self, multi_host_run):
        state = multi_host_run["state"]
        assert state.stages_completed == [
            "host_discovery",
            "port_scan",
            "service_enum",
            "os_fingerprint",
        ]

    def test_stage_complete_emitted_per_host_for_per_host_stages(self, multi_host_run):
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
        events = multi_host_run["events"]
        per_host_stages = {"port_scan", "service_enum", "os_fingerprint"}
        for event in events:
            if event["stage"] in per_host_stages:
                assert event["host_target"] in EXPECTED_HOSTS, (
                    f"{event['event_type']} for {event['stage']} missing host_target"
                )

    def test_hosts_iterated_in_sorted_order(self, multi_host_run):
        events = multi_host_run["events"]
        for stage in ("port_scan", "service_enum", "os_fingerprint"):
            stage_completes = [
                e for e in events if e["event_type"] == "stage_complete" and e["stage"] == stage
            ]
            hosts_in_order = [e["host_target"] for e in stage_completes]
            assert hosts_in_order == sorted(EXPECTED_HOSTS)

    def test_current_target_lifecycle(self, multi_host_run):
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
        state = multi_host_run["state"]
        assert state.current_target is None
        assert state.current_stage == "report"

    def test_per_host_state_updates_scoped_to_current_host(self, multi_host_run):
        state = multi_host_run["state"]
        for ip in EXPECTED_HOSTS:
            host = state.discovered_hosts[ip]
            assert host.open_ports, f"{ip} missing ports"
            assert host.services, f"{ip} missing services"
            assert host.os_matches, f"{ip} missing OS matches"

    def test_stage_complete_parent_is_interpretation(self, multi_host_run):
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
        assert len(multi_host_run["tool"].history) == 7
        assert len(multi_host_run["llm"].history) == 14

    def test_state_errors_empty_on_happy_path(self, multi_host_run):
        assert multi_host_run["state"].errors == []


class TestZeroHostsDiscovered:
    """Per-host stages deterministic-skip when host_discovery finds no hosts."""

    def test_stages_completed_still_has_all_four(self, zero_hosts_run):
        state = zero_hosts_run["state"]
        assert state.stages_completed == [
            "host_discovery",
            "port_scan",
            "service_enum",
            "os_fingerprint",
        ]

    def test_skipped_stage_complete_events_deterministic_skip(self, zero_hosts_run):
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
        errors = zero_hosts_run["state"].errors
        stages = [e["stage"] for e in errors]
        assert stages == ["port_scan", "service_enum", "os_fingerprint"]
        for entry in errors:
            assert entry["reason"] == "no_hosts_discovered"
            assert entry["host"] is None

    def test_no_per_host_llm_or_executor_calls(self, zero_hosts_run):
        assert len(zero_hosts_run["llm"].history) == 2
        assert len(zero_hosts_run["tool"].history) == 1

    def test_report_still_generated(self, zero_hosts_run):
        report_path = zero_hosts_run["report_path"]
        assert Path(report_path).exists()
