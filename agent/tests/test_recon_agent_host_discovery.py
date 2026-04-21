"""Single-stage host-discovery happy-path tests for ReconAgent."""

from __future__ import annotations

import json

from agent import ReconAgent
from guardrails import Guardrails


class TestHostDiscoveryHappyPath:
    """Single-stage end-to-end for host_discovery."""

    def test_state_contains_discovered_hosts(self, host_discovery_run):
        state = host_discovery_run["state"]
        assert set(state.discovered_hosts.keys()) == {"192.168.56.1", "192.168.56.101"}

    def test_stages_completed_has_only_host_discovery(self, host_discovery_run):
        state = host_discovery_run["state"]
        assert state.stages_completed == ["host_discovery"]

    def test_current_stage_set_to_host_discovery_during_run(self, host_discovery_run):
        events = host_discovery_run["events"]
        planning = next(e for e in events if e["event_type"] == "planning_call")
        assert planning["stage"] == "host_discovery"
        state_update = next(e for e in events if e["event_type"] == "state_update")
        assert state_update["state_snapshot"]["current_stage"] == "host_discovery"

    def test_log_contains_all_pipeline_events(self, host_discovery_run):
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
        events = host_discovery_run["events"]
        cmd_exec = next(e for e in events if e["event_type"] == "command_exec")
        assert cmd_exec["command_source"] == "llm"

    def test_stage_complete_counters(self, host_discovery_run):
        events = host_discovery_run["events"]
        stage_complete = next(e for e in events if e["event_type"] == "stage_complete")
        assert stage_complete["success"] is True
        assert stage_complete["llm_calls"] == 2
        assert stage_complete["retries"] == 0
        assert stage_complete["mitre_technique"] == "T1595.001"

    def test_interpretation_not_stored_in_state(self, host_discovery_run):
        state = host_discovery_run["state"]
        snapshot_json = json.dumps(state.to_log_snapshot())
        assert "Discovered 2 hosts on the subnet." not in snapshot_json
        assert "Proceed with port scanning." not in snapshot_json

    def test_shared_guardrails_injected_into_executor(self, config):
        agent = ReconAgent(config)
        assert isinstance(agent._guardrails, Guardrails)
        assert agent._executor._guardrails is agent._guardrails

    def test_planning_call_uses_host_discovery_stage_config(self, host_discovery_run):
        llm = host_discovery_run["llm"]
        planning_record = llm.history[0]
        assert planning_record.stage_config is not None
        assert planning_record.stage_config.temperature == 0.0

    def test_host_discovery_executed_once(self, host_discovery_run):
        tool = host_discovery_run["tool"]
        assert len(tool.history) == 1
        assert "-sn" in tool.history[0].args
