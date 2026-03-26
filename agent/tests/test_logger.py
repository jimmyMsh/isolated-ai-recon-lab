"""Tests for logger module — JSONL structured logging + stderr console output."""

from __future__ import annotations

import json
import re

import pytest

from config import AgentConfig
from logger import AgentLogger


@pytest.fixture()
def config(tmp_path):
    return AgentConfig(
        ollama_url="http://localhost:11434",
        model="qwen3:8b",
        target_subnet="192.168.56.0/24",
        attacker_ip="192.168.56.10",
        nmap_path="/usr/bin/nmap",
        output_dir=str(tmp_path),
        log_file=str(tmp_path / "agent.log.jsonl"),
    )


@pytest.fixture()
def logger(config):
    lg = AgentLogger(config)
    yield lg
    lg.close()


def _read_events(config) -> list[dict]:
    """Read all JSONL events from the log file."""
    with open(config.log_file) as f:
        return [json.loads(line) for line in f if line.strip()]


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


class TestEnvelope:
    _ENVELOPE_KEYS = {
        "timestamp",
        "trace_id",
        "span_id",
        "parent_span_id",
        "surface",
        "event_type",
        "stage",
        "stage_attempt",
        "host_target",
    }

    def test_envelope_has_all_required_fields(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {})
        event = _read_events(config)[0]
        assert self._ENVELOPE_KEYS.issubset(event.keys())

    def test_timestamp_is_iso8601_utc(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {})
        event = _read_events(config)[0]
        ts = event["timestamp"]
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts)
        assert "+00:00" in ts or ts.endswith("Z")

    def test_trace_id_format(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {})
        event = _read_events(config)[0]
        assert re.match(r"^run_\d{8}_\d{6}_\d+$", event["trace_id"])

    def test_trace_id_includes_pid_for_uniqueness(self, logger, config):
        import os

        logger.log_event("planning_call", "host_discovery", {})
        event = _read_events(config)[0]
        assert event["trace_id"].endswith(f"_{os.getpid()}")

    def test_trace_id_stable_across_calls(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {})
        logger.log_event("command_exec", "host_discovery", {})
        events = _read_events(config)
        assert events[0]["trace_id"] == events[1]["trace_id"]

    def test_span_id_format_and_auto_increment(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {})
        logger.log_event("command_exec", "host_discovery", {})
        events = _read_events(config)
        assert events[0]["span_id"] == "span_001"
        assert events[1]["span_id"] == "span_002"

    def test_span_id_returned_by_log_event(self, logger):
        span = logger.log_event("planning_call", "host_discovery", {})
        assert re.match(r"^span_\d{3}$", span)

    def test_parent_span_id_defaults_to_none(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {})
        event = _read_events(config)[0]
        assert event["parent_span_id"] is None

    def test_parent_span_id_passed_through(self, logger, config):
        logger.log_event("command_exec", "host_discovery", {}, parent_span_id="span_001")
        event = _read_events(config)[0]
        assert event["parent_span_id"] == "span_001"

    def test_stage_attempt_defaults_to_1(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {})
        event = _read_events(config)[0]
        assert event["stage_attempt"] == 1

    def test_stage_attempt_accepts_caller_value(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {}, stage_attempt=3)
        event = _read_events(config)[0]
        assert event["stage_attempt"] == 3

    def test_host_target_defaults_to_none(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {})
        event = _read_events(config)[0]
        assert event["host_target"] is None

    def test_host_target_accepts_ip_string(self, logger, config):
        logger.log_event("planning_call", "port_scan", {}, host_target="192.168.56.101")
        event = _read_events(config)[0]
        assert event["host_target"] == "192.168.56.101"


# ---------------------------------------------------------------------------
# Surface mapping
# ---------------------------------------------------------------------------


class TestSurfaceMapping:
    @pytest.mark.parametrize(
        ("event_type", "expected_surface"),
        [
            ("planning_call", "cognitive"),
            ("interpretation_call", "cognitive"),
            ("command_exec", "operational"),
            ("guardrail_violation", "operational"),
            ("stage_complete", "operational"),
            ("state_update", "contextual"),
            ("error", "contextual"),
        ],
    )
    def test_event_type_maps_to_correct_surface(self, logger, config, event_type, expected_surface):
        logger.log_event(event_type, "host_discovery", {})
        event = _read_events(config)[0]
        assert event["surface"] == expected_surface


# ---------------------------------------------------------------------------
# Data field
# ---------------------------------------------------------------------------


class TestDataField:
    def test_data_dict_merged_into_event(self, logger, config):
        logger.log_event(
            "command_exec",
            "host_discovery",
            {"command": ["nmap", "-sn", "192.168.56.0/24"], "return_code": 0},
        )
        event = _read_events(config)[0]
        assert event["command"] == ["nmap", "-sn", "192.168.56.0/24"]
        assert event["return_code"] == 0

    def test_empty_data_dict(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {})
        events = _read_events(config)
        assert len(events) == 1


# ---------------------------------------------------------------------------
# JSONL output
# ---------------------------------------------------------------------------


class TestJSONLOutput:
    def test_one_line_per_event(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {})
        logger.log_event("command_exec", "host_discovery", {})
        logger.log_event("stage_complete", "host_discovery", {})
        with open(config.log_file) as f:
            lines = [line for line in f if line.strip()]
        assert len(lines) == 3

    def test_each_line_is_valid_json(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {})
        logger.log_event("error", "port_scan", {"error_type": "llm_timeout"})
        with open(config.log_file) as f:
            for line in f:
                if line.strip():
                    json.loads(line)  # Raises on invalid JSON

    def test_file_at_config_log_file_path(self, logger, config):
        logger.log_event("planning_call", "host_discovery", {})
        from pathlib import Path

        assert Path(config.log_file).exists()

    def test_output_dir_created_if_missing(self, tmp_path):
        nested = tmp_path / "deep" / "nested"
        cfg = AgentConfig(
            ollama_url="http://localhost:11434",
            model="qwen3:8b",
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
            nmap_path="/usr/bin/nmap",
            output_dir=str(nested),
            log_file=str(nested / "agent.log.jsonl"),
        )
        lg = AgentLogger(cfg)
        lg.log_event("planning_call", "host_discovery", {})
        lg.close()
        assert nested.exists()
        events = _read_events(cfg)
        assert len(events) == 1

    def test_append_mode(self, config):
        lg1 = AgentLogger(config)
        lg1.log_event("planning_call", "host_discovery", {})
        lg1.close()

        lg2 = AgentLogger(config)
        lg2.log_event("command_exec", "host_discovery", {})
        lg2.close()

        events = _read_events(config)
        assert len(events) == 2
        assert events[0]["event_type"] == "planning_call"
        assert events[1]["event_type"] == "command_exec"


# ---------------------------------------------------------------------------
# Stderr output
# ---------------------------------------------------------------------------


class TestStderrOutput:
    def test_planning_call_stderr(self, logger, capsys):
        logger.log_event("planning_call", "host_discovery", {})
        err = capsys.readouterr().err
        assert "[host_discovery]" in err
        assert "Planning" in err

    def test_command_exec_stderr(self, logger, capsys):
        logger.log_event(
            "command_exec",
            "port_scan",
            {"command": ["nmap", "-sS", "192.168.56.101"]},
        )
        err = capsys.readouterr().err
        assert "[port_scan]" in err
        assert "nmap" in err

    def test_stage_complete_stderr(self, logger, capsys):
        logger.log_event(
            "stage_complete",
            "port_scan",
            {"success": True, "findings_count": 25},
        )
        err = capsys.readouterr().err
        assert "[port_scan]" in err
        assert "25" in err

    def test_error_stderr(self, logger, capsys):
        logger.log_event(
            "error",
            "port_scan",
            {"error_type": "llm_timeout", "error_message": "connection refused"},
        )
        err = capsys.readouterr().err
        assert "[port_scan]" in err
        assert "llm_timeout" in err

    def test_guardrail_violation_stderr(self, logger, capsys):
        logger.log_event(
            "guardrail_violation",
            "port_scan",
            {
                "rule": "target_outside_subnet",
                "detail": "10.0.0.1 not in subnet",
                "action_taken": "retry_planning",
            },
        )
        err = capsys.readouterr().err
        assert "[port_scan]" in err
        assert "target_outside_subnet" in err
        assert "retry_planning" in err

    def test_state_update_stderr(self, logger, capsys):
        logger.log_event("state_update", "host_discovery", {"update_source": "tool_parser"})
        err = capsys.readouterr().err
        assert "[host_discovery]" in err
        assert "State updated" in err

    def test_interpretation_call_stderr(self, logger, capsys):
        logger.log_event("interpretation_call", "port_scan", {})
        err = capsys.readouterr().err
        assert "[port_scan]" in err
        assert "Interpreting" in err


# ---------------------------------------------------------------------------
# Close
# ---------------------------------------------------------------------------


class TestClose:
    def test_close_flushes_file(self, config):
        lg = AgentLogger(config)
        lg.log_event("planning_call", "host_discovery", {})
        lg.close()
        events = _read_events(config)
        assert len(events) == 1

    def test_close_idempotent(self, config):
        lg = AgentLogger(config)
        lg.log_event("planning_call", "host_discovery", {})
        lg.close()
        lg.close()  # Should not raise

    def test_log_after_close_raises(self, config):
        lg = AgentLogger(config)
        lg.log_event("planning_call", "host_discovery", {})
        lg.close()
        with pytest.raises(RuntimeError, match="close"):
            lg.log_event("command_exec", "host_discovery", {})


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_unknown_event_type_raises_value_error(self, logger):
        with pytest.raises(ValueError, match="unknown_type"):
            logger.log_event("unknown_type", "host_discovery", {})

    def test_non_serializable_data_raises(self, logger):
        with pytest.raises(TypeError):
            logger.log_event("planning_call", "host_discovery", {"bad": object()})

    def test_nested_data_structures_serialize(self, logger, config):
        logger.log_event(
            "state_update",
            "host_discovery",
            {
                "state_delta": {"hosts_added": ["192.168.56.101"]},
                "state_snapshot": {"hosts": {"192.168.56.101": {"ports": [22, 80, 443]}}},
            },
        )
        event = _read_events(config)[0]
        assert event["state_delta"]["hosts_added"] == ["192.168.56.101"]
        assert event["state_snapshot"]["hosts"]["192.168.56.101"]["ports"] == [
            22,
            80,
            443,
        ]


# ---------------------------------------------------------------------------
# Reserved keys
# ---------------------------------------------------------------------------


class TestReservedKeys:
    def test_data_collision_with_reserved_key_raises(self, logger):
        with pytest.raises(ValueError, match="timestamp"):
            logger.log_event(
                "planning_call",
                "host_discovery",
                {"timestamp": "bogus", "extra": 1},
            )

    def test_non_colliding_payload_fields_remain_top_level(self, logger, config):
        logger.log_event(
            "command_exec",
            "host_discovery",
            {"command": ["nmap", "-sn"], "return_code": 0},
        )
        event = _read_events(config)[0]
        assert event["command"] == ["nmap", "-sn"]
        assert event["return_code"] == 0
        assert "timestamp" in event  # envelope key still present


# ---------------------------------------------------------------------------
# Spec examples — representative payload shapes from logging-and-reporting-spec
# ---------------------------------------------------------------------------


class TestSpecExamples:
    def test_planning_call_payload(self, logger, config):
        logger.log_event(
            "planning_call",
            "host_discovery",
            {
                "llm_input": {
                    "messages": [{"role": "system", "content": "You are..."}],
                    "schema_name": "planning",
                    "options": {"temperature": 0, "top_p": 1.0, "num_ctx": 8192},
                },
                "llm_output": {
                    "raw_content": '{"tool": "nmap"}',
                    "parsed": {"tool": "nmap"},
                    "thinking": None,
                },
                "duration_seconds": 3.2,
            },
        )
        event = _read_events(config)[0]
        assert event["llm_input"]["schema_name"] == "planning"
        assert event["llm_output"]["thinking"] is None
        assert event["duration_seconds"] == 3.2

    def test_interpretation_call_payload(self, logger, config):
        logger.log_event(
            "interpretation_call",
            "port_scan",
            {
                "llm_input": {
                    "messages": [{"role": "user", "content": "Analyze..."}],
                    "schema_name": "interpretation",
                    "options": {"temperature": 0.7, "top_p": 0.8, "num_ctx": 8192},
                },
                "llm_output": {
                    "raw_content": '{"summary": "found ports"}',
                    "parsed": {"summary": "found ports"},
                    "thinking": None,
                },
                "duration_seconds": 2.1,
            },
        )
        event = _read_events(config)[0]
        assert event["surface"] == "cognitive"
        assert event["llm_input"]["schema_name"] == "interpretation"

    def test_command_exec_payload(self, logger, config):
        logger.log_event(
            "command_exec",
            "port_scan",
            {
                "command": ["nmap", "-sS", "-T4", "-p-", "--open", "-oX", "out.xml"],
                "command_source": "llm",
                "return_code": 0,
                "stdout_preview": "Starting Nmap...",
                "stderr": "",
                "xml_output_path": "./output/port_scan_192.168.56.101_20260315.xml",
                "duration_seconds": 22.4,
                "timed_out": False,
            },
            host_target="192.168.56.101",
        )
        event = _read_events(config)[0]
        assert event["command_source"] == "llm"
        assert event["timed_out"] is False
        assert event["host_target"] == "192.168.56.101"

    def test_guardrail_violation_payload(self, logger, config):
        logger.log_event(
            "guardrail_violation",
            "port_scan",
            {
                "rule": "target_outside_subnet",
                "detail": "10.0.0.1 is not in 192.168.56.0/24",
                "action_taken": "retry_planning",
                "original_llm_output": {"target": "10.0.0.1"},
            },
        )
        event = _read_events(config)[0]
        assert event["rule"] == "target_outside_subnet"
        assert event["action_taken"] == "retry_planning"

    def test_stage_complete_payload(self, logger, config):
        logger.log_event(
            "stage_complete",
            "port_scan",
            {
                "success": True,
                "findings_count": 23,
                "total_stage_duration_seconds": 28.7,
                "llm_calls": 2,
                "retries": 0,
                "mitre_technique": "T1046",
            },
        )
        event = _read_events(config)[0]
        assert event["success"] is True
        assert event["findings_count"] == 23
        assert event["mitre_technique"] == "T1046"

    def test_state_update_payload(self, logger, config):
        logger.log_event(
            "state_update",
            "host_discovery",
            {
                "update_source": "tool_parser",
                "state_delta": {
                    "hosts_added": ["192.168.56.101"],
                    "ports_added": {},
                    "services_added": {},
                    "os_matches_added": {},
                },
                "state_snapshot": {"discovered_hosts": {"192.168.56.101": {}}},
            },
        )
        event = _read_events(config)[0]
        assert event["update_source"] == "tool_parser"
        assert "192.168.56.101" in event["state_delta"]["hosts_added"]

    def test_error_payload(self, logger, config):
        logger.log_event(
            "error",
            "port_scan",
            {
                "error_type": "nmap_timeout",
                "error_message": "nmap timed out after 120s",
                "recoverable": True,
                "action_taken": "retry_after_3s",
            },
        )
        event = _read_events(config)[0]
        assert event["error_type"] == "nmap_timeout"
        assert event["recoverable"] is True
        assert event["action_taken"] == "retry_after_3s"


# ---------------------------------------------------------------------------
# Error provenance — logger must not infer error types from data shapes
# ---------------------------------------------------------------------------


class TestErrorProvenance:
    def test_xml_parse_error_only_when_explicitly_passed(self, logger, config):
        """Logger records xml_parse_error only when the caller provides it.

        An empty-result-shaped payload must NOT cause the logger to infer or
        inject an error event/field. Error types come from the caller.
        """
        logger.log_event(
            "error",
            "port_scan",
            {
                "error_type": "xml_parse_error",
                "error_message": "Failed to parse XML output",
                "recoverable": True,
                "action_taken": "use_fallback",
            },
        )
        event = _read_events(config)[0]
        assert event["error_type"] == "xml_parse_error"

        # An empty state_update must NOT get rewritten to an error
        logger.log_event(
            "state_update",
            "port_scan",
            {
                "update_source": "tool_parser",
                "state_delta": {
                    "hosts_added": [],
                    "ports_added": {},
                    "services_added": {},
                    "os_matches_added": {},
                },
                "state_snapshot": {},
            },
        )
        events = _read_events(config)
        last = events[-1]
        assert last["event_type"] == "state_update"
        assert "error_type" not in last
