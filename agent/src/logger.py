"""JSONL structured logging + stderr console output for the reconnaissance pipeline."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from config import AgentConfig

_EVENT_TYPE_TO_SURFACE: dict[str, str] = {
    "planning_call": "cognitive",
    "interpretation_call": "cognitive",
    "command_exec": "operational",
    "guardrail_violation": "operational",
    "stage_complete": "operational",
    "state_update": "contextual",
    "error": "contextual",
}

_VALID_EVENT_TYPES = set(_EVENT_TYPE_TO_SURFACE)

_RESERVED_KEYS = frozenset(
    {
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
)


class AgentLogger:
    """Dual-output structured logger: JSONL file + stderr one-liners."""

    def __init__(self, config: AgentConfig) -> None:
        now = datetime.now(timezone.utc)
        pid = os.getpid()
        self._trace_id = f"run_{now.strftime('%Y%m%d_%H%M%S')}_{pid}"
        self._span_counter = 0
        self._closed = False

        Path(config.log_file).parent.mkdir(parents=True, exist_ok=True)
        self._file: TextIO = open(config.log_file, "a")  # noqa: SIM115

    @property
    def trace_id(self) -> str:
        return self._trace_id

    def log_event(
        self,
        event_type: str,
        stage: str,
        data: dict,
        *,
        parent_span_id: str | None = None,
        stage_attempt: int = 1,
        host_target: str | None = None,
    ) -> str:
        if self._closed:
            msg = "Cannot log events after close()"
            raise RuntimeError(msg)

        if event_type not in _VALID_EVENT_TYPES:
            msg = f"Unknown event_type: {event_type}"
            raise ValueError(msg)

        collisions = _RESERVED_KEYS & data.keys()
        if collisions:
            msg = f"Data keys collide with reserved envelope keys: {collisions}"
            raise ValueError(msg)

        self._span_counter += 1
        span_id = f"span_{self._span_counter:03d}"

        envelope = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "trace_id": self._trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "surface": _EVENT_TYPE_TO_SURFACE[event_type],
            "event_type": event_type,
            "stage": stage,
            "stage_attempt": stage_attempt,
            "host_target": host_target,
        }

        event = {**envelope, **data}
        self._file.write(json.dumps(event) + "\n")
        self._file.flush()

        self._write_stderr(event_type, stage, data)

        return span_id

    def _write_stderr(self, event_type: str, stage: str, data: dict) -> None:
        formatters = {
            "planning_call": self._fmt_planning_call,
            "interpretation_call": self._fmt_interpretation_call,
            "command_exec": self._fmt_command_exec,
            "guardrail_violation": self._fmt_guardrail_violation,
            "stage_complete": self._fmt_stage_complete,
            "state_update": self._fmt_state_update,
            "error": self._fmt_error,
        }
        msg = formatters[event_type](stage, data)
        sys.stderr.write(msg + "\n")

    def close(self) -> None:
        if not self._closed:
            self._file.flush()
            self._file.close()
            self._closed = True

    # -- stderr formatters --------------------------------------------------

    @staticmethod
    def _fmt_planning_call(stage: str, data: dict) -> str:
        return f"[{stage}] Planning..."

    @staticmethod
    def _fmt_interpretation_call(stage: str, data: dict) -> str:
        return f"[{stage}] Interpreting results..."

    @staticmethod
    def _fmt_command_exec(stage: str, data: dict) -> str:
        cmd = data.get("command", [])
        cmd_str = " ".join(cmd) if cmd else "unknown"
        return f"[{stage}] Executing: {cmd_str}"

    @staticmethod
    def _fmt_guardrail_violation(stage: str, data: dict) -> str:
        rule = data.get("rule", "unknown")
        action = data.get("action_taken", "unknown")
        return f"[{stage}] GUARDRAIL: {rule} — {action}"

    @staticmethod
    def _fmt_stage_complete(stage: str, data: dict) -> str:
        count = data.get("findings_count", 0)
        success = data.get("success", False)
        status = "ok" if success else "FAILED"
        return f"[{stage}] Stage complete: {count} findings ({status})"

    @staticmethod
    def _fmt_state_update(stage: str, data: dict) -> str:
        return f"[{stage}] State updated"

    @staticmethod
    def _fmt_error(stage: str, data: dict) -> str:
        err_type = data.get("error_type", "unknown")
        err_msg = data.get("error_message", "")
        return f"[{stage}] ERROR: {err_type} — {err_msg}"
