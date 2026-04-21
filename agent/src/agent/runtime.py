"""Execution, interpretation, and stage-emission helpers for ReconAgent."""

from __future__ import annotations

import json
import time
from pathlib import Path

from config import StageConfig
from prompt_templates import INTERPRETATION_SCHEMA, build_interpretation_prompt
from report_generator import ReportGenerator
from tool_executor import CommandBlockedError, ExecutionResult

from .outcomes import HostStageOutcome, _host_kwargs
from .planning import _PlanResult

_PERMISSION_STDERR_MARKERS = (
    "requires root privileges",
    "operation not permitted",
    "permission denied",
)


def _execution_ok(result: ExecutionResult) -> bool:
    """Interpretation gate: the scan produced a readable XML output file."""
    if result.return_code != 0 or result.timed_out:
        return False
    if result.xml_output_path is None:
        return False
    return Path(result.xml_output_path).exists()


def _execution_error_type(result: ExecutionResult) -> str:
    if result.timed_out:
        return "nmap_timeout"
    stderr = (result.stderr or "").lower()
    if any(marker in stderr for marker in _PERMISSION_STDERR_MARKERS):
        return "permission_error"
    return "nmap_nonzero_exit"


def _compute_retries(planning_attempts: int, interpretation_attempts: int) -> int:
    return max(0, planning_attempts - 1) + max(0, interpretation_attempts - 1)


class _RuntimeMixin:
    """Execution / interpretation / skip-emission mixin for ReconAgent.

    Relies on the host class to provide `_executor`, `_logger`, `_llm`,
    `_state`, `_config`, and `_outcomes` attributes.
    """

    def _execute_and_log(
        self,
        *,
        stage: str,
        host: str | None,
        plan: _PlanResult,
        outcome: HostStageOutcome,
        stage_config: StageConfig,
        stage_start: float,
    ) -> tuple[ExecutionResult, str] | None:
        """Run the planned command and apply the interpretation gate.

        On a blocked command or a failed scan, logs an ``error`` event and
        emits a post-attempt skip via ``_emit_post_attempt_skip`` — then
        returns ``None`` so the caller stops before parsing/interpretation.
        On success, returns ``(result, command_exec_span_id)``.
        """
        host_kwargs = {"host_target": host} if host is not None else {}

        try:
            result = self._executor.execute_nmap(
                plan.args, plan.filename, timeout=stage_config.timeout_seconds
            )
        except CommandBlockedError as exc:
            self._logger.log_event(
                "error",
                stage,
                {
                    "error_type": "command_blocked",
                    "error_message": str(exc),
                    "recoverable": False,
                    "action_taken": "skip_interpretation",
                    "rule": exc.rule,
                },
                parent_span_id=plan.command_exec_parent,
                **host_kwargs,
            )
            self._emit_post_attempt_skip(
                stage=stage,
                host=host,
                reason="execution_failed",
                detail=f"command_blocked: {exc.rule}",
                outcome=outcome,
                parent_span=plan.command_exec_parent,
                stage_start=stage_start,
            )
            return None

        cmd_exec_span = self._logger.log_event(
            "command_exec",
            stage,
            {
                "command": result.command,
                "return_code": result.return_code,
                "stdout_preview": result.stdout[:500],
                "xml_output_path": result.xml_output_path,
                "duration_seconds": result.duration_seconds,
                "command_source": plan.command_source,
            },
            parent_span_id=plan.command_exec_parent,
            **host_kwargs,
        )

        if not _execution_ok(result):
            error_type = _execution_error_type(result)
            self._logger.log_event(
                "error",
                stage,
                {
                    "error_type": error_type,
                    "error_message": (result.stderr or "")[:500],
                    "recoverable": False,
                    "action_taken": "skip_interpretation",
                },
                parent_span_id=cmd_exec_span,
                **host_kwargs,
            )
            self._emit_post_attempt_skip(
                stage=stage,
                host=host,
                reason="execution_failed",
                detail=error_type,
                outcome=outcome,
                parent_span=cmd_exec_span,
                stage_start=stage_start,
            )
            return None

        outcome.execution_succeeded = True
        return result, cmd_exec_span

    def _emit_deterministic_skip(
        self,
        *,
        stage: str,
        host: str | None,
        reason: str,
        detail: str,
        stage_start: float,
        outcome: HostStageOutcome,
    ) -> None:
        """Emit a deterministic skip: no LLM was ever consulted for this unit.

        Counters are zero, there is no parent span, and one entry is added
        to ``state.errors`` so the report summary remains accurate.
        """
        self._state.errors.append(
            {"stage": stage, "host": host, "reason": reason, "detail": detail}
        )
        outcome.skipped_reason = reason
        outcome.skip_category = "deterministic_skip"
        outcome.duration_seconds = time.monotonic() - stage_start
        self._outcomes.append(outcome)

        mitre = ReportGenerator.STAGE_TO_MITRE[stage]
        self._logger.log_event(
            "stage_complete",
            stage,
            {
                "success": False,
                "findings_count": 0,
                "total_stage_duration_seconds": outcome.duration_seconds,
                "llm_calls": 0,
                "retries": 0,
                "mitre_technique": mitre["id"],
                "skip_category": "deterministic_skip",
                "reason": reason,
            },
            host_target=host,
        )

    def _emit_post_attempt_skip(
        self,
        *,
        stage: str,
        host: str | None,
        reason: str,
        detail: str | None,
        outcome: HostStageOutcome,
        parent_span: str | None,
        stage_start: float,
    ) -> None:
        """Emit a post-attempt skip: planning or execution was attempted but
        the unit ended without a successful state update.

        Counters reflect the actual planning (and interpretation, if any)
        invocations that took place. One entry is added to ``state.errors``.
        """
        self._state.errors.append(
            {"stage": stage, "host": host, "reason": reason, "detail": detail}
        )
        outcome.skipped_reason = reason
        outcome.skip_category = "post_attempt_skip"
        outcome.duration_seconds = time.monotonic() - stage_start
        self._outcomes.append(outcome)

        mitre = ReportGenerator.STAGE_TO_MITRE[stage]
        self._logger.log_event(
            "stage_complete",
            stage,
            {
                "success": False,
                "findings_count": 0,
                "total_stage_duration_seconds": outcome.duration_seconds,
                "llm_calls": outcome.planning_attempts + outcome.interpretation_attempts,
                "retries": _compute_retries(
                    outcome.planning_attempts, outcome.interpretation_attempts
                ),
                "mitre_technique": mitre["id"],
                "skip_category": "post_attempt_skip",
                "reason": reason,
            },
            parent_span_id=parent_span,
            host_target=host,
        )

    def _log_state_update(
        self,
        *,
        stage: str,
        host: str | None,
        delta: dict,
        parent_span: str,
    ) -> str:
        return self._logger.log_event(
            "state_update",
            stage,
            {
                "update_source": "tool_parser",
                "state_delta": delta,
                "state_snapshot": self._state.to_log_snapshot(),
            },
            parent_span_id=parent_span,
            **_host_kwargs(host),
        )

    def _run_interpretation(
        self,
        *,
        stage: str,
        host: str | None,
        prompt_context: str,
        parsed: object,
        target_info: str | None,
        parent_span: str,
        outcome: HostStageOutcome,
    ) -> str:
        interp_messages = build_interpretation_prompt(
            stage,
            prompt_context,
            json.dumps(parsed),
            self._config,
            current_target_info=target_info,
        )
        interp = self._llm.call(interp_messages, INTERPRETATION_SCHEMA)
        outcome.interpretation_attempts = 1
        interp_span = self._logger.log_event(
            "interpretation_call",
            stage,
            {
                "llm_input": {"messages": interp_messages},
                "llm_output": {
                    "parsed": interp.parsed,
                    "raw_content": interp.raw_content,
                },
            },
            parent_span_id=parent_span,
            **_host_kwargs(host),
        )
        outcome.interpretation_succeeded = True
        return interp_span

    def _emit_stage_success(
        self,
        *,
        stage: str,
        host: str | None,
        outcome: HostStageOutcome,
        parent_span: str,
        stage_start: float,
    ) -> None:
        outcome.duration_seconds = time.monotonic() - stage_start
        self._outcomes.append(outcome)

        mitre = ReportGenerator.STAGE_TO_MITRE[stage]
        self._logger.log_event(
            "stage_complete",
            stage,
            {
                "success": True,
                "findings_count": outcome.findings_count,
                "total_stage_duration_seconds": outcome.duration_seconds,
                "llm_calls": outcome.planning_attempts + outcome.interpretation_attempts,
                "retries": _compute_retries(
                    outcome.planning_attempts, outcome.interpretation_attempts
                ),
                "mitre_technique": mitre["id"],
            },
            parent_span_id=parent_span,
            **_host_kwargs(host),
        )
