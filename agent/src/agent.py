"""ReconAgent — pipeline orchestrator for the reconnaissance agent."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from command_builder import CommandBuilder
from config import AgentConfig, StageConfig
from guardrails import Guardrails, GuardrailViolation
from llm_client import LLMClient, LLMError
from logger import AgentLogger
from prompt_templates import (
    INTERPRETATION_SCHEMA,
    PLANNING_SCHEMA,
    build_interpretation_prompt,
    build_planning_prompt,
)
from report_generator import ReportGenerator
from state import AgentState
from tool_executor import CommandBlockedError, ExecutionResult, ToolExecutor
from tool_parser import NmapParser

_MAX_RETRY_SNIPPET_CHARS = 250
_PERMISSION_STDERR_MARKERS = (
    "requires root privileges",
    "operation not permitted",
    "permission denied",
)


@dataclass
class HostStageOutcome:
    """Ephemeral per-host-stage orchestration metadata.

    Lives only in the orchestrator. Never fed back into AgentState or into
    any LLM prompt.
    """

    stage: str
    host: str | None = None
    planning_attempts: int = 0
    interpretation_attempts: int = 0
    used_fallback: bool = False
    execution_succeeded: bool = False
    skipped_reason: str | None = None
    skip_category: str | None = None
    interpretation_succeeded: bool = False
    findings_count: int = 0
    duration_seconds: float = 0.0


@dataclass
class _PlanResult:
    """Outcome of the planning step.

    A successful LLM plan (possibly after retries) and a deterministic
    fallback both resolve to `args`/`filename` with a `command_source` tag.
    When a fallback is required but cannot be built (e.g. service_enum with
    no known open ports), `skip_reason` is set and `args`/`filename` are
    left None so the caller emits a post-attempt skip instead of executing.
    """

    args: list[str] | None = None
    filename: str | None = None
    command_source: str = "llm"
    command_exec_parent: str | None = None
    planning_attempts: int = 0
    used_fallback: bool = False
    skip_reason: str | None = None
    skip_detail: str | None = None
    skip_parent: str | None = None


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


class ReconAgent:
    _PARSERS = {
        "port_scan": NmapParser.parse_port_scan,
        "service_enum": NmapParser.parse_service_enum,
        "os_fingerprint": NmapParser.parse_os_fingerprint,
    }

    def __init__(
        self,
        config: AgentConfig,
        *,
        llm_client: LLMClient | None = None,
        tool_executor: ToolExecutor | None = None,
        logger: AgentLogger | None = None,
    ) -> None:
        self._config = config
        self._state = AgentState(
            target_subnet=config.target_subnet,
            attacker_ip=config.attacker_ip,
        )
        self._guardrails = Guardrails(config)
        self._llm = llm_client or LLMClient(config)
        self._executor = tool_executor or ToolExecutor(config, self._guardrails)
        self._command_builder = CommandBuilder(config)
        self._logger = logger or AgentLogger(config)
        self._report_generator = ReportGenerator(config)
        self._outcomes: list[HostStageOutcome] = []
        self._start_monotonic: float = 0.0

    def run(self) -> str:
        self._start_monotonic = time.monotonic()
        try:
            self._run_host_discovery()
            for stage in ("port_scan", "service_enum", "os_fingerprint"):
                self._run_per_host_stage_loop(stage)
        finally:
            try:
                self._state.current_stage = "report"
                self._state.current_target = None
                report_path = self._report_generator.generate(
                    self._state,
                    self._config.log_file,
                    trace_id=self._logger.trace_id,
                )
            finally:
                self._logger.close()
        return report_path

    # -- host_discovery stage ------------------------------------------------

    def _run_host_discovery(self) -> None:
        stage = "host_discovery"
        self._state.current_stage = stage
        stage_start = time.monotonic()
        outcome = HostStageOutcome(stage=stage)
        stage_config = self._stage_config(stage)
        prompt_context = self._state.to_prompt_context()

        plan = self._plan(
            stage=stage,
            host=None,
            prompt_context=prompt_context,
            target_info=None,
            stage_config=stage_config,
        )
        outcome.planning_attempts = plan.planning_attempts
        outcome.used_fallback = plan.used_fallback

        if plan.skip_reason is not None:
            self._emit_post_attempt_skip(
                stage=stage,
                host=None,
                reason=plan.skip_reason,
                detail=plan.skip_detail,
                outcome=outcome,
                parent_span=plan.skip_parent,
                stage_start=stage_start,
            )
            self._state.stages_completed.append(stage)
            return

        cmd_outcome = self._execute_and_log(
            stage=stage,
            host=None,
            plan=plan,
            outcome=outcome,
            stage_config=stage_config,
            stage_start=stage_start,
        )
        if cmd_outcome is None:
            self._state.stages_completed.append(stage)
            return
        result, cmd_exec_span = cmd_outcome

        parsed = NmapParser.parse_host_discovery(Path(result.xml_output_path))
        delta = self._state.update_from_discovery(parsed)
        state_update_span = self._logger.log_event(
            "state_update",
            stage,
            {
                "update_source": "tool_parser",
                "state_delta": delta,
                "state_snapshot": self._state.to_log_snapshot(),
            },
            parent_span_id=cmd_exec_span,
        )
        outcome.findings_count = len(self._state.discovered_hosts)

        interp_messages = build_interpretation_prompt(
            stage,
            self._state.to_prompt_context(),
            json.dumps(parsed),
            self._config,
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
            parent_span_id=state_update_span,
        )
        outcome.interpretation_succeeded = True

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
            parent_span_id=interp_span,
        )
        self._state.stages_completed.append(stage)

    # -- per-host stages -----------------------------------------------------

    def _run_per_host_stage_loop(self, stage: str) -> None:
        self._state.current_stage = stage
        hosts = sorted(self._state.get_target_ips())
        if not hosts:
            self._skip_stage_no_hosts(stage)
        else:
            for host in hosts:
                self._run_per_host_stage(stage, host)
            self._state.current_target = None
        self._state.stages_completed.append(stage)

    def _run_per_host_stage(self, stage: str, host: str) -> None:
        self._state.current_target = host
        stage_start = time.monotonic()
        outcome = HostStageOutcome(stage=stage, host=host)
        stage_config = self._stage_config(stage)
        target_info = f"Current scan target: {host}"
        prompt_context = self._build_prompt_context(stage, host)

        # Pre-planning deterministic skip: service_enum with no known ports.
        # Without a port list, -sV would fall back to nmap's default ~1000
        # ports — contradictory to the pipeline's "scan what was discovered"
        # contract. Skip cleanly without burning an LLM call.
        if stage == "service_enum" and not self._state.get_open_ports_csv(host):
            self._emit_deterministic_skip(
                stage=stage,
                host=host,
                reason="no_known_ports",
                detail=f"No known open ports for {host} — service_enum skipped.",
                stage_start=stage_start,
                outcome=outcome,
            )
            return

        plan = self._plan(
            stage=stage,
            host=host,
            prompt_context=prompt_context,
            target_info=target_info,
            stage_config=stage_config,
        )
        outcome.planning_attempts = plan.planning_attempts
        outcome.used_fallback = plan.used_fallback

        if plan.skip_reason is not None:
            self._emit_post_attempt_skip(
                stage=stage,
                host=host,
                reason=plan.skip_reason,
                detail=plan.skip_detail,
                outcome=outcome,
                parent_span=plan.skip_parent,
                stage_start=stage_start,
            )
            return

        cmd_outcome = self._execute_and_log(
            stage=stage,
            host=host,
            plan=plan,
            outcome=outcome,
            stage_config=stage_config,
            stage_start=stage_start,
        )
        if cmd_outcome is None:
            return
        result, cmd_exec_span = cmd_outcome

        parser = self._PARSERS[stage]
        parsed = parser(Path(result.xml_output_path))

        updater = {
            "port_scan": self._state.update_from_port_scan,
            "service_enum": self._state.update_from_service_enum,
            "os_fingerprint": self._state.update_from_os_fingerprint,
        }[stage]
        delta = updater(host, parsed)
        state_update_span = self._logger.log_event(
            "state_update",
            stage,
            {
                "update_source": "tool_parser",
                "state_delta": delta,
                "state_snapshot": self._state.to_log_snapshot(),
            },
            parent_span_id=cmd_exec_span,
            host_target=host,
        )
        outcome.findings_count = self._findings_count(stage, host)

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
            parent_span_id=state_update_span,
            host_target=host,
        )
        outcome.interpretation_succeeded = True

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
            parent_span_id=interp_span,
            host_target=host,
        )

    def _skip_stage_no_hosts(self, stage: str) -> None:
        outcome = HostStageOutcome(
            stage=stage,
            host=None,
            skipped_reason="no_hosts_discovered",
            skip_category="deterministic_skip",
        )
        self._outcomes.append(outcome)
        self._state.errors.append(
            {
                "stage": stage,
                "host": None,
                "reason": "no_hosts_discovered",
                "detail": "host_discovery returned zero live hosts",
            }
        )
        mitre = ReportGenerator.STAGE_TO_MITRE[stage]
        self._logger.log_event(
            "stage_complete",
            stage,
            {
                "success": False,
                "findings_count": 0,
                "total_stage_duration_seconds": 0.0,
                "llm_calls": 0,
                "retries": 0,
                "mitre_technique": mitre["id"],
                "skip_category": "deterministic_skip",
                "reason": "no_hosts_discovered",
            },
        )

    # -- planning (LLM retry + deterministic fallback) -----------------------

    def _plan(
        self,
        *,
        stage: str,
        host: str | None,
        prompt_context: str,
        target_info: str | None,
        stage_config: StageConfig,
    ) -> _PlanResult:
        """Plan a scan with retry + fallback for a single host-stage unit.

        Handles both `LLMError` and `GuardrailViolation` under a shared
        retry budget of `1 + stage_config.max_retries` total planning
        attempts. On exhaustion it calls `command_builder.build_fallback`.
        If the fallback cannot be constructed (for example, `service_enum`
        with no known open ports for `host`), the resulting `ValueError`
        is captured into `_PlanResult.skip_reason` so the caller emits a
        post-attempt skip instead of executing.
        """
        max_attempts = 1 + stage_config.max_retries
        original_messages = build_planning_prompt(
            stage, prompt_context, self._config, current_target_info=target_info
        )

        planning_attempts = 0
        last_planning_span: str | None = None
        last_violation_span: str | None = None
        last_violation_snippet: str | None = None

        for attempt in range(1, max_attempts + 1):
            messages = self._build_planning_messages(
                original_messages, attempt, last_violation_snippet
            )
            planning_attempts += 1
            try:
                planning = self._llm.call(messages, PLANNING_SCHEMA, stage_config=stage_config)
            except LLMError:
                # No response produced; nothing to log for this attempt, and
                # no correction snippet carries forward from a failed call.
                last_violation_snippet = None
                continue

            planning_span = self._logger.log_event(
                "planning_call",
                stage,
                {
                    "llm_input": {"messages": messages},
                    "llm_output": {
                        "parsed": planning.parsed,
                        "raw_content": planning.raw_content,
                    },
                },
                stage_attempt=attempt,
                host_target=host,
            )
            last_planning_span = planning_span

            try:
                validated = self._guardrails.validate_planning_response(stage, planning.parsed)
            except GuardrailViolation as gv:
                action = "retry_planning" if attempt < max_attempts else "use_fallback"
                snippet = f"[{gv.rule}] {gv.detail}"[:_MAX_RETRY_SNIPPET_CHARS]
                last_violation_snippet = snippet
                last_violation_span = self._logger.log_event(
                    "guardrail_violation",
                    stage,
                    {
                        "rule": gv.rule,
                        "detail": gv.detail,
                        "action_taken": action,
                        "original_output": planning.parsed,
                    },
                    parent_span_id=planning_span,
                    stage_attempt=attempt,
                    host_target=host,
                )
                continue

            args, filename = self._command_builder.build(stage, validated, self._state)
            return _PlanResult(
                args=args,
                filename=filename,
                command_source="llm",
                command_exec_parent=planning_span,
                planning_attempts=planning_attempts,
                used_fallback=False,
            )

        # Planning exhausted — attempt a deterministic fallback command.
        try:
            args, filename = self._command_builder.build_fallback(
                stage, self._state, target_ip=host
            )
        except ValueError as exc:
            return _PlanResult(
                planning_attempts=planning_attempts,
                skip_reason="no_known_ports",
                skip_detail=str(exc),
                skip_parent=last_violation_span or last_planning_span,
            )

        parent = last_violation_span or last_planning_span
        return _PlanResult(
            args=args,
            filename=filename,
            command_source="fallback",
            command_exec_parent=parent,
            planning_attempts=planning_attempts,
            used_fallback=True,
        )

    @staticmethod
    def _build_planning_messages(
        original: list[dict[str, str]],
        attempt: int,
        violation_snippet: str | None,
    ) -> list[dict[str, str]]:
        """Build messages for a planning attempt.

        Replace-style retry: on retries the original user turn is preserved
        and a new user turn carrying the guardrail correction is appended.
        Assistant turns from failed attempts are intentionally not included
        to keep the context small and focused.
        """
        if attempt == 1 or not violation_snippet:
            return [dict(m) for m in original]
        return [
            *[dict(m) for m in original],
            {
                "role": "user",
                "content": f"Previous attempt rejected: {violation_snippet}",
            },
        ]

    # -- execution -----------------------------------------------------------

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

    # -- skip emission -------------------------------------------------------

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

    # -- helpers -------------------------------------------------------------

    def _build_prompt_context(self, stage: str, host: str | None) -> str:
        if stage == "host_discovery" or host is None:
            return self._state.to_prompt_context()
        host_state = self._state.discovered_hosts.get(host)
        context: dict = {
            "target_subnet": self._state.target_subnet,
            "current_stage": stage,
            "current_target": host,
        }
        if host_state is not None:
            if stage in ("service_enum", "os_fingerprint"):
                context["open_ports"] = host_state.open_ports
            if stage == "os_fingerprint":
                context["services"] = host_state.services
        return json.dumps(context, indent=2)

    def _findings_count(self, stage: str, host: str) -> int:
        host_state = self._state.discovered_hosts.get(host)
        if host_state is None:
            return 0
        if stage == "port_scan":
            return len(host_state.open_ports)
        if stage == "service_enum":
            return len(host_state.services)
        if stage == "os_fingerprint":
            return len(host_state.os_matches)
        return 0

    def _stage_config(self, stage: str) -> StageConfig:
        return self._config.stage_configs.get(stage, StageConfig())
