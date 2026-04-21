"""ReconAgent — pipeline orchestrator for the reconnaissance agent."""

from __future__ import annotations

import time
from pathlib import Path

from command_builder import CommandBuilder
from config import AgentConfig
from guardrails import Guardrails
from llm_client import LLMClient
from logger import AgentLogger
from report_generator import ReportGenerator
from state import AgentState
from tool_executor import ToolExecutor
from tool_parser import NmapParser

from .outcomes import (
    _PARSERS,
    _UPDATERS,
    HostStageOutcome,
    _build_prompt_context,
    _findings_count,
    _stage_config,
)
from .planning import _PlanningMixin
from .runtime import _RuntimeMixin

_PIPELINE_STAGES = ("host_discovery", "port_scan", "service_enum", "os_fingerprint")


class ReconAgent(_PlanningMixin, _RuntimeMixin):
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
        # Seed with a live monotonic reading so budget checks have a sane
        # baseline even before ``run()`` rewrites it at pipeline start.
        self._start_monotonic: float = time.monotonic()
        self._time_budget_exhausted: bool = False

    def run(self) -> str:
        self._start_monotonic = time.monotonic()
        self._time_budget_exhausted = False
        try:
            try:
                for stage in _PIPELINE_STAGES:
                    self._run_stage_with_budget(stage)
            except Exception as exc:
                self._log_run_level_abort(exc)
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

    # -- budget + run-level helpers ------------------------------------------

    def _check_budget_exceeded(self) -> bool:
        elapsed = time.monotonic() - self._start_monotonic
        return elapsed >= self._config.max_total_duration_seconds

    def _run_stage_with_budget(self, stage: str) -> None:
        """Entry gate for any pipeline stage — enforces the pre-stage budget
        check, then delegates to the real per-stage runner.

        Sets ``state.current_stage`` up front so that any run-level abort
        raised before the delegated runner updates it is still attributed
        to the correct stage.
        """
        self._state.current_stage = stage
        if self._time_budget_exhausted or self._check_budget_exceeded():
            self._time_budget_exhausted = True
            self._skip_stage_budget_exceeded(stage)
            return
        if stage == "host_discovery":
            self._run_host_discovery()
        else:
            self._run_per_host_stage_loop(stage)

    def _skip_stage_budget_exceeded(self, stage: str) -> None:
        """Fan out deterministic-skip ``stage_complete`` events for every unit
        in ``stage`` once the global time budget is known to be exhausted.

        For per-host stages, emit one event per discovered host in sorted
        order so the report summary reflects every intended scan target. If
        no hosts have been discovered yet (e.g. the budget tripped before
        host_discovery finished), emit a single subnet-level skip so the
        stage still appears in the pipeline summary.
        """
        self._state.current_stage = stage
        reason = "time_budget_exceeded"
        detail = "global time budget exhausted before stage began"
        if stage == "host_discovery":
            self._emit_budget_skip(stage, host=None, reason=reason, detail=detail)
        else:
            hosts = sorted(self._state.get_target_ips())
            if not hosts:
                self._emit_budget_skip(stage, host=None, reason=reason, detail=detail)
            else:
                for host in hosts:
                    self._emit_budget_skip(stage, host=host, reason=reason, detail=detail)
        self._state.stages_completed.append(stage)

    def _emit_budget_skip(self, stage: str, *, host: str | None, reason: str, detail: str) -> None:
        outcome = HostStageOutcome(
            stage=stage,
            host=host,
            skipped_reason=reason,
            skip_category="deterministic_skip",
        )
        self._outcomes.append(outcome)
        self._state.errors.append(
            {"stage": stage, "host": host, "reason": reason, "detail": detail}
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
                "reason": reason,
            },
            host_target=host,
        )

    def _log_run_level_abort(self, exc: BaseException) -> None:
        """Record a run-level unexpected exception.

        Logs a single ``error`` event with ``action_taken="abort_pipeline"``
        and appends one matching entry to ``state.errors`` so the report
        executive-summary counter reflects the abort. Does NOT synthesize a
        ``stage_complete`` for the in-flight unit — the exception escaped
        the per-host layer, so the unit's outcome is genuinely unknown.
        """
        stage = self._state.current_stage or "unknown"
        host = self._state.current_target
        self._logger.log_event(
            "error",
            stage,
            {
                "error_type": "unexpected_exception",
                "error_message": str(exc),
                "recoverable": False,
                "action_taken": "abort_pipeline",
            },
            host_target=host,
        )
        self._state.errors.append(
            {
                "stage": stage,
                "host": host,
                "reason": "unexpected_exception",
                "detail": str(exc),
            }
        )

    # -- host_discovery stage ------------------------------------------------

    def _run_host_discovery(self) -> None:
        stage = "host_discovery"
        self._state.current_stage = stage
        stage_start = time.monotonic()
        outcome = HostStageOutcome(stage=stage)
        stage_config = _stage_config(self._config, stage)
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

        if self._check_budget_exceeded():
            self._time_budget_exhausted = True
            self._emit_post_attempt_skip(
                stage=stage,
                host=None,
                reason="time_budget_exceeded",
                detail="budget exhausted between planning and execute",
                outcome=outcome,
                parent_span=plan.command_exec_parent,
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
        state_update_span = self._log_state_update(
            stage=stage,
            host=None,
            delta=delta,
            parent_span=cmd_exec_span,
        )
        outcome.findings_count = len(self._state.discovered_hosts)
        interp_span = self._run_interpretation(
            stage=stage,
            host=None,
            prompt_context=self._state.to_prompt_context(),
            parsed=parsed,
            target_info=None,
            parent_span=state_update_span,
            outcome=outcome,
        )
        parent_for_complete = interp_span or state_update_span
        self._emit_stage_success(
            stage=stage,
            host=None,
            outcome=outcome,
            parent_span=parent_for_complete,
            stage_start=stage_start,
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
                if self._time_budget_exhausted or self._check_budget_exceeded():
                    self._time_budget_exhausted = True
                    self._state.current_target = host
                    self._emit_budget_skip(
                        stage,
                        host=host,
                        reason="time_budget_exceeded",
                        detail="budget exhausted before host iteration",
                    )
                    continue
                self._run_per_host_stage(stage, host)
            self._state.current_target = None
        self._state.stages_completed.append(stage)

    def _run_per_host_stage(self, stage: str, host: str) -> None:
        self._state.current_target = host
        stage_start = time.monotonic()
        outcome = HostStageOutcome(stage=stage, host=host)
        stage_config = _stage_config(self._config, stage)
        target_info = f"Current scan target: {host}"
        prompt_context = _build_prompt_context(self._state, stage, host)

        # Highest-priority parent span logged so far for this host-stage.
        # Advanced as events are emitted (planning → command_exec →
        # state_update → interpretation_call); used to parent the skip
        # ``stage_complete`` and ``error`` events emitted by the broad
        # host-level catch so the causal chain is preserved.
        best_parent: str | None = None

        try:
            # Pre-planning deterministic skip: service_enum with no known ports.
            # Without a port list, -sV would fall back to nmap's default ~1000
            # ports — contradictory to the pipeline's "scan what was
            # discovered" contract. Skip cleanly without burning an LLM call.
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

            # Planning completed; its span is the best available parent for
            # anything that happens before a command_exec event is logged.
            best_parent = plan.command_exec_parent

            # Pre-execution budget check: planning succeeded, but if the
            # global wall-clock is exhausted before the executor runs, treat
            # this host as a post-attempt skip with the counters accumulated
            # so far (no interpretation, no state update).
            if self._check_budget_exceeded():
                self._time_budget_exhausted = True
                self._emit_post_attempt_skip(
                    stage=stage,
                    host=host,
                    reason="time_budget_exceeded",
                    detail="budget exhausted between planning and execute",
                    outcome=outcome,
                    parent_span=best_parent,
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
            best_parent = cmd_exec_span

            parser = _PARSERS[stage]
            parsed = parser(Path(result.xml_output_path))

            delta = _UPDATERS[stage](self._state, host, parsed)
            state_update_span = self._log_state_update(
                stage=stage,
                host=host,
                delta=delta,
                parent_span=cmd_exec_span,
            )
            best_parent = state_update_span
            outcome.findings_count = _findings_count(self._state, stage, host)
            interp_span = self._run_interpretation(
                stage=stage,
                host=host,
                prompt_context=prompt_context,
                parsed=parsed,
                target_info=target_info,
                parent_span=state_update_span,
                outcome=outcome,
            )
            if interp_span is not None:
                best_parent = interp_span
            parent_for_complete = interp_span or state_update_span
            self._emit_stage_success(
                stage=stage,
                host=host,
                outcome=outcome,
                parent_span=parent_for_complete,
                stage_start=stage_start,
            )
        except Exception as exc:
            # Host-level unexpected exception: log, emit a post-attempt skip
            # for this host with whatever counters accumulated, and let the
            # caller continue to the next host. ``LLMError`` cannot reach
            # here — it is absorbed inside ``_plan()`` (planning) and
            # ``_run_interpretation()`` (interpretation). The error and skip
            # events parent to the highest-priority event already logged for
            # this host-stage so the causal chain is preserved.
            self._logger.log_event(
                "error",
                stage,
                {
                    "error_type": "unexpected_exception",
                    "error_message": str(exc),
                    "recoverable": False,
                    "action_taken": "skip_host",
                },
                parent_span_id=best_parent,
                host_target=host,
            )
            self._emit_post_attempt_skip(
                stage=stage,
                host=host,
                reason="unexpected_exception",
                detail=str(exc),
                outcome=outcome,
                parent_span=best_parent,
                stage_start=stage_start,
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
