"""Planning retry, fallback, and prompt-building for ReconAgent."""

from __future__ import annotations

from dataclasses import dataclass

from config import StageConfig
from guardrails import GuardrailViolation
from llm_client import LLMError
from prompt_templates import PLANNING_SCHEMA, build_planning_prompt

_MAX_RETRY_SNIPPET_CHARS = 250


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


class _PlanningMixin:
    """Planning loop mixin for ReconAgent.

    Relies on the host class to provide `_llm`, `_guardrails`,
    `_command_builder`, `_logger`, `_state`, and `_config` attributes.
    """

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
