"""ReconAgent — Phase 5 pipeline orchestrator.

Phase 5.1 scope: single-stage end-to-end for ``host_discovery``. Multi-host
iteration, planning retry/fallback, interpretation retry, and time-budget
handling are introduced in 5.2–5.4.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from command_builder import CommandBuilder
from config import AgentConfig, StageConfig
from guardrails import Guardrails
from llm_client import LLMClient
from logger import AgentLogger
from prompt_templates import (
    INTERPRETATION_SCHEMA,
    PLANNING_SCHEMA,
    build_interpretation_prompt,
    build_planning_prompt,
)
from report_generator import ReportGenerator
from state import AgentState
from tool_executor import ToolExecutor
from tool_parser import NmapParser


@dataclass
class HostStageOutcome:
    """Ephemeral per-host-stage orchestration metadata.

    Lives only in the orchestrator. Never fed back into AgentState or into
    any LLM prompt.
    """

    stage: str
    host: str | None = None
    planning_attempts: int = 0
    used_fallback: bool = False
    execution_succeeded: bool = False
    skipped_reason: str | None = None
    interpretation_succeeded: bool = False
    findings_count: int = 0
    duration_seconds: float = 0.0


class ReconAgent:
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

        # Step 1-2: planning prompt → planning LLM call
        planning_messages = build_planning_prompt(
            stage, self._state.to_prompt_context(), self._config
        )
        planning = self._llm.call(planning_messages, PLANNING_SCHEMA, stage_config=stage_config)
        outcome.planning_attempts = 1
        planning_span = self._logger.log_event(
            "planning_call",
            stage,
            {
                "llm_input": {"messages": planning_messages},
                "llm_output": {
                    "parsed": planning.parsed,
                    "raw_content": planning.raw_content,
                },
            },
        )

        # Step 3: guardrails validate planning response
        validated = self._guardrails.validate_planning_response(stage, planning.parsed)

        # Step 4-5: build + execute nmap command
        args, filename = self._command_builder.build(stage, validated, self._state)
        result = self._executor.execute_nmap(args, filename, timeout=stage_config.timeout_seconds)
        cmd_exec_span = self._logger.log_event(
            "command_exec",
            stage,
            {
                "command": result.command,
                "return_code": result.return_code,
                "stdout_preview": result.stdout[:500],
                "xml_output_path": result.xml_output_path,
                "duration_seconds": result.duration_seconds,
                "command_source": "llm",
            },
            parent_span_id=planning_span,
        )
        outcome.execution_succeeded = True

        # Step 7: parse XML
        parsed = NmapParser.parse_host_discovery(Path(result.xml_output_path))

        # Step 8: update state + emit state_update
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

        # Step 9-10: interpretation
        interp_messages = build_interpretation_prompt(
            stage,
            self._state.to_prompt_context(),
            json.dumps(parsed),
            self._config,
        )
        interp = self._llm.call(interp_messages, INTERPRETATION_SCHEMA)
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

        # Step 11: stage_complete
        mitre = ReportGenerator.STAGE_TO_MITRE[stage]
        self._logger.log_event(
            "stage_complete",
            stage,
            {
                "success": True,
                "findings_count": outcome.findings_count,
                "total_stage_duration_seconds": outcome.duration_seconds,
                "llm_calls": 2,
                "retries": 0,
                "mitre_technique": mitre["id"],
            },
            parent_span_id=interp_span,
        )
        self._state.stages_completed.append(stage)

    # -- helpers -------------------------------------------------------------

    def _stage_config(self, stage: str) -> StageConfig:
        return self._config.stage_configs.get(stage, StageConfig())
