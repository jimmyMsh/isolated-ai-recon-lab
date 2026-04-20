"""ReconAgent — pipeline orchestrator for the reconnaissance agent."""

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

        validated = self._guardrails.validate_planning_response(stage, planning.parsed)

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
                "llm_calls": 2,
                "retries": 0,
                "mitre_technique": mitre["id"],
            },
            parent_span_id=interp_span,
        )
        self._state.stages_completed.append(stage)

    # -- per-host stages -----------------------------------------------------

    _PARSERS = {
        "port_scan": NmapParser.parse_port_scan,
        "service_enum": NmapParser.parse_service_enum,
        "os_fingerprint": NmapParser.parse_os_fingerprint,
    }

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

        planning_messages = build_planning_prompt(
            stage, prompt_context, self._config, current_target_info=target_info
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
            host_target=host,
        )

        validated = self._guardrails.validate_planning_response(stage, planning.parsed)

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
            host_target=host,
        )
        outcome.execution_succeeded = True

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
                "llm_calls": 2,
                "retries": 0,
                "mitre_technique": mitre["id"],
            },
            parent_span_id=interp_span,
            host_target=host,
        )

    def _skip_stage_no_hosts(self, stage: str) -> None:
        outcome = HostStageOutcome(stage=stage, host=None, skipped_reason="no_hosts_discovered")
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

    # -- helpers -------------------------------------------------------------

    def _stage_config(self, stage: str) -> StageConfig:
        return self._config.stage_configs.get(stage, StageConfig())
