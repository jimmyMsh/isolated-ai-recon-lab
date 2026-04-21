"""Orchestration dataclasses and small pure helpers for ReconAgent."""

from __future__ import annotations

import json
from dataclasses import dataclass

from config import AgentConfig, StageConfig
from state import AgentState
from tool_parser import NmapParser

_PARSERS = {
    "port_scan": NmapParser.parse_port_scan,
    "service_enum": NmapParser.parse_service_enum,
    "os_fingerprint": NmapParser.parse_os_fingerprint,
}

_UPDATERS = {
    "port_scan": AgentState.update_from_port_scan,
    "service_enum": AgentState.update_from_service_enum,
    "os_fingerprint": AgentState.update_from_os_fingerprint,
}


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


def _host_kwargs(host: str | None) -> dict[str, str]:
    return {"host_target": host} if host is not None else {}


def _stage_config(config: AgentConfig, stage: str) -> StageConfig:
    return config.stage_configs.get(stage, StageConfig())


def _findings_count(state: AgentState, stage: str, host: str) -> int:
    host_state = state.discovered_hosts.get(host)
    if host_state is None:
        return 0
    if stage == "port_scan":
        return len(host_state.open_ports)
    if stage == "service_enum":
        return len(host_state.services)
    if stage == "os_fingerprint":
        return len(host_state.os_matches)
    return 0


def _build_prompt_context(state: AgentState, stage: str, host: str | None) -> str:
    if stage == "host_discovery" or host is None:
        return state.to_prompt_context()
    host_state = state.discovered_hosts.get(host)
    context: dict = {
        "target_subnet": state.target_subnet,
        "current_stage": stage,
        "current_target": host,
    }
    if host_state is not None:
        if stage in ("service_enum", "os_fingerprint"):
            context["open_ports"] = host_state.open_ports
        if stage == "os_fingerprint":
            context["services"] = host_state.services
    return json.dumps(context, indent=2)
