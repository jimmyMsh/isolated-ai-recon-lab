"""Shared helpers for ReconAgent orchestration tests."""

from __future__ import annotations

import json
from pathlib import Path

from agent import ReconAgent
from config import StageConfig
from llm_client import LLMResponse
from logger import AgentLogger
from tool_executor import ExecutionResult

FIXTURES_DIR = Path(__file__).parent / "fixtures"

EXPECTED_HOSTS = ["192.168.56.1", "192.168.56.101"]
TEST_HOST = "192.168.56.101"
FIRST_HOST = "192.168.56.1"
SECOND_HOST = "192.168.56.101"


def _stage_configs_default() -> dict[str, StageConfig]:
    return {
        "host_discovery": StageConfig(timeout_seconds=120),
        "port_scan": StageConfig(timeout_seconds=120),
        "service_enum": StageConfig(timeout_seconds=120),
        "os_fingerprint": StageConfig(timeout_seconds=120),
    }


def _planning_response() -> LLMResponse:
    parsed = {
        "target": "192.168.56.0/24",
        "scan_intensity": "standard",
        "reasoning": "Full-subnet discovery on isolated LAN.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _interpretation_response() -> LLMResponse:
    parsed = {
        "findings": [
            {
                "description": "192.168.56.101 is alive",
                "severity": "informational",
                "mitre_technique": "T1595.001",
            }
        ],
        "summary": "Discovered 2 hosts on the subnet.",
        "recommendations": "Proceed with port scanning.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _exec_result_ok(command: list[str]) -> ExecutionResult:
    return ExecutionResult(
        command=command,
        return_code=0,
        stdout="",
        stderr="",
        xml_output_path=None,  # overwritten by FakeToolExecutor
        duration_seconds=0.1,
        timed_out=False,
    )


def _exec_result_timeout() -> ExecutionResult:
    return ExecutionResult(
        command=["/usr/bin/nmap", "-sS", TEST_HOST],
        return_code=-1,
        stdout="",
        stderr="",
        xml_output_path=None,
        duration_seconds=120.0,
        timed_out=True,
    )


def _exec_result_nonzero_exit() -> ExecutionResult:
    return ExecutionResult(
        command=["/usr/bin/nmap", "-sS", TEST_HOST],
        return_code=2,
        stdout="",
        stderr="failed to resolve target",
        xml_output_path=None,
        duration_seconds=0.4,
        timed_out=False,
    )


def _exec_result_permission_error() -> ExecutionResult:
    return ExecutionResult(
        command=["/usr/bin/nmap", "-sS", TEST_HOST],
        return_code=1,
        stdout="",
        stderr="You requested a scan type which requires root privileges.",
        xml_output_path=None,
        duration_seconds=0.1,
        timed_out=False,
    )


def _read_log_events(log_path: str) -> list[dict]:
    path = Path(log_path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _build_agent(config, llm, tool) -> tuple[ReconAgent, AgentLogger]:
    logger = AgentLogger(config)
    agent = ReconAgent(config, llm_client=llm, tool_executor=tool, logger=logger)
    return agent, logger


def _events_for_run(config, trace_id: str) -> list[dict]:
    return [e for e in _read_log_events(config.log_file) if e.get("trace_id") == trace_id]


def _port_scan_plan(host: str) -> LLMResponse:
    parsed = {
        "target": host,
        "scan_intensity": "standard",
        "reasoning": f"Full port scan for {host}.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _service_enum_plan(host: str, ports: str) -> LLMResponse:
    parsed = {
        "target": host,
        "ports": ports,
        "scan_intensity": "standard",
        "reasoning": f"Version detection on known-open ports of {host}.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _os_fingerprint_plan(host: str) -> LLMResponse:
    parsed = {
        "target": host,
        "scan_intensity": "standard",
        "reasoning": f"OS fingerprint for {host}.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _interpretation_generic(summary: str) -> LLMResponse:
    parsed = {
        "findings": [],
        "summary": summary,
        "recommendations": "Continue pipeline.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _four_stage_llm_queue() -> list[LLMResponse]:
    """Queue of LLM responses for a full four-stage happy-path run."""
    queue: list[LLMResponse] = [
        _planning_response(),
        _interpretation_response(),
    ]
    known_ports_csv = "21,22,80,445"
    for host in EXPECTED_HOSTS:
        queue.extend(
            [
                _port_scan_plan(host),
                _interpretation_generic(f"Ports for {host}."),
            ]
        )
    for host in EXPECTED_HOSTS:
        queue.extend(
            [
                _service_enum_plan(host, known_ports_csv),
                _interpretation_generic(f"Services for {host}."),
            ]
        )
    for host in EXPECTED_HOSTS:
        queue.extend(
            [
                _os_fingerprint_plan(host),
                _interpretation_generic(f"OS for {host}."),
            ]
        )
    return queue


def _four_stage_exec_queue() -> list:
    """Queue of executor results for a full four-stage happy-path run."""
    exec_queue: list = [
        (FIXTURES_DIR / "host_discovery.xml", _exec_result_ok(["/usr/bin/nmap", "-sn"])),
    ]
    for _ in EXPECTED_HOSTS:
        exec_queue.append(
            (FIXTURES_DIR / "port_scan.xml", _exec_result_ok(["/usr/bin/nmap", "-sS"]))
        )
    for _ in EXPECTED_HOSTS:
        exec_queue.append(
            (FIXTURES_DIR / "service_enum.xml", _exec_result_ok(["/usr/bin/nmap", "-sV"]))
        )
    for _ in EXPECTED_HOSTS:
        exec_queue.append(
            (FIXTURES_DIR / "os_fingerprint.xml", _exec_result_ok(["/usr/bin/nmap", "-O"]))
        )
    return exec_queue


def _bad_plan_invalid_intensity(host: str = TEST_HOST) -> LLMResponse:
    parsed = {
        "target": host,
        "scan_intensity": "invalid",
        "reasoning": "broken intensity choice",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _good_port_scan_plan(host: str = TEST_HOST) -> LLMResponse:
    parsed = {
        "target": host,
        "scan_intensity": "standard",
        "reasoning": f"Full port scan for {host}.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _good_os_fingerprint_plan(host: str = TEST_HOST) -> LLMResponse:
    parsed = {
        "target": host,
        "scan_intensity": "standard",
        "reasoning": f"OS fingerprint for {host}.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _generic_interpretation(summary: str = "ok") -> LLMResponse:
    parsed = {
        "findings": [],
        "summary": summary,
        "recommendations": "Continue pipeline.",
    }
    return LLMResponse(parsed=parsed, raw_content=json.dumps(parsed))


def _seed_host(agent: ReconAgent, ip: str = TEST_HOST) -> None:
    agent._state.update_from_discovery([{"ip": ip}])


def _seed_ports(agent: ReconAgent, ip: str = TEST_HOST) -> None:
    agent._state.update_from_port_scan(
        ip,
        {
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open"},
                {"port": 80, "protocol": "tcp", "state": "open"},
            ]
        },
    )
