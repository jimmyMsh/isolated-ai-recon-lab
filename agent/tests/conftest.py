"""Shared pytest fixtures for ReconAgent orchestration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent import ReconAgent
from config import AgentConfig
from logger import AgentLogger

from .fakes import FakeLLMClient, FakeToolExecutor
from .recon_agent_test_support import (
    FIXTURES_DIR,
    _exec_result_ok,
    _four_stage_exec_queue,
    _four_stage_llm_queue,
    _interpretation_response,
    _planning_response,
    _read_log_events,
    _stage_configs_default,
)


@pytest.fixture()
def config(tmp_path):
    output = tmp_path / "output"
    return AgentConfig(
        ollama_url="http://localhost:11434",
        model="qwen3:8b",
        target_subnet="192.168.56.0/24",
        attacker_ip="192.168.56.10",
        nmap_path="/usr/bin/nmap",
        output_dir=str(output),
        log_file=str(output / "agent.log.jsonl"),
        stage_configs=_stage_configs_default(),
    )


@pytest.fixture()
def host_discovery_run(config):
    """Exercise only the host_discovery stage, without per-host iteration."""
    llm = FakeLLMClient([_planning_response(), _interpretation_response()])
    exec_dummy_cmd = ["/usr/bin/nmap", "-sn", "192.168.56.0/24"]
    tool = FakeToolExecutor(
        results=[(FIXTURES_DIR / "host_discovery.xml", _exec_result_ok(exec_dummy_cmd))],
        output_dir=Path(config.output_dir),
    )
    logger = AgentLogger(config)
    trace_id = logger.trace_id

    agent = ReconAgent(config, llm_client=llm, tool_executor=tool, logger=logger)
    agent._run_host_discovery()
    logger.close()

    events = [e for e in _read_log_events(config.log_file) if e.get("trace_id") == trace_id]
    return {
        "agent": agent,
        "llm": llm,
        "tool": tool,
        "trace_id": trace_id,
        "events": events,
        "state": agent._state,
    }


@pytest.fixture()
def multi_host_run(config):
    """Run ReconAgent through all four stages across two discovered hosts."""
    llm = FakeLLMClient(_four_stage_llm_queue())
    tool = FakeToolExecutor(
        results=_four_stage_exec_queue(),
        output_dir=Path(config.output_dir),
    )
    logger = AgentLogger(config)
    trace_id = logger.trace_id

    agent = ReconAgent(config, llm_client=llm, tool_executor=tool, logger=logger)
    report_path = agent.run()

    events = [e for e in _read_log_events(config.log_file) if e.get("trace_id") == trace_id]
    return {
        "agent": agent,
        "llm": llm,
        "tool": tool,
        "trace_id": trace_id,
        "report_path": report_path,
        "events": events,
        "state": agent._state,
    }


@pytest.fixture()
def zero_hosts_run(config):
    """Run ReconAgent when host_discovery finds no live hosts."""
    llm = FakeLLMClient([_planning_response(), _interpretation_response()])
    tool = FakeToolExecutor(
        results=[(FIXTURES_DIR / "empty.xml", _exec_result_ok(["/usr/bin/nmap", "-sn"]))],
        output_dir=Path(config.output_dir),
    )
    logger = AgentLogger(config)
    trace_id = logger.trace_id

    agent = ReconAgent(config, llm_client=llm, tool_executor=tool, logger=logger)
    report_path = agent.run()

    events = [e for e in _read_log_events(config.log_file) if e.get("trace_id") == trace_id]
    return {
        "agent": agent,
        "llm": llm,
        "tool": tool,
        "trace_id": trace_id,
        "report_path": report_path,
        "events": events,
        "state": agent._state,
    }
