"""Tests for prompt_templates module — prompt assembly and schema validation."""

import json

import pytest

from config import AgentConfig
from prompt_templates import (
    INTERPRETATION_SCHEMA,
    PLANNING_SCHEMA,
    STAGE_INTERPRETATION_INSTRUCTIONS,
    STAGE_PLANNING_INSTRUCTIONS,
    SYSTEM_PROMPT,
    build_interpretation_prompt,
    build_planning_prompt,
)

STAGES = ["host_discovery", "port_scan", "service_enum", "os_fingerprint"]


@pytest.fixture
def config():
    return AgentConfig(
        ollama_url="http://localhost:11434",
        model="qwen3:8b",
        num_ctx=8192,
        target_subnet="192.168.56.0/24",
        attacker_ip="192.168.56.10",
        nmap_path="/usr/bin/nmap",
    )


class TestSystemPrompt:
    def test_is_nonempty_string(self):
        assert isinstance(SYSTEM_PROMPT, str)
        assert len(SYSTEM_PROMPT) > 100

    def test_contains_key_rules(self):
        assert "subnet" in SYSTEM_PROMPT.lower()
        assert "nmap" in SYSTEM_PROMPT.lower()


class TestSchemas:
    def test_planning_schema_is_valid_json_schema(self):
        assert PLANNING_SCHEMA["type"] == "object"
        assert "target" in PLANNING_SCHEMA["properties"]
        assert "scan_intensity" in PLANNING_SCHEMA["properties"]
        assert "reasoning" in PLANNING_SCHEMA["properties"]
        assert set(PLANNING_SCHEMA["required"]) == {"target", "scan_intensity", "reasoning"}

    def test_interpretation_schema_is_valid_json_schema(self):
        assert INTERPRETATION_SCHEMA["type"] == "object"
        assert "findings" in INTERPRETATION_SCHEMA["properties"]
        assert "summary" in INTERPRETATION_SCHEMA["properties"]
        assert "recommendations" in INTERPRETATION_SCHEMA["properties"]
        assert set(INTERPRETATION_SCHEMA["required"]) == {
            "findings",
            "summary",
            "recommendations",
        }

    def test_planning_schema_intensity_enum(self):
        intensity = PLANNING_SCHEMA["properties"]["scan_intensity"]
        assert set(intensity["enum"]) == {"light", "standard", "aggressive"}

    def test_schemas_are_json_serializable(self):
        json.dumps(PLANNING_SCHEMA)
        json.dumps(INTERPRETATION_SCHEMA)


class TestStageInstructions:
    @pytest.mark.parametrize("stage", STAGES)
    def test_planning_instruction_exists(self, stage):
        assert stage in STAGE_PLANNING_INSTRUCTIONS
        assert len(STAGE_PLANNING_INSTRUCTIONS[stage]) > 20

    @pytest.mark.parametrize("stage", STAGES)
    def test_interpretation_instruction_exists(self, stage):
        assert stage in STAGE_INTERPRETATION_INSTRUCTIONS
        assert len(STAGE_INTERPRETATION_INSTRUCTIONS[stage]) > 20


class TestBuildPlanningPrompt:
    def test_returns_messages_list(self, config):
        messages = build_planning_prompt("host_discovery", "{}", config)
        assert isinstance(messages, list)
        assert len(messages) == 2

    def test_system_message_first(self, config):
        messages = build_planning_prompt("host_discovery", "{}", config)
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == SYSTEM_PROMPT

    def test_user_message_contains_stage_instruction(self, config):
        messages = build_planning_prompt("port_scan", "{}", config)
        user_content = messages[1]["content"]
        assert STAGE_PLANNING_INSTRUCTIONS["port_scan"] in user_content

    def test_user_message_contains_state_context(self, config):
        state_ctx = '{"discovered_hosts": {"192.168.56.101": {}}}'
        messages = build_planning_prompt("port_scan", state_ctx, config)
        user_content = messages[1]["content"]
        assert state_ctx in user_content

    def test_user_message_contains_target_subnet(self, config):
        messages = build_planning_prompt("host_discovery", "{}", config)
        user_content = messages[1]["content"]
        assert "192.168.56.0/24" in user_content

    def test_user_message_contains_attacker_ip(self, config):
        messages = build_planning_prompt("host_discovery", "{}", config)
        user_content = messages[1]["content"]
        assert "192.168.56.10" in user_content

    def test_user_message_ends_with_no_think(self, config):
        messages = build_planning_prompt("host_discovery", "{}", config)
        user_content = messages[1]["content"]
        assert user_content.rstrip().endswith("/no_think")

    def test_current_target_info_included_when_provided(self, config):
        target_info = "Currently scanning host 2 of 3: 192.168.56.102"
        messages = build_planning_prompt("port_scan", "{}", config, current_target_info=target_info)
        user_content = messages[1]["content"]
        assert target_info in user_content

    def test_current_target_info_absent_when_not_provided(self, config):
        messages = build_planning_prompt("port_scan", "{}", config)
        user_content = messages[1]["content"]
        assert "Currently scanning" not in user_content


class TestBuildInterpretationPrompt:
    def test_returns_messages_list(self, config):
        messages = build_interpretation_prompt("host_discovery", "{}", "{}", config)
        assert isinstance(messages, list)
        assert len(messages) == 2

    def test_user_message_contains_parsed_results(self, config):
        parsed = '{"hosts": [{"ip": "192.168.56.101"}]}'
        messages = build_interpretation_prompt("host_discovery", "{}", parsed, config)
        user_content = messages[1]["content"]
        assert parsed in user_content

    def test_user_message_contains_interpretation_instruction(self, config):
        messages = build_interpretation_prompt("service_enum", "{}", "{}", config)
        user_content = messages[1]["content"]
        assert STAGE_INTERPRETATION_INSTRUCTIONS["service_enum"] in user_content

    def test_user_message_ends_with_no_think(self, config):
        messages = build_interpretation_prompt("host_discovery", "{}", "{}", config)
        user_content = messages[1]["content"]
        assert user_content.rstrip().endswith("/no_think")

    def test_current_target_info_included(self, config):
        target_info = "Currently scanning host 1 of 2: 192.168.56.101"
        messages = build_interpretation_prompt(
            "port_scan", "{}", "{}", config, current_target_info=target_info
        )
        user_content = messages[1]["content"]
        assert target_info in user_content
