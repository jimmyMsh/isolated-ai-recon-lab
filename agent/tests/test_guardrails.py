"""Tests for guardrails module — validation at two pipeline points."""

import pytest

from config import AgentConfig
from guardrails import Guardrails, GuardrailViolation


@pytest.fixture
def config():
    return AgentConfig(
        ollama_url="http://localhost:11434",
        model="qwen3:8b",
        num_ctx=8192,
        target_subnet="192.168.56.0/24",
        attacker_ip="192.168.56.10",
        nmap_path="/usr/bin/nmap",
        allowed_tools=["nmap"],
    )


@pytest.fixture
def guardrails(config):
    return Guardrails(config)


class TestIsIpInSubnet:
    def test_ip_in_subnet(self, guardrails):
        assert guardrails.is_ip_in_subnet("192.168.56.101") is True

    def test_ip_out_of_subnet(self, guardrails):
        assert guardrails.is_ip_in_subnet("10.0.0.1") is False

    def test_subnet_cidr_itself(self, guardrails):
        assert guardrails.is_ip_in_subnet("192.168.56.0/24") is True

    def test_attacker_ip_is_in_subnet(self, guardrails):
        assert guardrails.is_ip_in_subnet("192.168.56.10") is True

    def test_broadcast_address(self, guardrails):
        assert guardrails.is_ip_in_subnet("192.168.56.255") is True

    def test_adjacent_subnet_rejected(self, guardrails):
        assert guardrails.is_ip_in_subnet("192.168.57.1") is False

    def test_invalid_ip_returns_false(self, guardrails):
        assert guardrails.is_ip_in_subnet("not-an-ip") is False

    def test_ipv6_returns_false_not_raises(self, guardrails):
        """IPv6 input against IPv4 subnet should return False, not TypeError."""
        assert guardrails.is_ip_in_subnet("::1") is False
        assert guardrails.is_ip_in_subnet("fe80::1") is False


class TestIsValidPortSpec:
    def test_single_port(self, guardrails):
        assert guardrails.is_valid_port_spec("80") is True

    def test_comma_separated(self, guardrails):
        assert guardrails.is_valid_port_spec("22,80,443") is True

    def test_range(self, guardrails):
        assert guardrails.is_valid_port_spec("1-1024") is True

    def test_mixed(self, guardrails):
        assert guardrails.is_valid_port_spec("22,80,8000-9000") is True

    def test_empty_string(self, guardrails):
        assert guardrails.is_valid_port_spec("") is True

    def test_invalid_port_string(self, guardrails):
        assert guardrails.is_valid_port_spec("abc") is False

    def test_port_out_of_range(self, guardrails):
        assert guardrails.is_valid_port_spec("99999") is False

    def test_negative_port(self, guardrails):
        assert guardrails.is_valid_port_spec("-1") is False

    def test_reversed_range_rejected(self, guardrails):
        """Reversed ranges like 9000-80 should be rejected."""
        assert guardrails.is_valid_port_spec("9000-80") is False


class TestValidatePlanningResponse:
    def test_valid_host_discovery_response(self, guardrails):
        response = {
            "target": "192.168.56.0/24",
            "scan_intensity": "standard",
            "reasoning": "Scanning the full subnet.",
        }
        result = guardrails.validate_planning_response("host_discovery", response)
        assert result["target"] == "192.168.56.0/24"
        assert result["scan_intensity"] == "standard"
        assert result["reasoning"] == "Scanning the full subnet."

    def test_valid_port_scan_response(self, guardrails):
        response = {
            "target": "192.168.56.101",
            "scan_intensity": "light",
            "reasoning": "Quick scan of common ports.",
        }
        result = guardrails.validate_planning_response("port_scan", response)
        assert result["target"] == "192.168.56.101"

    def test_target_outside_subnet_raises(self, guardrails):
        response = {
            "target": "10.0.0.1",
            "scan_intensity": "standard",
            "reasoning": "test",
        }
        with pytest.raises(GuardrailViolation, match="target_outside_subnet"):
            guardrails.validate_planning_response("port_scan", response)

    def test_invalid_scan_intensity_raises(self, guardrails):
        response = {
            "target": "192.168.56.101",
            "scan_intensity": "nuclear",
            "reasoning": "test",
        }
        with pytest.raises(GuardrailViolation, match="invalid_scan_intensity"):
            guardrails.validate_planning_response("port_scan", response)

    def test_invalid_port_spec_raises(self, guardrails):
        response = {
            "target": "192.168.56.101",
            "ports": "abc",
            "scan_intensity": "standard",
            "reasoning": "test",
        }
        with pytest.raises(GuardrailViolation, match="invalid_port_spec"):
            guardrails.validate_planning_response("port_scan", response)

    def test_strips_unexpected_fields(self, guardrails):
        response = {
            "target": "192.168.56.101",
            "scan_intensity": "standard",
            "reasoning": "test",
            "unexpected_field": "should be stripped",
            "another_extra": 42,
        }
        result = guardrails.validate_planning_response("port_scan", response)
        assert "unexpected_field" not in result
        assert "another_extra" not in result
        assert "target" in result

    def test_missing_required_target_raises(self, guardrails):
        response = {
            "scan_intensity": "standard",
            "reasoning": "test",
        }
        with pytest.raises(GuardrailViolation, match="missing_required_field"):
            guardrails.validate_planning_response("port_scan", response)

    def test_missing_required_scan_intensity_raises(self, guardrails):
        response = {
            "target": "192.168.56.101",
            "reasoning": "test",
        }
        with pytest.raises(GuardrailViolation, match="missing_required_field"):
            guardrails.validate_planning_response("port_scan", response)

    def test_empty_ports_allowed(self, guardrails):
        """ports field is optional / can be empty (e.g. host_discovery)."""
        response = {
            "target": "192.168.56.0/24",
            "ports": "",
            "scan_intensity": "standard",
            "reasoning": "test",
        }
        result = guardrails.validate_planning_response("host_discovery", response)
        assert result["ports"] == ""

    def test_planning_response_rejects_attacker_ip(self, guardrails):
        """Target equal to attacker IP should be rejected for single-host stages."""
        response = {
            "target": "192.168.56.10",
            "scan_intensity": "standard",
            "reasoning": "test",
        }
        with pytest.raises(GuardrailViolation, match="target_is_attacker_ip"):
            guardrails.validate_planning_response("port_scan", response)

    def test_service_enum_empty_ports_raises(self, guardrails):
        """service_enum requires non-empty ports."""
        response = {
            "target": "192.168.56.101",
            "ports": "",
            "scan_intensity": "standard",
            "reasoning": "test",
        }
        with pytest.raises(GuardrailViolation, match="missing_ports_for_stage"):
            guardrails.validate_planning_response("service_enum", response)

    def test_host_discovery_nonempty_ports_raises(self, guardrails):
        """host_discovery should not accept ports."""
        response = {
            "target": "192.168.56.0/24",
            "ports": "22,80",
            "scan_intensity": "standard",
            "reasoning": "test",
        }
        with pytest.raises(GuardrailViolation, match="invalid_ports_for_stage"):
            guardrails.validate_planning_response("host_discovery", response)

    def test_port_scan_nonempty_ports_raises(self, guardrails):
        """port_scan should not accept ports — intensity controls port range."""
        response = {
            "target": "192.168.56.101",
            "ports": "22,80",
            "scan_intensity": "standard",
            "reasoning": "test",
        }
        with pytest.raises(GuardrailViolation, match="invalid_ports_for_stage"):
            guardrails.validate_planning_response("port_scan", response)

    def test_port_scan_targeting_subnet_raises(self, guardrails):
        """port_scan must target a single host, not the subnet."""
        response = {
            "target": "192.168.56.0/24",
            "scan_intensity": "standard",
            "reasoning": "test",
        }
        with pytest.raises(GuardrailViolation, match="invalid_target_for_stage"):
            guardrails.validate_planning_response("port_scan", response)

    def test_service_enum_targeting_subnet_raises(self, guardrails):
        """service_enum must target a single host, not the subnet."""
        response = {
            "target": "192.168.56.0/24",
            "ports": "22,80",
            "scan_intensity": "standard",
            "reasoning": "test",
        }
        with pytest.raises(GuardrailViolation, match="invalid_target_for_stage"):
            guardrails.validate_planning_response("service_enum", response)


class TestValidateNmapArgs:
    def test_valid_args(self, guardrails):
        args = ["-sn", "192.168.56.0/24"]
        guardrails.validate_nmap_args(args)  # should not raise

    def test_target_outside_subnet_raises(self, guardrails):
        args = ["-sS", "10.0.0.1"]
        with pytest.raises(GuardrailViolation, match="target_outside_subnet"):
            guardrails.validate_nmap_args(args)

    def test_multiple_valid_args(self, guardrails):
        args = ["-sS", "-T4", "-p-", "--open", "192.168.56.101"]
        guardrails.validate_nmap_args(args)  # should not raise

    def test_ox_flag_allowed(self, guardrails):
        """Output flags like -oX should be allowed."""
        args = ["-sn", "-oX", "/tmp/output.xml", "192.168.56.0/24"]
        guardrails.validate_nmap_args(args)  # should not raise

    def test_exclude_flag_allowed(self, guardrails):
        args = ["-sn", "--exclude", "192.168.56.10", "192.168.56.0/24"]
        guardrails.validate_nmap_args(args)  # should not raise

    def test_no_target_at_all_raises(self, guardrails):
        """Args with only flags and no target should raise."""
        args = ["-sS", "-T4"]
        with pytest.raises(GuardrailViolation, match="no_target"):
            guardrails.validate_nmap_args(args)

    def test_nmap_args_rejects_attacker_ip(self, guardrails):
        """Args containing the attacker IP as target should be rejected."""
        args = ["-sS", "-T4", "192.168.56.10"]
        with pytest.raises(GuardrailViolation, match="target_is_attacker_ip"):
            guardrails.validate_nmap_args(args)
