"""Tests for command_builder module — nmap command construction per stage."""

import pytest

from command_builder import CommandBuilder
from config import AgentConfig
from state import AgentState, HostState


@pytest.fixture
def config():
    return AgentConfig(
        ollama_url="http://localhost:11434",
        model="qwen3:8b",
        num_ctx=8192,
        target_subnet="192.168.56.0/24",
        attacker_ip="192.168.56.10",
        nmap_path="/usr/bin/nmap",
        output_dir="./output",
    )


@pytest.fixture
def builder(config):
    return CommandBuilder(config)


@pytest.fixture
def state_with_host():
    state = AgentState(
        target_subnet="192.168.56.0/24",
        attacker_ip="192.168.56.10",
    )
    host = HostState(ip="192.168.56.101")
    host.open_ports = [
        {"port": 22, "protocol": "tcp", "state": "open"},
        {"port": 80, "protocol": "tcp", "state": "open"},
        {"port": 445, "protocol": "tcp", "state": "open"},
    ]
    state.discovered_hosts["192.168.56.101"] = host
    return state


class TestBuildHostDiscovery:
    def test_light_intensity(self, builder, state_with_host):
        params = {"target": "192.168.56.0/24", "scan_intensity": "light"}
        args, filename = builder.build("host_discovery", params, state_with_host)
        assert "-sn" in args
        # Light host_discovery should NOT have -PE, -PP, etc.
        assert "-PE" not in args

    def test_standard_intensity(self, builder, state_with_host):
        params = {"target": "192.168.56.0/24", "scan_intensity": "standard"}
        args, filename = builder.build("host_discovery", params, state_with_host)
        assert "-sn" in args
        assert "-PE" in args
        assert "-PP" in args

    def test_aggressive_same_as_standard(self, builder, state_with_host):
        params_std = {"target": "192.168.56.0/24", "scan_intensity": "standard"}
        params_agg = {"target": "192.168.56.0/24", "scan_intensity": "aggressive"}
        args_std, _ = builder.build("host_discovery", params_std, state_with_host)
        args_agg, _ = builder.build("host_discovery", params_agg, state_with_host)

        def filter_ox(a):
            return [x for x in a if x != "-oX" and not x.endswith(".xml")]

        assert filter_ox(args_std) == filter_ox(args_agg)

    def test_excludes_attacker_ip(self, builder, state_with_host):
        params = {"target": "192.168.56.0/24", "scan_intensity": "standard"}
        args, _ = builder.build("host_discovery", params, state_with_host)
        assert "--exclude" in args
        exclude_idx = args.index("--exclude")
        assert args[exclude_idx + 1] == "192.168.56.10"

    def test_target_included(self, builder, state_with_host):
        params = {"target": "192.168.56.0/24", "scan_intensity": "light"}
        args, _ = builder.build("host_discovery", params, state_with_host)
        assert "192.168.56.0/24" in args


class TestBuildPortScan:
    def test_light_uses_fast_scan(self, builder, state_with_host):
        params = {"target": "192.168.56.101", "scan_intensity": "light"}
        args, _ = builder.build("port_scan", params, state_with_host)
        assert "-sS" in args
        assert "-F" in args
        assert "--open" in args

    def test_standard_scans_all_ports(self, builder, state_with_host):
        params = {"target": "192.168.56.101", "scan_intensity": "standard"}
        args, _ = builder.build("port_scan", params, state_with_host)
        assert "-sS" in args
        assert "-p-" in args
        assert "-T4" in args

    def test_aggressive_uses_t5(self, builder, state_with_host):
        params = {"target": "192.168.56.101", "scan_intensity": "aggressive"}
        args, _ = builder.build("port_scan", params, state_with_host)
        assert "-T5" in args

    def test_no_exclude_on_port_scan(self, builder, state_with_host):
        """--exclude is only for host_discovery."""
        params = {"target": "192.168.56.101", "scan_intensity": "standard"}
        args, _ = builder.build("port_scan", params, state_with_host)
        assert "--exclude" not in args


class TestBuildServiceEnum:
    def test_light_low_version_intensity(self, builder, state_with_host):
        params = {
            "target": "192.168.56.101",
            "ports": "22,80,445",
            "scan_intensity": "light",
        }
        args, _ = builder.build("service_enum", params, state_with_host)
        assert "-sV" in args
        assert "--version-intensity" in args
        vi_idx = args.index("--version-intensity")
        assert args[vi_idx + 1] == "2"

    def test_standard_version_intensity(self, builder, state_with_host):
        params = {
            "target": "192.168.56.101",
            "ports": "22,80,445",
            "scan_intensity": "standard",
        }
        args, _ = builder.build("service_enum", params, state_with_host)
        assert "-sV" in args
        assert "--version-intensity" in args
        vi_idx = args.index("--version-intensity")
        assert args[vi_idx + 1] == "5"

    def test_aggressive_uses_sc(self, builder, state_with_host):
        params = {
            "target": "192.168.56.101",
            "ports": "22,80,445",
            "scan_intensity": "aggressive",
        }
        args, _ = builder.build("service_enum", params, state_with_host)
        assert "-sV" in args
        assert "-sC" in args

    def test_ports_from_params(self, builder, state_with_host):
        params = {
            "target": "192.168.56.101",
            "ports": "22,80",
            "scan_intensity": "standard",
        }
        args, _ = builder.build("service_enum", params, state_with_host)
        assert "-p" in args
        p_idx = args.index("-p")
        assert args[p_idx + 1] == "22,80"


class TestBuildOsFingerprint:
    def test_light(self, builder, state_with_host):
        params = {
            "target": "192.168.56.101",
            "ports": "22,80,445",
            "scan_intensity": "light",
        }
        args, _ = builder.build("os_fingerprint", params, state_with_host)
        assert "-O" in args
        assert "--osscan-guess" not in args

    def test_standard(self, builder, state_with_host):
        params = {
            "target": "192.168.56.101",
            "ports": "22,80,445",
            "scan_intensity": "standard",
        }
        args, _ = builder.build("os_fingerprint", params, state_with_host)
        assert "-O" in args
        assert "--osscan-guess" in args

    def test_aggressive(self, builder, state_with_host):
        params = {
            "target": "192.168.56.101",
            "ports": "22,80,445",
            "scan_intensity": "aggressive",
        }
        args, _ = builder.build("os_fingerprint", params, state_with_host)
        assert "-O" in args
        assert "--osscan-guess" in args
        assert "--osscan-limit" in args


class TestBuildOutputFilename:
    def test_filename_format(self, builder, state_with_host):
        params = {"target": "192.168.56.101", "scan_intensity": "standard"}
        args, filename = builder.build("port_scan", params, state_with_host)
        # Filename should match {stage}_{target}_{timestamp}.xml
        assert filename.startswith("port_scan_192.168.56.101_")
        assert filename.endswith(".xml")

    def test_ox_flag_in_args(self, builder, state_with_host):
        params = {"target": "192.168.56.101", "scan_intensity": "standard"}
        args, filename = builder.build("port_scan", params, state_with_host)
        assert "-oX" in args
        ox_idx = args.index("-oX")
        assert args[ox_idx + 1].endswith(filename)


class TestBuildFallback:
    def test_host_discovery_fallback(self, builder, state_with_host):
        args, filename = builder.build_fallback("host_discovery", state_with_host)
        assert "-sn" in args
        assert "192.168.56.0/24" in args

    def test_port_scan_fallback(self, builder, state_with_host):
        args, filename = builder.build_fallback("port_scan", state_with_host)
        assert "-sS" in args
        assert "-F" in args
        assert "192.168.56.101" in args

    def test_service_enum_fallback(self, builder, state_with_host):
        args, filename = builder.build_fallback("service_enum", state_with_host)
        assert "-sV" in args
        assert "-p" in args
        # Should use open ports from state
        p_idx = args.index("-p")
        assert args[p_idx + 1] == "22,80,445"

    def test_os_fingerprint_fallback(self, builder, state_with_host):
        args, filename = builder.build_fallback("os_fingerprint", state_with_host)
        assert "-O" in args
        assert "--osscan-guess" in args

    def test_fallback_port_scan_empty_state_raises(self, builder):
        empty_state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        with pytest.raises(ValueError, match="No discovered hosts"):
            builder.build_fallback("port_scan", empty_state)

    def test_fallback_service_enum_empty_state_raises(self, builder):
        empty_state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        with pytest.raises(ValueError, match="No discovered hosts"):
            builder.build_fallback("service_enum", empty_state)

    def test_fallback_os_fingerprint_empty_state_raises(self, builder):
        empty_state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        with pytest.raises(ValueError, match="No discovered hosts"):
            builder.build_fallback("os_fingerprint", empty_state)

    def test_fallback_service_enum_no_ports_raises(self, builder):
        """Host exists but has no known ports — service_enum fallback must not widen scope."""
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")
        with pytest.raises(ValueError, match="No known open ports"):
            builder.build_fallback("service_enum", state)

    def test_fallback_os_fingerprint_no_ports_omits_p(self, builder):
        """Host exists but has no known ports — os_fingerprint works without -p."""
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")
        args, _ = builder.build_fallback("os_fingerprint", state)
        assert "-O" in args
        assert "-p" not in args

    def test_fallback_uses_explicit_target_ip(self, builder):
        """Multi-host: explicit target_ip overrides first-discovered host."""
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        host_a = HostState(ip="192.168.56.101")
        host_a.open_ports = [{"port": 22, "protocol": "tcp", "state": "open"}]
        host_b = HostState(ip="192.168.56.102")
        host_b.open_ports = [{"port": 443, "protocol": "tcp", "state": "open"}]
        state.discovered_hosts["192.168.56.101"] = host_a
        state.discovered_hosts["192.168.56.102"] = host_b
        args, _ = builder.build_fallback("port_scan", state, target_ip="192.168.56.102")
        assert "192.168.56.102" in args
        assert "192.168.56.101" not in args

    def test_fallback_host_discovery_ignores_target_ip(self, builder, state_with_host):
        """host_discovery always targets subnet, even with explicit target_ip."""
        args, _ = builder.build_fallback(
            "host_discovery", state_with_host, target_ip="192.168.56.102"
        )
        assert "192.168.56.0/24" in args
        assert "192.168.56.102" not in args

    def test_fallback_service_enum_explicit_target_uses_its_ports(self, builder):
        """Multi-host: service_enum fallback uses the explicit target's ports."""
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        host_a = HostState(ip="192.168.56.101")
        host_a.open_ports = [
            {"port": 22, "protocol": "tcp", "state": "open"},
            {"port": 80, "protocol": "tcp", "state": "open"},
        ]
        host_b = HostState(ip="192.168.56.102")
        host_b.open_ports = [
            {"port": 443, "protocol": "tcp", "state": "open"},
            {"port": 8080, "protocol": "tcp", "state": "open"},
        ]
        state.discovered_hosts["192.168.56.101"] = host_a
        state.discovered_hosts["192.168.56.102"] = host_b
        args, _ = builder.build_fallback("service_enum", state, target_ip="192.168.56.102")
        p_idx = args.index("-p")
        assert args[p_idx + 1] == "443,8080"
        assert "192.168.56.102" in args
