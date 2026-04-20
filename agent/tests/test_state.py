"""Tests for state module — HostState, AgentState, and state updates."""

import json

from state import AgentState, HostState


class TestHostState:
    def test_defaults(self):
        host = HostState(ip="192.168.56.101")
        assert host.ip == "192.168.56.101"
        assert host.mac is None
        assert host.hostname is None
        assert host.open_ports == []
        assert host.services == []
        assert host.os_matches == []


class TestAgentState:
    def test_initial_state(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        assert state.target_subnet == "192.168.56.0/24"
        assert state.attacker_ip == "192.168.56.10"
        assert state.discovered_hosts == {}
        assert state.current_stage == ""
        assert state.stages_completed == []
        assert state.errors == []

    def test_update_from_discovery(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        parsed = [
            {
                "ip": "192.168.56.101",
                "mac": "52:54:00:DA:01:01",
                "hostname": "metasploitable.localdomain",
            },
            {
                "ip": "192.168.56.102",
                "mac": "52:54:00:DA:02:02",
                "hostname": None,
            },
        ]

        state.update_from_discovery(parsed)

        assert "192.168.56.101" in state.discovered_hosts
        assert "192.168.56.102" in state.discovered_hosts
        host = state.discovered_hosts["192.168.56.101"]
        assert host.mac == "52:54:00:DA:01:01"
        assert host.hostname == "metasploitable.localdomain"

    def test_update_from_discovery_excludes_attacker(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        parsed = [
            {"ip": "192.168.56.10", "mac": "52:54:00:AA:00:00", "hostname": None},
            {"ip": "192.168.56.101", "mac": "52:54:00:DA:01:01", "hostname": None},
        ]

        state.update_from_discovery(parsed)

        assert "192.168.56.10" not in state.discovered_hosts
        assert "192.168.56.101" in state.discovered_hosts

    def test_update_from_port_scan(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")

        parsed = {
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open"},
                {"port": 80, "protocol": "tcp", "state": "open"},
            ]
        }

        state.update_from_port_scan("192.168.56.101", parsed)

        host = state.discovered_hosts["192.168.56.101"]
        assert len(host.open_ports) == 2
        assert host.open_ports[0]["port"] == 22
        assert host.open_ports[1]["port"] == 80

    def test_update_from_service_enum(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")

        parsed = {
            "services": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "4.7p1",
                    "extrainfo": "Debian 8ubuntu1",
                    "cpe": ["cpe:/a:openbsd:openssh:4.7p1"],
                },
                {
                    "port": 80,
                    "protocol": "tcp",
                    "name": "http",
                    "product": "Apache httpd",
                    "version": "2.2.8",
                    "extrainfo": "(Ubuntu) DAV/2",
                    "cpe": ["cpe:/a:apache:http_server:2.2.8"],
                },
            ]
        }

        state.update_from_service_enum("192.168.56.101", parsed)

        host = state.discovered_hosts["192.168.56.101"]
        assert len(host.services) == 2
        assert host.services[0]["product"] == "OpenSSH"

    def test_update_from_os_fingerprint(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")

        parsed = {
            "os_matches": [
                {
                    "name": "Linux 2.6.9 - 2.6.33",
                    "accuracy": 95,
                    "osclasses": [
                        {
                            "type": "general purpose",
                            "vendor": "Linux",
                            "os_family": "Linux",
                            "os_gen": "2.6.X",
                            "accuracy": 95,
                            "cpe": ["cpe:/o:linux:linux_kernel:2.6"],
                        },
                    ],
                },
            ]
        }

        state.update_from_os_fingerprint("192.168.56.101", parsed)

        host = state.discovered_hosts["192.168.56.101"]
        assert len(host.os_matches) == 1
        assert host.os_matches[0]["accuracy"] == 95

    def test_get_target_ips(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")
        state.discovered_hosts["192.168.56.102"] = HostState(ip="192.168.56.102")

        ips = state.get_target_ips()
        assert sorted(ips) == ["192.168.56.101", "192.168.56.102"]

    def test_get_open_ports_csv(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        host = HostState(ip="192.168.56.101")
        host.open_ports = [
            {"port": 22, "protocol": "tcp", "state": "open"},
            {"port": 80, "protocol": "tcp", "state": "open"},
            {"port": 443, "protocol": "tcp", "state": "open"},
        ]
        state.discovered_hosts["192.168.56.101"] = host

        csv = state.get_open_ports_csv("192.168.56.101")
        assert csv == "22,80,443"

    def test_get_open_ports_csv_empty(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")

        csv = state.get_open_ports_csv("192.168.56.101")
        assert csv == ""

    def test_to_prompt_context_returns_valid_json(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        host = HostState(
            ip="192.168.56.101",
            mac="52:54:00:DA:01:01",
            hostname="metasploitable.localdomain",
        )
        host.open_ports = [{"port": 22, "protocol": "tcp", "state": "open"}]
        state.discovered_hosts["192.168.56.101"] = host
        state.current_stage = "port_scan"
        state.stages_completed = ["host_discovery"]

        context = state.to_prompt_context()

        # Must be valid JSON
        parsed = json.loads(context)
        assert parsed["target_subnet"] == "192.168.56.0/24"
        assert "192.168.56.101" in parsed["discovered_hosts"]

    def test_to_prompt_context_includes_current_target(self):
        """When current_target is set, it appears in the prompt context."""
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")
        state.discovered_hosts["192.168.56.102"] = HostState(ip="192.168.56.102")
        state.current_target = "192.168.56.101"

        context = state.to_prompt_context()
        parsed = json.loads(context)
        assert parsed["current_target"] == "192.168.56.101"

    def test_to_prompt_context_no_current_target(self):
        """When no current_target, field is absent or None."""
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )

        context = state.to_prompt_context()
        parsed = json.loads(context)
        assert parsed.get("current_target") is None

    def test_existing_ports_survive_empty_retry(self):
        """Empty port scan retry must not wipe previously discovered ports."""
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        host = HostState(ip="192.168.56.101")
        host.open_ports = [{"port": 22, "protocol": "tcp", "state": "open"}]
        state.discovered_hosts["192.168.56.101"] = host

        state.update_from_port_scan("192.168.56.101", {"ports": []})

        assert len(state.discovered_hosts["192.168.56.101"].open_ports) == 1
        assert state.discovered_hosts["192.168.56.101"].open_ports[0]["port"] == 22

    def test_existing_services_survive_empty_retry(self):
        """Empty service enum retry must not wipe previously discovered services."""
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        host = HostState(ip="192.168.56.101")
        host.services = [{"port": 22, "name": "ssh", "product": "OpenSSH"}]
        state.discovered_hosts["192.168.56.101"] = host

        state.update_from_service_enum("192.168.56.101", {"services": []})

        assert len(state.discovered_hosts["192.168.56.101"].services) == 1
        assert state.discovered_hosts["192.168.56.101"].services[0]["product"] == "OpenSSH"

    def test_existing_os_matches_survive_empty_retry(self):
        """Empty OS fingerprint retry must not wipe previously discovered OS matches."""
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        host = HostState(ip="192.168.56.101")
        host.os_matches = [{"name": "Linux 2.6.9 - 2.6.33", "accuracy": 95}]
        state.discovered_hosts["192.168.56.101"] = host

        state.update_from_os_fingerprint("192.168.56.101", {"os_matches": []})

        assert len(state.discovered_hosts["192.168.56.101"].os_matches) == 1
        assert state.discovered_hosts["192.168.56.101"].os_matches[0]["accuracy"] == 95

    def test_update_from_port_scan_unknown_host(self):
        """Updating a host that doesn't exist in state should be handled."""
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        parsed = {"ports": [{"port": 22, "protocol": "tcp", "state": "open"}]}

        # Should not raise — creates the host entry
        state.update_from_port_scan("192.168.56.101", parsed)
        assert "192.168.56.101" in state.discovered_hosts


class TestUpdateDeltaReturns:
    """Shared Semantic #6 / File-Change Inventory: update_from_* methods return
    sparse delta dicts recording only what changed for this call.
    """

    def test_update_from_discovery_returns_hosts_added(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        parsed = [
            {"ip": "192.168.56.101", "mac": None, "hostname": None},
            {"ip": "192.168.56.1", "mac": None, "hostname": None},
        ]
        delta = state.update_from_discovery(parsed)
        assert delta == {"hosts_added": ["192.168.56.101", "192.168.56.1"]}

    def test_update_from_discovery_attacker_excluded_from_delta(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        parsed = [
            {"ip": "192.168.56.10", "mac": None, "hostname": None},
            {"ip": "192.168.56.101", "mac": None, "hostname": None},
        ]
        delta = state.update_from_discovery(parsed)
        assert delta == {"hosts_added": ["192.168.56.101"]}

    def test_update_from_discovery_only_new_hosts(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")
        parsed = [
            {"ip": "192.168.56.101", "mac": None, "hostname": None},
            {"ip": "192.168.56.102", "mac": None, "hostname": None},
        ]
        delta = state.update_from_discovery(parsed)
        assert delta == {"hosts_added": ["192.168.56.102"]}

    def test_update_from_port_scan_returns_ports_added(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")
        parsed = {
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open"},
                {"port": 80, "protocol": "tcp", "state": "open"},
            ]
        }
        delta = state.update_from_port_scan("192.168.56.101", parsed)
        assert delta == {"ports_added": {"192.168.56.101": [22, 80]}}

    def test_update_from_port_scan_empty_is_empty_delta(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")
        delta = state.update_from_port_scan("192.168.56.101", {"ports": []})
        assert delta == {}

    def test_update_from_service_enum_returns_services_added(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")
        svc = {
            "port": 22,
            "protocol": "tcp",
            "name": "ssh",
            "product": "OpenSSH",
            "version": "4.7p1",
            "extrainfo": "",
            "cpe": ["cpe:/a:openbsd:openssh:4.7p1"],
        }
        delta = state.update_from_service_enum("192.168.56.101", {"services": [svc]})
        assert delta == {"services_added": {"192.168.56.101": [svc]}}

    def test_update_from_service_enum_empty_is_empty_delta(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")
        delta = state.update_from_service_enum("192.168.56.101", {"services": []})
        assert delta == {}

    def test_update_from_os_fingerprint_returns_os_matches_added(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")
        match = {"name": "Linux 2.6.9 - 2.6.33", "accuracy": 95, "osclasses": []}
        delta = state.update_from_os_fingerprint("192.168.56.101", {"os_matches": [match]})
        assert delta == {"os_matches_added": {"192.168.56.101": [match]}}

    def test_update_from_os_fingerprint_empty_is_empty_delta(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.discovered_hosts["192.168.56.101"] = HostState(ip="192.168.56.101")
        delta = state.update_from_os_fingerprint("192.168.56.101", {"os_matches": []})
        assert delta == {}


class TestToLogSnapshot:
    """File-Change Inventory: to_log_snapshot() — full, canonical shape including errors."""

    def test_empty_state_snapshot(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        snap = state.to_log_snapshot()
        assert snap == {
            "target_subnet": "192.168.56.0/24",
            "attacker_ip": "192.168.56.10",
            "current_stage": "",
            "current_target": None,
            "stages_completed": [],
            "errors": [],
            "discovered_hosts": {},
        }

    def test_snapshot_serializes_host_fields(self):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        host = HostState(
            ip="192.168.56.101",
            mac="52:54:00:DA:01:01",
            hostname="metasploitable.localdomain",
        )
        host.open_ports = [{"port": 22, "protocol": "tcp", "state": "open"}]
        host.services = [{"port": 22, "name": "ssh"}]
        host.os_matches = [{"name": "Linux", "accuracy": 95}]
        state.discovered_hosts["192.168.56.101"] = host

        snap = state.to_log_snapshot()
        assert snap["discovered_hosts"]["192.168.56.101"] == {
            "mac": "52:54:00:DA:01:01",
            "hostname": "metasploitable.localdomain",
            "open_ports": [{"port": 22, "protocol": "tcp", "state": "open"}],
            "services": [{"port": 22, "name": "ssh"}],
            "os_matches": [{"name": "Linux", "accuracy": 95}],
        }

    def test_snapshot_includes_errors(self):
        """Unlike to_prompt_context(), the log snapshot must include errors."""
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.errors.append(
            {
                "stage": "port_scan",
                "host": "192.168.56.101",
                "reason": "execution_failed",
                "detail": "timeout",
            }
        )
        snap = state.to_log_snapshot()
        assert snap["errors"] == [
            {
                "stage": "port_scan",
                "host": "192.168.56.101",
                "reason": "execution_failed",
                "detail": "timeout",
            }
        ]
