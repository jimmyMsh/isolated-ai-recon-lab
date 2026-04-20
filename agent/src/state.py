"""Agent state management — code-built, never LLM-built."""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class HostState:
    ip: str
    mac: str | None = None
    hostname: str | None = None
    open_ports: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    os_matches: list[dict] = field(default_factory=list)


@dataclass
class AgentState:
    target_subnet: str
    attacker_ip: str
    discovered_hosts: dict[str, HostState] = field(default_factory=dict)
    current_stage: str = ""
    current_target: str | None = None
    stages_completed: list[str] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    def _ensure_host(self, ip: str) -> HostState:
        if ip not in self.discovered_hosts:
            self.discovered_hosts[ip] = HostState(ip=ip)
        return self.discovered_hosts[ip]

    def update_from_discovery(self, parsed: list[dict]) -> dict:
        hosts_added: list[str] = []
        for entry in parsed:
            ip = entry["ip"]
            # Skip the attacker's own IP — scanning ourselves wastes a full
            # pipeline cycle and pollutes findings. Also enforced by
            # command_builder (--exclude) and guardrails (subnet validation).
            if ip == self.attacker_ip:
                continue
            is_new = ip not in self.discovered_hosts
            host = self._ensure_host(ip)
            if entry.get("mac"):
                host.mac = entry["mac"]
            if entry.get("hostname"):
                host.hostname = entry["hostname"]
            if is_new:
                hosts_added.append(ip)
        return {"hosts_added": hosts_added}

    def update_from_port_scan(self, target_ip: str, parsed: dict) -> dict:
        host = self._ensure_host(target_ip)
        new_ports = parsed.get("ports", [])
        if not new_ports:
            return {}
        host.open_ports = new_ports
        return {"ports_added": {target_ip: [p["port"] for p in new_ports]}}

    def update_from_service_enum(self, target_ip: str, parsed: dict) -> dict:
        host = self._ensure_host(target_ip)
        new_services = parsed.get("services", [])
        if not new_services:
            return {}
        host.services = new_services
        return {"services_added": {target_ip: new_services}}

    def update_from_os_fingerprint(self, target_ip: str, parsed: dict) -> dict:
        host = self._ensure_host(target_ip)
        new_os_matches = parsed.get("os_matches", [])
        if not new_os_matches:
            return {}
        host.os_matches = new_os_matches
        return {"os_matches_added": {target_ip: new_os_matches}}

    def get_target_ips(self) -> list[str]:
        return list(self.discovered_hosts.keys())

    def get_open_ports_csv(self, target_ip: str) -> str:
        host = self.discovered_hosts.get(target_ip)
        if not host or not host.open_ports:
            return ""
        return ",".join(str(p["port"]) for p in host.open_ports)

    def to_prompt_context(self) -> str:
        """JSON string of findings for LLM context. Code-built only.

        Deliberately omits `errors` — error state is handled by the pipeline
        (retries, fallbacks) and should not influence LLM reasoning. Errors
        are logged separately via the JSONL logger.
        """
        hosts_dict = {}
        for ip, host in self.discovered_hosts.items():
            hosts_dict[ip] = {
                "mac": host.mac,
                "hostname": host.hostname,
                "open_ports": host.open_ports,
                "services": host.services,
                "os_matches": host.os_matches,
            }

        context = {
            "target_subnet": self.target_subnet,
            "current_stage": self.current_stage,
            "stages_completed": self.stages_completed,
            "current_target": self.current_target,
            "discovered_hosts": hosts_dict,
        }
        return json.dumps(context, indent=2)

    def to_log_snapshot(self) -> dict:
        """Canonical full-state serialization for JSONL logging.

        Distinct from to_prompt_context(): includes `errors` (never sent to
        the LLM) and `attacker_ip`, and returns a dict rather than a JSON string.
        """
        hosts_dict: dict[str, dict] = {}
        for ip, host in self.discovered_hosts.items():
            hosts_dict[ip] = {
                "mac": host.mac,
                "hostname": host.hostname,
                "open_ports": host.open_ports,
                "services": host.services,
                "os_matches": host.os_matches,
            }
        return {
            "target_subnet": self.target_subnet,
            "attacker_ip": self.attacker_ip,
            "current_stage": self.current_stage,
            "current_target": self.current_target,
            "stages_completed": list(self.stages_completed),
            "errors": list(self.errors),
            "discovered_hosts": hosts_dict,
        }
