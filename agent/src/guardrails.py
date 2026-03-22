"""Guardrails — validation at two pipeline points: after LLM, before exec."""

from __future__ import annotations

import ipaddress
import re

from config import AgentConfig

_VALID_INTENSITIES = {"light", "standard", "aggressive"}
_PLANNING_ALLOWED_FIELDS = {"target", "ports", "scan_intensity", "reasoning"}
_PLANNING_REQUIRED_FIELDS = {"target", "scan_intensity", "reasoning"}

# Nmap flags that take an argument value as the next token.
# Used to distinguish flag-arguments from targets when validating args.
_NMAP_FLAGS_WITH_VALUE = {
    "-oX",
    "-oN",
    "-oG",
    "-oA",
    "-oS",
    "-p",
    "--exclude",
    "--excludefile",
    "-e",
    "-iL",
    "-iR",
    "--source-port",
    "--data-length",
    "--max-retries",
    "--host-timeout",
    "--scan-delay",
    "--min-rate",
    "--max-rate",
    "--version-intensity",
}


class GuardrailViolation(Exception):  # noqa: N818 — name matches domain concept, not renaming
    def __init__(self, rule: str, detail: str) -> None:
        self.rule = rule
        self.detail = detail
        super().__init__(f"[{rule}] {detail}")


class Guardrails:
    def __init__(self, config: AgentConfig) -> None:
        self._subnet = ipaddress.ip_network(config.target_subnet, strict=False)
        self._attacker_ip = config.attacker_ip
        self._allowed_tools = config.allowed_tools

    def is_ip_in_subnet(self, ip_or_cidr: str) -> bool:
        try:
            net = ipaddress.ip_network(ip_or_cidr, strict=False)
            # Check that every address in the given network is within our subnet
            return (
                net.network_address >= self._subnet.network_address
                and net.broadcast_address <= self._subnet.broadcast_address
            )
        except (ValueError, TypeError):
            return False

    def is_valid_port_spec(self, ports: str) -> bool:
        if not ports:
            return True
        # Accept comma-separated ports and ranges like "22,80,8000-9000"
        pattern = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")
        if not pattern.match(ports):
            return False
        # Check each port/range is within valid range
        for part in ports.split(","):
            if "-" in part:
                low, high = part.split("-", 1)
                if not (0 < int(low) <= 65535 and 0 < int(high) <= 65535):
                    return False
                if int(low) > int(high):
                    return False
            else:
                if not (0 < int(part) <= 65535):
                    return False
        return True

    def validate_planning_response(self, stage: str, response: dict) -> dict:
        """Validate LLM planning output. Returns cleaned dict with only allowed fields."""
        # Check required fields
        for field in _PLANNING_REQUIRED_FIELDS:
            if field not in response:
                raise GuardrailViolation(
                    "missing_required_field",
                    f"Planning response missing required field: {field}",
                )

        # Validate target is in subnet
        target = response["target"]
        if not self.is_ip_in_subnet(target):
            raise GuardrailViolation(
                "target_outside_subnet",
                f"Target {target} is outside allowed subnet {self._subnet}",
            )

        # Reject attacker IP as target for single-host stages
        if stage != "host_discovery" and target == self._attacker_ip:
            raise GuardrailViolation(
                "target_is_attacker_ip",
                f"Target {target} is the attacker IP",
            )

        # Validate scan intensity
        intensity = response["scan_intensity"]
        if intensity not in _VALID_INTENSITIES:
            raise GuardrailViolation(
                "invalid_scan_intensity",
                f"Invalid scan_intensity '{intensity}', must be one of {_VALID_INTENSITIES}",
            )

        # Validate ports if present
        ports = response.get("ports", "")
        if ports and not self.is_valid_port_spec(ports):
            raise GuardrailViolation(
                "invalid_port_spec",
                f"Invalid port specification: {ports}",
            )

        # Stage-specific invariants
        self._validate_stage_invariants(stage, target, ports)

        # Strip unexpected fields — only return what we expect
        return {k: response[k] for k in _PLANNING_ALLOWED_FIELDS if k in response}

    def _validate_stage_invariants(self, stage: str, target: str, ports: str) -> None:
        """Enforce stage-specific planning invariants."""
        if stage == "host_discovery":
            # Target must be the configured subnet, not a single host
            target_net = ipaddress.ip_network(target, strict=False)
            if target_net != self._subnet:
                raise GuardrailViolation(
                    "invalid_target_for_stage",
                    f"host_discovery target must be the configured subnet "
                    f"{self._subnet}, got {target}",
                )
            # Ports are not applicable for host discovery
            if ports:
                raise GuardrailViolation(
                    "invalid_ports_for_stage",
                    "host_discovery does not use ports",
                )
        elif stage == "port_scan":
            # Target must be a single host IP, not a subnet
            target_net = ipaddress.ip_network(target, strict=False)
            if target_net.num_addresses != 1:
                raise GuardrailViolation(
                    "invalid_target_for_stage",
                    f"port_scan requires a single host target, got {target}",
                )
            # Ports are not applicable — intensity controls port range
            if ports:
                raise GuardrailViolation(
                    "invalid_ports_for_stage",
                    "port_scan does not use ports — intensity controls port range",
                )
        elif stage in ("service_enum", "os_fingerprint"):
            # Target must be a single host IP, not a subnet
            target_net = ipaddress.ip_network(target, strict=False)
            if target_net.num_addresses != 1:
                raise GuardrailViolation(
                    "invalid_target_for_stage",
                    f"{stage} requires a single host target, got {target}",
                )
            # service_enum requires non-empty ports
            if stage == "service_enum" and not ports:
                raise GuardrailViolation(
                    "missing_ports_for_stage",
                    "service_enum requires non-empty ports",
                )

    def validate_nmap_args(self, args: list[str]) -> None:
        """Validate nmap command args before execution. Raises GuardrailViolation."""
        # Extract targets: arguments that look like IPs/CIDRs (not flags or flag values)
        targets = self._extract_targets(args)

        if not targets:
            raise GuardrailViolation(
                "no_target",
                "No scan target found in nmap arguments",
            )

        for target in targets:
            if not self.is_ip_in_subnet(target):
                raise GuardrailViolation(
                    "target_outside_subnet",
                    f"Target {target} is outside allowed subnet {self._subnet}",
                )
            if target == self._attacker_ip:
                raise GuardrailViolation(
                    "target_is_attacker_ip",
                    f"Target {target} is the attacker IP",
                )

    def _extract_targets(self, args: list[str]) -> list[str]:
        """Extract probable target IPs/CIDRs from nmap args, skipping flags and their values."""
        targets = []
        skip_next = False
        for arg in args:
            if skip_next:
                skip_next = False
                continue
            if arg in _NMAP_FLAGS_WITH_VALUE:
                skip_next = True
                continue
            if arg.startswith("-"):
                # Flags like -sS, -T4, --open, -p- etc.
                # Handle joined flag+value like -p22,80
                continue
            # Non-flag argument — likely a target IP or CIDR
            targets.append(arg)
        return targets
