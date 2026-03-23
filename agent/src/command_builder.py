"""Command builder — maps (stage, LLM params) to nmap arg lists."""

from __future__ import annotations

from datetime import datetime, timezone

from config import AgentConfig
from state import AgentState

# Intensity-to-flags mappings per stage.
# Each value is a list of nmap flag tokens.
_INTENSITY_MAP: dict[str, dict[str, list[str]]] = {
    "host_discovery": {
        "light": ["-sn"],
        "standard": ["-sn", "-PE", "-PP", "-PS21,22,80,443"],
        "aggressive": ["-sn", "-PE", "-PP", "-PS21,22,80,443"],
    },
    "port_scan": {
        "light": ["-sS", "-T4", "-F", "--open"],
        "standard": ["-sS", "-T4", "-p-", "--open"],
        "aggressive": ["-sS", "-T5", "-p-", "--open"],
    },
    "service_enum": {
        "light": ["-sV", "--version-intensity", "2"],
        "standard": ["-sV", "--version-intensity", "5"],
        "aggressive": ["-sV", "-sC"],
    },
    "os_fingerprint": {
        "light": ["-O"],
        "standard": ["-O", "--osscan-guess"],
        "aggressive": ["-O", "--osscan-guess", "--osscan-limit"],
    },
}


class CommandBuilder:
    def __init__(self, config: AgentConfig) -> None:
        self._config = config

    def build(self, stage: str, llm_params: dict, state: AgentState) -> tuple[list[str], str]:
        target = llm_params["target"]
        intensity = llm_params.get("scan_intensity", "standard")
        ports = llm_params.get("ports", "")

        flags = list(_INTENSITY_MAP[stage][intensity])

        # Only service_enum and os_fingerprint use the ports field.
        # host_discovery and port_scan do not — their port range is
        # controlled by intensity flags (e.g. -F vs -p-).
        if ports and stage in ("service_enum", "os_fingerprint"):
            flags.extend(["-p", ports])

        args = flags + [target]

        # Auto-exclude attacker IP on host discovery
        if stage == "host_discovery":
            args.extend(["--exclude", self._config.attacker_ip])

        filename = self._make_filename(stage, target)
        output_path = f"{self._config.output_dir}/{filename}"
        args.extend(["-oX", output_path])

        return args, filename

    def build_fallback(
        self, stage: str, state: AgentState, target_ip: str | None = None
    ) -> tuple[list[str], str]:
        """Deterministic fallback command when LLM output is invalid.

        Args:
            target_ip: Explicit host to target. Used during multi-host iteration
                so the fallback targets the current host, not the first discovered.
                Ignored for host_discovery (always targets subnet).
        """
        if stage == "host_discovery":
            target = self._config.target_subnet
        else:
            target = target_ip or self._get_first_target(state)
            if target is None:
                raise ValueError(
                    f"No discovered hosts available for {stage} fallback — "
                    f"cannot fall back to subnet CIDR for single-host stages"
                )

        if stage == "service_enum" and not state.get_open_ports_csv(target):
            raise ValueError(
                f"No known open ports for {target} — "
                f"cannot build service_enum fallback without port list"
            )

        fallback_params: dict[str, dict] = {
            "host_discovery": {
                "target": self._config.target_subnet,
                "scan_intensity": "light",
            },
            "port_scan": {
                "target": target,
                "scan_intensity": "light",
            },
            "service_enum": {
                "target": target,
                "ports": state.get_open_ports_csv(target),
                "scan_intensity": "standard",
            },
            "os_fingerprint": {
                "target": target,
                "ports": state.get_open_ports_csv(target),
                "scan_intensity": "standard",
            },
        }

        return self.build(stage, fallback_params[stage], state)

    def _get_first_target(self, state: AgentState) -> str | None:
        ips = state.get_target_ips()
        return ips[0] if ips else None

    def _make_filename(self, stage: str, target: str) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("/", "-")
        return f"{stage}_{safe_target}_{ts}.xml"
