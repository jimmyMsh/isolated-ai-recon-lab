"""Markdown report generator — deterministic skeleton from state, agent analysis from JSONL log."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from config import AgentConfig
from state import AgentState


class ReportGenerator:
    STAGE_TO_MITRE: dict[str, dict[str, str]] = {
        "host_discovery": {
            "id": "T1595.001",
            "name": "Active Scanning: Scanning IP Blocks",
            "tactic": "Reconnaissance",
        },
        "port_scan": {
            "id": "T1046",
            "name": "Network Service Discovery",
            "tactic": "Discovery",
        },
        "service_enum": {
            "id": "T1046",
            "name": "Network Service Discovery",
            "tactic": "Discovery",
        },
        "os_fingerprint": {
            "id": "T1082",
            "name": "System Information Discovery",
            "tactic": "Discovery",
        },
    }

    def __init__(self, config: AgentConfig) -> None:
        self._config = config

    def generate(
        self,
        state: AgentState,
        log_path: str,
        trace_id: str | None = None,
    ) -> str:
        resolved_trace_id = self._resolve_trace_id(log_path, trace_id)
        events = self._read_log_events(log_path, resolved_trace_id)

        output_dir = Path(self._config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"recon_report_{resolved_trace_id}.md"

        sections = [
            "# Dark Agents — Reconnaissance Report\n",
            self._build_executive_summary(state),
            self._build_scope(state, events),
            self._build_discovered_hosts(state),
            self._build_mitre_findings(state),
            self._build_service_inventory(state),
            self._build_agent_analysis(events),
            self._build_pipeline_summary(events),
        ]

        report = "\n".join(sections)
        report_path.write_text(report)
        return str(report_path)

    # -- trace_id resolution ------------------------------------------------

    @staticmethod
    def _resolve_trace_id(log_path: str, trace_id: str | None) -> str:
        if trace_id is not None:
            return trace_id
        try:
            path = Path(log_path)
            if not path.exists():
                return "unknown"
            lines = path.read_text().strip().splitlines()
            for line in reversed(lines):
                if line.strip():
                    event = json.loads(line)
                    if "trace_id" in event:
                        return event["trace_id"]
        except (json.JSONDecodeError, OSError):
            pass
        return "unknown"

    @staticmethod
    def _read_log_events(log_path: str, trace_id: str) -> list[dict]:
        try:
            path = Path(log_path)
            if not path.exists():
                return []
            events = []
            for line in path.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if event.get("trace_id") == trace_id:
                        events.append(event)
                except json.JSONDecodeError:
                    continue
            return events
        except OSError:
            return []

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _get_best_os(host) -> tuple[str, int]:
        if not host.os_matches:
            return ("Unknown", 0)
        best = max(host.os_matches, key=lambda m: m.get("accuracy", 0))
        return (best.get("name", "Unknown"), best.get("accuracy", 0))

    @staticmethod
    def _format_osclasses(osclasses: list[dict]) -> str:
        parts = []
        for oc in osclasses:
            oc_type = oc.get("type", "")
            os_family = oc.get("os_family", "")
            os_gen = oc.get("os_gen", "")
            parts.append(f"{oc_type} ({os_family}, {os_gen})")
        return "; ".join(parts)

    @staticmethod
    def _collect_osclass_cpes(osclasses: list[dict]) -> list[str]:
        seen = set()
        result = []
        for oc in osclasses:
            for cpe in oc.get("cpe", []):
                if cpe not in seen:
                    seen.add(cpe)
                    result.append(cpe)
        return result

    # -- section builders ---------------------------------------------------

    def _build_executive_summary(self, state: AgentState) -> str:
        host_count = len(state.discovered_hosts)
        port_count = sum(len(h.open_ports) for h in state.discovered_hosts.values())
        service_count = sum(len(h.services) for h in state.discovered_hosts.values())

        sentence1 = (
            f"Reconnaissance scan of {state.target_subnet} discovered "
            f"{host_count} live host(s) with {port_count} open port(s) "
            f"and {service_count} identified service(s)."
        )

        error_count = len(state.errors)
        if error_count == 0:
            sentence2 = "All pipeline stages completed successfully."
        else:
            sentence2 = f"Pipeline completed with {error_count} failure/skip event(s)."

        return f"## Executive Summary\n\n{sentence1} {sentence2}\n"

    def _build_scope(self, state: AgentState, events: list[dict]) -> str:
        scan_date = None
        if events:
            scan_date = events[0].get("timestamp", "")[:10]
        if not scan_date:
            scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        stages = ", ".join(self._config.pipeline_stages)

        return (
            "## Scope\n\n"
            f"- **Target Subnet:** {state.target_subnet}\n"
            f"- **Attacker IP:** {state.attacker_ip}\n"
            f"- **Model:** {self._config.model}\n"
            f"- **Pipeline Stages:** {stages}\n"
            f"- **Tool:** nmap\n"
            f"- **Scan Date:** {scan_date}\n"
        )

    def _build_discovered_hosts(self, state: AgentState) -> str:
        lines = [
            "## Discovered Hosts\n",
            "| IP | MAC | Hostname | OS | Confidence |",
            "|---|---|---|---|---|",
        ]
        for ip in sorted(state.discovered_hosts):
            host = state.discovered_hosts[ip]
            os_name, accuracy = self._get_best_os(host)
            mac = host.mac or "-"
            hostname = host.hostname or "-"
            lines.append(f"| {ip} | {mac} | {hostname} | {os_name} | {accuracy} |")
        if not state.discovered_hosts:
            lines.append("| - | - | - | - | - |")
        return "\n".join(lines) + "\n"

    def _build_mitre_findings(self, state: AgentState) -> str:
        sections = ["## Findings by MITRE ATT&CK Technique\n"]

        # T1595.001 — Host Discovery
        mitre = self.STAGE_TO_MITRE["host_discovery"]
        sections.append(f"### {mitre['id']} — {mitre['name']}\n")
        if state.discovered_hosts:
            for ip in sorted(state.discovered_hosts):
                host = state.discovered_hosts[ip]
                mac = host.mac or "-"
                hostname = host.hostname or "-"
                sections.append(f"- **{ip}** (MAC: {mac}, Hostname: {hostname})")
            sections.append("")
        else:
            sections.append("No hosts discovered.\n")

        # T1046 — Port Scan + Service Enum
        mitre = self.STAGE_TO_MITRE["port_scan"]
        sections.append(f"### {mitre['id']} — {mitre['name']}\n")

        # Port Scan subsection
        sections.append("#### Port Scan Findings\n")
        if any(h.open_ports for h in state.discovered_hosts.values()):
            sections.append("| Host | Port | Protocol | State |")
            sections.append("|---|---|---|---|")
            for ip in sorted(state.discovered_hosts):
                host = state.discovered_hosts[ip]
                for p in host.open_ports:
                    sections.append(f"| {ip} | {p['port']} | {p['protocol']} | {p['state']} |")
            sections.append("")
        else:
            sections.append("No open ports found.\n")

        # Service Enum subsection
        sections.append("#### Service Enumeration Findings\n")
        if any(h.services for h in state.discovered_hosts.values()):
            sections.append("| Host | Port | Protocol | Service | Product | Version |")
            sections.append("|---|---|---|---|---|---|")
            for ip in sorted(state.discovered_hosts):
                host = state.discovered_hosts[ip]
                for s in host.services:
                    sections.append(
                        f"| {ip} | {s['port']} | {s['protocol']} "
                        f"| {s['name']} | {s['product']} | {s['version']} |"
                    )
            sections.append("")
        else:
            sections.append("No services enumerated.\n")

        # T1082 — OS Fingerprint
        mitre = self.STAGE_TO_MITRE["os_fingerprint"]
        sections.append(f"### {mitre['id']} — {mitre['name']}\n")
        has_os = any(h.os_matches for h in state.discovered_hosts.values())
        if has_os:
            sections.append("| Host | OS Name | Accuracy | Classifications | CPE(s) |")
            sections.append("|---|---|---|---|---|")
            for ip in sorted(state.discovered_hosts):
                host = state.discovered_hosts[ip]
                for match in host.os_matches:
                    osclasses = match.get("osclasses", [])
                    classifications = self._format_osclasses(osclasses)
                    cpes = ", ".join(self._collect_osclass_cpes(osclasses))
                    sections.append(
                        f"| {ip} | {match['name']} | {match['accuracy']} "
                        f"| {classifications} | {cpes} |"
                    )
            sections.append("")
        else:
            sections.append("No OS fingerprinting data.\n")

        return "\n".join(sections)

    def _build_service_inventory(self, state: AgentState) -> str:
        lines = [
            "## Detailed Service Inventory\n",
            "| Host | Port | Protocol | Service | Product | Version | CPE(s) |",
            "|---|---|---|---|---|---|---|",
        ]
        for ip in sorted(state.discovered_hosts):
            host = state.discovered_hosts[ip]
            for s in host.services:
                cpe_str = ", ".join(s.get("cpe", []))
                lines.append(
                    f"| {ip} | {s['port']} | {s['protocol']} "
                    f"| {s['name']} | {s['product']} | {s['version']} "
                    f"| {cpe_str} |"
                )
        if not any(h.services for h in state.discovered_hosts.values()):
            lines.append("| - | - | - | - | - | - | - |")
        return "\n".join(lines) + "\n"

    def _build_agent_analysis(self, events: list[dict]) -> str:
        interp_events = [e for e in events if e.get("event_type") == "interpretation_call"]

        lines = [
            "## Agent Analysis\n",
            "> **Note:** This section contains non-deterministic LLM agent "
            "assessment. Findings, severity ratings, and recommendations are "
            "generated by the agent and should be independently verified.\n",
        ]

        if not interp_events:
            lines.append("No agent interpretation events available for this run.\n")
            return "\n".join(lines)

        for event in interp_events:
            stage = event.get("stage", "unknown")
            host_target = event.get("host_target")
            if host_target:
                lines.append(f"### {stage} — {host_target}\n")
            else:
                lines.append(f"### {stage}\n")

            parsed = event.get("llm_output", {}).get("parsed", {})

            summary = parsed.get("summary", "")
            if summary:
                lines.append(f"**Summary:** {summary}\n")

            findings = parsed.get("findings", [])
            if findings:
                lines.append("**Findings:**\n")
                for f in findings:
                    desc = f.get("description", "")
                    severity = f.get("severity", "")
                    if severity:
                        lines.append(f"- [{severity}] {desc}")
                    else:
                        lines.append(f"- {desc}")
                lines.append("")

            recommendations = parsed.get("recommendations", "")
            if recommendations:
                lines.append("**Recommendations:**\n")
                lines.append(f"- {recommendations}")
                lines.append("")

        return "\n".join(lines)

    def _build_pipeline_summary(self, events: list[dict]) -> str:
        stage_events = [e for e in events if e.get("event_type") == "stage_complete"]

        lines = [
            "## Pipeline Execution Summary\n",
        ]

        if not stage_events:
            lines.append("No stage completion events available for this run.\n")
            return "\n".join(lines)

        lines.append(
            "| Stage | Host | MITRE Technique | Duration (s) "
            "| Findings | LLM Calls | Retries | Status |"
        )
        lines.append("|---|---|---|---|---|---|---|---|")

        for event in stage_events:
            stage = event.get("stage", "")
            host = event.get("host_target") or "-"
            mitre_info = self.STAGE_TO_MITRE.get(stage, {})
            mitre = mitre_info.get("id", event.get("mitre_technique", ""))
            duration = event.get("total_stage_duration_seconds", "")
            findings = event.get("findings_count", "")
            llm_calls = event.get("llm_calls", "")
            retries = event.get("retries", "")
            success = event.get("success", False)
            status = "ok" if success else "FAILED"
            lines.append(
                f"| {stage} | {host} | {mitre} | {duration} "
                f"| {findings} | {llm_calls} | {retries} | {status} |"
            )

        return "\n".join(lines) + "\n"
