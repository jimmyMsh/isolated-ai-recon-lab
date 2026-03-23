"""Prompt templates, schemas, and assembly functions for LLM calls."""

from __future__ import annotations

from config import AgentConfig

SYSTEM_PROMPT = (
    "You are an autonomous network reconnaissance agent. Your task is to "
    "analyze an isolated target subnet and discover what hosts, services, "
    "and operating systems are present.\n\n"
    "You operate in a guided pipeline: host discovery → port scan → service "
    "enumeration → OS fingerprinting. At each stage, you either plan scan "
    "parameters or interpret scan results.\n\n"
    "RULES:\n"
    "- You may ONLY target the subnet provided in your scope.\n"
    "- You may ONLY use nmap.\n"
    "- Exclude the attacker IP from target lists.\n"
    "- Base your decisions on evidence from scan results, not assumptions.\n"
    "- When interpreting results, note anything a penetration tester would "
    "find interesting: outdated software, known vulnerable versions, unusual "
    "ports, or misconfiguration indicators.\n\n"
    "CONTEXT: You will receive the current pipeline stage, accumulated "
    "findings from prior stages, and (for interpretation) the parsed results "
    "from the latest scan. Use all available context to inform your reasoning."
)

PLANNING_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": "IP address, subnet CIDR, or host to scan",
        },
        "ports": {
            "type": "string",
            "description": (
                "Comma-separated ports or range (e.g. '22,80,443' or '1-1024'). "
                "Empty string if not applicable."
            ),
        },
        "scan_intensity": {
            "type": "string",
            "enum": ["light", "standard", "aggressive"],
        },
        "reasoning": {
            "type": "string",
            "description": "Why these parameters are appropriate given the current state",
        },
    },
    "required": ["target", "scan_intensity", "reasoning"],
}

INTERPRETATION_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "description": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": [
                            "informational",
                            "low",
                            "medium",
                            "high",
                            "critical",
                        ],
                    },
                    "mitre_technique": {"type": "string"},
                },
                "required": ["description", "severity"],
            },
        },
        "summary": {"type": "string"},
        "recommendations": {"type": "string"},
    },
    "required": ["findings", "summary", "recommendations"],
}

PLANNING_FEW_SHOT = (
    "EXAMPLE:\n"
    "Given: Pipeline stage is port_scan. State shows host 192.168.56.101 "
    "discovered alive via ARP response.\n"
    'Response: {"target": "192.168.56.101", "ports": "", '
    '"scan_intensity": "standard", "reasoning": "Single live host discovered. '
    "Standard intensity full port scan will identify all open services. "
    "The host responded to ARP which suggests it is directly reachable on "
    'the local segment with minimal filtering."}'
)

INTERPRETATION_FEW_SHOT = (
    "EXAMPLE:\n"
    "Given: Pipeline stage is service_enum. Scan results show port 21 "
    "running vsftpd 2.3.4, port 22 running OpenSSH 4.7p1, port 80 "
    "running Apache 2.2.8.\n"
    'Response: {"findings": [{"description": "vsftpd 2.3.4 on port 21 — '
    "this specific version contains a known backdoor (CVE-2011-2523) that "
    'allows remote code execution", "severity": "critical", '
    '"mitre_technique": "T1046"}, {"description": "OpenSSH 4.7p1 is '
    'severely outdated with multiple known vulnerabilities", '
    '"severity": "high"}, {"description": "Apache 2.2.8 is end-of-life '
    'with known vulnerabilities including mod_proxy flaws", '
    '"severity": "high"}], "summary": "Three services identified with '
    "significant security concerns. The vsftpd 2.3.4 backdoor is the "
    "highest priority finding — it provides trivial remote access. All "
    'software versions are severely outdated.", "recommendations": '
    '"Prioritize investigation of vsftpd 2.3.4 backdoor. Enumerate '
    "additional services on remaining ports. Consider NSE script scanning "
    'for deeper vulnerability assessment."}'
)

STAGE_PLANNING_INSTRUCTIONS: dict[str, str] = {
    "host_discovery": (
        "Plan a host discovery scan on the target subnet to identify all live hosts. "
        "Set target to the full subnet CIDR. Ports are not applicable for this stage. "
        "Choose intensity based on network conditions "
        "— standard is appropriate for an isolated LAN."
    ),
    "port_scan": (
        "Plan a port scan against the discovered target host to identify all open TCP ports. "
        "Set target to the specific host IP from the discovery results. "
        "Ports are not applicable for this stage — intensity controls port range. "
        "Standard intensity scans all 65535 ports; light scans the top 1000."
    ),
    "service_enum": (
        "Plan a service and version enumeration scan on the target's open ports. "
        "Set target to the host IP. Set ports to the open ports discovered in the port scan. "
        "Standard intensity uses version probes; aggressive adds default NSE scripts."
    ),
    "os_fingerprint": (
        "Plan an OS fingerprinting scan on the target host. "
        "Set target to the host IP. Set ports to known open ports to assist fingerprinting. "
        "Standard intensity is sufficient for most cases."
    ),
}

STAGE_INTERPRETATION_INSTRUCTIONS: dict[str, str] = {
    "host_discovery": (
        "Analyze these host discovery results. Identify all live hosts found on the subnet. "
        "Note any interesting indicators from MAC addresses or hostnames. "
        "Assess whether the discovered hosts warrant further investigation."
    ),
    "port_scan": (
        "Analyze these port scan results. Identify the open ports and assess the attack surface. "
        "Note any unusual or high-risk ports. A large number of open ports "
        "suggests an intentionally vulnerable or misconfigured system. "
        "Flag ports commonly associated with known vulnerable services."
    ),
    "service_enum": (
        "Analyze these service enumeration results. "
        "Identify all software and versions running on open ports. "
        "Flag any known vulnerable versions, outdated software, or misconfiguration indicators. "
        "Note any CPE strings that provide structured identification. "
        "This is the richest data in the pipeline — be thorough in your analysis."
    ),
    "os_fingerprint": (
        "Analyze these OS fingerprinting results. "
        "Identify the operating system, kernel version, and confidence level. "
        "Assess the overall security posture by combining OS information "
        "with previously discovered services. "
        "Provide a final synthesis of all findings across all pipeline stages."
    ),
}


def build_planning_prompt(
    stage: str,
    state_context: str,
    config: AgentConfig,
    current_target_info: str | None = None,
) -> list[dict[str, str]]:
    parts = [
        PLANNING_FEW_SHOT,
        "",
        f"CURRENT TASK: {STAGE_PLANNING_INSTRUCTIONS[stage]}",
        f"Target scope: {config.target_subnet}",
        f"Attacker IP (exclude): {config.attacker_ip}",
    ]
    if current_target_info:
        parts.append(current_target_info)
    parts.extend(
        [
            f"CURRENT STATE:\n{state_context}",
            "",
            "Respond with your scan parameters and reasoning. /no_think",
        ]
    )

    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "\n".join(parts)},
    ]


def build_interpretation_prompt(
    stage: str,
    state_context: str,
    parsed_results_json: str,
    config: AgentConfig,
    current_target_info: str | None = None,
) -> list[dict[str, str]]:
    parts = [
        INTERPRETATION_FEW_SHOT,
        "",
        f"CURRENT TASK: {STAGE_INTERPRETATION_INSTRUCTIONS[stage]}",
        f"Target scope: {config.target_subnet}",
    ]
    if current_target_info:
        parts.append(current_target_info)
    parts.extend(
        [
            f"CURRENT STATE (prior findings):\n{state_context}",
            "",
            f"LATEST SCAN RESULTS:\n{parsed_results_json}",
            "",
            "Analyze these results. Note findings a penetration tester would "
            "prioritize. Assess severity. Provide your summary and recommendations. /no_think",
        ]
    )

    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "\n".join(parts)},
    ]
