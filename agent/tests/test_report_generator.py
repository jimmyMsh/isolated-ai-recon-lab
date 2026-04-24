"""Tests for report_generator module — Markdown report from AgentState + JSONL log."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from config import AgentConfig
from report_generator import ReportGenerator
from state import AgentState, HostState

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TRACE_ID = "run_20260328_120000_12345"


@pytest.fixture()
def config(tmp_path):
    return AgentConfig(
        ollama_url="http://localhost:11434",
        model="qwen3:8b",
        target_subnet="192.168.56.0/24",
        attacker_ip="192.168.56.10",
        nmap_path="/usr/bin/nmap",
        output_dir=str(tmp_path / "output"),
        log_file=str(tmp_path / "output" / "agent.log.jsonl"),
    )


@pytest.fixture()
def sample_state():
    state = AgentState(
        target_subnet="192.168.56.0/24",
        attacker_ip="192.168.56.10",
    )
    host = HostState(
        ip="192.168.56.101",
        mac="52:54:00:DA:01:01",
        hostname="metasploitable.localdomain",
    )
    host.open_ports = [
        {"port": 21, "protocol": "tcp", "state": "open"},
        {"port": 22, "protocol": "tcp", "state": "open"},
        {"port": 80, "protocol": "tcp", "state": "open"},
        {"port": 445, "protocol": "tcp", "state": "open"},
    ]
    host.services = [
        {
            "port": 21,
            "protocol": "tcp",
            "name": "ftp",
            "product": "vsftpd",
            "version": "2.3.4",
            "extrainfo": "",
            "cpe": ["cpe:/a:vsftpd:vsftpd:2.3.4"],
        },
        {
            "port": 22,
            "protocol": "tcp",
            "name": "ssh",
            "product": "OpenSSH",
            "version": "4.7p1",
            "extrainfo": "Debian 8ubuntu1",
            "cpe": ["cpe:/a:openbsd:openssh:4.7p1", "cpe:/o:linux:linux_kernel"],
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
        {
            "port": 445,
            "protocol": "tcp",
            "name": "netbios-ssn",
            "product": "Samba smbd",
            "version": "3.X - 4.X",
            "extrainfo": "",
            "cpe": [],
        },
    ]
    host.os_matches = [
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
        {
            "name": "Linux 2.6.32",
            "accuracy": 90,
            "osclasses": [
                {
                    "type": "general purpose",
                    "vendor": "Linux",
                    "os_family": "Linux",
                    "os_gen": "2.6.X",
                    "accuracy": 90,
                    "cpe": ["cpe:/o:linux:linux_kernel:2.6.32"],
                },
            ],
        },
    ]
    state.discovered_hosts["192.168.56.101"] = host
    state.stages_completed = [
        "host_discovery",
        "port_scan",
        "service_enum",
        "os_fingerprint",
    ]
    return state


@pytest.fixture()
def multi_host_state(sample_state):
    host2 = HostState(
        ip="192.168.56.102",
        mac="52:54:00:DA:02:02",
        hostname=None,
    )
    host2.open_ports = [
        {"port": 80, "protocol": "tcp", "state": "open"},
    ]
    host2.services = [
        {
            "port": 80,
            "protocol": "tcp",
            "name": "http",
            "product": "nginx",
            "version": "1.18.0",
            "extrainfo": "",
            "cpe": ["cpe:/a:nginx:nginx:1.18.0"],
        },
    ]
    host2.os_matches = []
    sample_state.discovered_hosts["192.168.56.102"] = host2
    return sample_state


@pytest.fixture()
def empty_state():
    return AgentState(
        target_subnet="192.168.56.0/24",
        attacker_ip="192.168.56.10",
    )


def _write_synthetic_log(
    log_path: str | Path,
    trace_id: str,
    multi_host: bool = False,
) -> None:
    """Write realistic JSONL events for all 4 stages."""
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    events = []

    def _evt(event_type, stage, data, host_target=None):
        return {
            "timestamp": "2026-03-28T12:00:00+00:00",
            "trace_id": trace_id,
            "span_id": f"span_{len(events) + 1:03d}",
            "parent_span_id": None,
            "surface": "cognitive" if event_type.endswith("_call") else "operational",
            "event_type": event_type,
            "stage": stage,
            "stage_attempt": 1,
            "host_target": host_target,
            **data,
        }

    # host_discovery
    events.append(
        _evt(
            "interpretation_call",
            "host_discovery",
            {
                "llm_input": {"messages": []},
                "llm_output": {
                    "parsed": {
                        "summary": "Discovered 2 live hosts on the subnet.",
                        "findings": [
                            {
                                "description": "Host 192.168.56.101 is up",
                                "severity": "informational",
                            }
                        ],
                        "recommendations": "Proceed with port scanning.",
                    },
                    "raw_content": "{}",
                },
                "duration_seconds": 2.0,
            },
        )
    )
    events.append(
        _evt(
            "stage_complete",
            "host_discovery",
            {
                "success": True,
                "findings_count": 2,
                "total_stage_duration_seconds": 10.5,
                "llm_calls": 2,
                "retries": 0,
                "mitre_technique": "T1595.001",
            },
        )
    )

    # port_scan — per host
    hosts = ["192.168.56.101"]
    if multi_host:
        hosts.append("192.168.56.102")
    for host_ip in hosts:
        events.append(
            _evt(
                "interpretation_call",
                "port_scan",
                {
                    "llm_input": {"messages": []},
                    "llm_output": {
                        "parsed": {
                            "summary": f"Port scan of {host_ip} found open ports.",
                            "findings": [
                                {
                                    "description": f"Multiple open ports on {host_ip}",
                                    "severity": "medium",
                                }
                            ],
                            "recommendations": "Enumerate services on discovered ports.",
                        },
                        "raw_content": "{}",
                    },
                    "duration_seconds": 1.5,
                },
                host_target=host_ip,
            )
        )
        events.append(
            _evt(
                "stage_complete",
                "port_scan",
                {
                    "success": True,
                    "findings_count": 4 if host_ip == "192.168.56.101" else 1,
                    "total_stage_duration_seconds": 22.0,
                    "llm_calls": 2,
                    "retries": 0,
                    "mitre_technique": "T1046",
                },
                host_target=host_ip,
            )
        )

    # service_enum — per host
    for host_ip in hosts:
        events.append(
            _evt(
                "interpretation_call",
                "service_enum",
                {
                    "llm_input": {"messages": []},
                    "llm_output": {
                        "parsed": {
                            "summary": f"Service enumeration of {host_ip} complete.",
                            "findings": [
                                {
                                    "description": "vsftpd 2.3.4 is critically vulnerable",
                                    "severity": "critical",
                                }
                            ],
                            "recommendations": "Patch vsftpd immediately.",
                        },
                        "raw_content": "{}",
                    },
                    "duration_seconds": 3.0,
                },
                host_target=host_ip,
            )
        )
        events.append(
            _evt(
                "stage_complete",
                "service_enum",
                {
                    "success": True,
                    "findings_count": 4 if host_ip == "192.168.56.101" else 1,
                    "total_stage_duration_seconds": 30.0,
                    "llm_calls": 2,
                    "retries": 0,
                    "mitre_technique": "T1046",
                },
                host_target=host_ip,
            )
        )

    # os_fingerprint — per host
    for host_ip in hosts:
        events.append(
            _evt(
                "interpretation_call",
                "os_fingerprint",
                {
                    "llm_input": {"messages": []},
                    "llm_output": {
                        "parsed": {
                            "summary": f"OS fingerprinting of {host_ip} complete.",
                            "findings": [
                                {
                                    "description": "Running Linux 2.6.x kernel",
                                    "severity": "informational",
                                }
                            ],
                            "recommendations": "Check for kernel updates.",
                        },
                        "raw_content": "{}",
                    },
                    "duration_seconds": 2.5,
                },
                host_target=host_ip,
            )
        )
        events.append(
            _evt(
                "stage_complete",
                "os_fingerprint",
                {
                    "success": True,
                    "findings_count": 2,
                    "total_stage_duration_seconds": 15.0,
                    "llm_calls": 2,
                    "retries": 0,
                    "mitre_technique": "T1082",
                },
                host_target=host_ip,
            )
        )

    with open(log_path, "w") as f:
        for evt in events:
            f.write(json.dumps(evt) + "\n")


# ---------------------------------------------------------------------------
# TestGenerateContract
# ---------------------------------------------------------------------------


class TestGenerateContract:
    def test_returns_file_path(self, config, sample_state):
        log_path = config.log_file
        _write_synthetic_log(log_path, TRACE_ID)
        gen = ReportGenerator(config)
        result = gen.generate(sample_state, log_path, trace_id=TRACE_ID)
        assert Path(result).exists()

    def test_filename_contains_trace_id(self, config, sample_state):
        log_path = config.log_file
        _write_synthetic_log(log_path, TRACE_ID)
        gen = ReportGenerator(config)
        result = gen.generate(sample_state, log_path, trace_id=TRACE_ID)
        assert result.endswith(f"recon_report_{TRACE_ID}.md")

    def test_writes_to_output_dir(self, config, sample_state):
        log_path = config.log_file
        _write_synthetic_log(log_path, TRACE_ID)
        gen = ReportGenerator(config)
        result = gen.generate(sample_state, log_path, trace_id=TRACE_ID)
        assert str(config.output_dir) in result

    def test_creates_output_dir_if_missing(self, tmp_path, sample_state):
        nested = tmp_path / "deep" / "nested"
        cfg = AgentConfig(
            ollama_url="http://localhost:11434",
            model="qwen3:8b",
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
            nmap_path="/usr/bin/nmap",
            output_dir=str(nested),
            log_file=str(nested / "agent.log.jsonl"),
        )
        gen = ReportGenerator(cfg)
        result = gen.generate(sample_state, cfg.log_file, trace_id=TRACE_ID)
        assert Path(result).exists()


# ---------------------------------------------------------------------------
# TestTraceIdResolution
# ---------------------------------------------------------------------------


class TestTraceIdResolution:
    def test_explicit_trace_id_used(self, config, sample_state):
        _write_synthetic_log(config.log_file, TRACE_ID)
        gen = ReportGenerator(config)
        result = gen.generate(sample_state, config.log_file, trace_id="run_test_123")
        assert "run_test_123" in Path(result).name

    def test_inferred_from_last_log_line(self, config, sample_state):
        log_path = Path(config.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "w") as f:
            f.write(json.dumps({"trace_id": "run_old_001"}) + "\n")
            f.write(json.dumps({"trace_id": "run_latest_002"}) + "\n")
        gen = ReportGenerator(config)
        result = gen.generate(sample_state, config.log_file, trace_id=None)
        assert "run_latest_002" in Path(result).name

    def test_missing_log_uses_fallback(self, config, sample_state):
        gen = ReportGenerator(config)
        result = gen.generate(sample_state, "/nonexistent/path/log.jsonl", trace_id=None)
        assert "unknown" in Path(result).name
        assert Path(result).exists()

    def test_empty_log_uses_fallback(self, config, sample_state):
        log_path = Path(config.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("")
        gen = ReportGenerator(config)
        result = gen.generate(sample_state, config.log_file, trace_id=None)
        assert "unknown" in Path(result).name


# ---------------------------------------------------------------------------
# TestExecutiveSummary
# ---------------------------------------------------------------------------


class TestExecutiveSummary:
    @pytest.fixture(autouse=True)
    def _generate(self, config, sample_state):
        _write_synthetic_log(config.log_file, TRACE_ID)
        gen = ReportGenerator(config)
        path = gen.generate(sample_state, config.log_file, trace_id=TRACE_ID)
        self.report = Path(path).read_text()

    def test_heading_present(self):
        assert "## Executive Summary" in self.report

    def test_contains_host_count(self):
        assert "1" in self.report.split("## Executive Summary")[1].split("##")[0]

    def test_contains_port_count(self):
        assert "4" in self.report.split("## Executive Summary")[1].split("##")[0]

    def test_contains_subnet(self):
        assert "192.168.56.0/24" in self.report

    def test_error_count_uses_failure_skip_wording(self, config):
        """Shared Semantic #2: state.errors records failure/skip events, not literal
        stage failures. Executive summary wording must match.
        """
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        state.errors.append(
            {
                "stage": "service_enum",
                "host": "192.168.56.101",
                "reason": "no_known_ports",
                "detail": None,
            }
        )
        _write_synthetic_log(config.log_file, TRACE_ID)
        gen = ReportGenerator(config)
        path = gen.generate(state, config.log_file, trace_id=TRACE_ID)
        report = Path(path).read_text()
        assert "Pipeline completed with 1 failure/skip event(s)." in report
        assert "stage failure" not in report.lower()


def test_executive_summary_interrupted_run(config, sample_state):
    """When state.errors carries an operator_interrupt entry, the Executive
    Summary must say the run was interrupted using internally consistent
    units (configured stages completed against configured stages expected),
    rather than 'All pipeline stages completed successfully' or the generic
    'failure/skip event(s)' wording.
    """
    state = sample_state
    state.stages_completed = ["host_discovery", "port_scan"]
    state.errors.append(
        {
            "stage": "service_enum",
            "host": None,
            "reason": "operator_interrupt",
            "detail": "run interrupted by operator",
        }
    )
    _write_synthetic_log(config.log_file, TRACE_ID)
    gen = ReportGenerator(config)
    path = gen.generate(state, config.log_file, trace_id=TRACE_ID)
    report = Path(path).read_text()
    total = len(config.pipeline_stages)
    assert f"Pipeline was interrupted after 2 of {total} stages completed." in report
    assert "All pipeline stages completed successfully" not in report
    assert "Pipeline completed with 1 failure/skip event(s)." not in report


# ---------------------------------------------------------------------------
# TestScopeSection
# ---------------------------------------------------------------------------


class TestScopeSection:
    @pytest.fixture(autouse=True)
    def _generate(self, config, sample_state):
        _write_synthetic_log(config.log_file, TRACE_ID)
        gen = ReportGenerator(config)
        path = gen.generate(sample_state, config.log_file, trace_id=TRACE_ID)
        self.report = Path(path).read_text()

    def test_contains_target_subnet(self):
        assert "192.168.56.0/24" in self.report

    def test_contains_attacker_ip(self):
        assert "192.168.56.10" in self.report

    def test_contains_model(self):
        assert "qwen3:8b" in self.report

    def test_contains_pipeline_stages(self):
        for stage in [
            "host_discovery",
            "port_scan",
            "service_enum",
            "os_fingerprint",
        ]:
            assert stage in self.report

    def test_scan_date_from_log(self):
        assert "2026-03-28" in self.report

    def test_scan_date_fallback_without_log(self, config, sample_state):
        gen = ReportGenerator(config)
        path = gen.generate(sample_state, "/nonexistent/log.jsonl", trace_id=TRACE_ID)
        report = Path(path).read_text()
        # Should still have some date string in the scope section
        scope = report.split("## Scope")[1].split("##")[0]
        assert any(c.isdigit() for c in scope)


# ---------------------------------------------------------------------------
# TestDiscoveredHostsTable
# ---------------------------------------------------------------------------


class TestDiscoveredHostsTable:
    @pytest.fixture(autouse=True)
    def _generate(self, config, sample_state):
        _write_synthetic_log(config.log_file, TRACE_ID)
        gen = ReportGenerator(config)
        path = gen.generate(sample_state, config.log_file, trace_id=TRACE_ID)
        self.report = Path(path).read_text()

    def test_heading_present(self):
        assert "## Discovered Hosts" in self.report

    def test_contains_ip(self):
        assert "192.168.56.101" in self.report

    def test_contains_mac(self):
        assert "52:54:00:DA:01:01" in self.report

    def test_contains_hostname(self):
        assert "metasploitable.localdomain" in self.report

    def test_os_uses_highest_accuracy(self):
        section = self.report.split("## Discovered Hosts")[1].split("##")[0]
        assert "Linux 2.6.9 - 2.6.33" in section
        assert "95" in section

    def test_os_unknown_when_no_matches(self, config, multi_host_state):
        _write_synthetic_log(config.log_file, TRACE_ID, multi_host=True)
        gen = ReportGenerator(config)
        path = gen.generate(multi_host_state, config.log_file, trace_id=TRACE_ID)
        report = Path(path).read_text()
        section = report.split("## Discovered Hosts")[1].split("##")[0]
        assert "Unknown" in section


# ---------------------------------------------------------------------------
# TestMitreFindings
# ---------------------------------------------------------------------------


class TestMitreFindings:
    @pytest.fixture(autouse=True)
    def _generate(self, config, sample_state):
        _write_synthetic_log(config.log_file, TRACE_ID)
        gen = ReportGenerator(config)
        path = gen.generate(sample_state, config.log_file, trace_id=TRACE_ID)
        self.report = Path(path).read_text()

    def test_section_heading_present(self):
        assert "## Findings by MITRE ATT&CK Technique" in self.report

    def test_t1595_001_section_present(self):
        assert "### T1595.001" in self.report

    def test_t1595_001_lists_hosts(self):
        section = self.report.split("### T1595.001")[1].split("###")[0]
        assert "192.168.56.101" in section

    def test_t1046_has_two_subsections(self):
        assert "#### Port Scan Findings" in self.report
        assert "#### Service Enumeration Findings" in self.report

    def test_t1046_port_scan_shows_ports(self):
        section = self.report.split("#### Port Scan Findings")[1].split("####")[0]
        for port in ["21", "22", "80", "445"]:
            assert port in section

    def test_t1046_service_enum_shows_products(self):
        section = self.report.split("#### Service Enumeration Findings")[1].split("###")[0]
        assert "vsftpd" in section
        assert "OpenSSH" in section
        assert "Apache" in section

    def test_t1082_section_present(self):
        assert "### T1082" in self.report

    def test_t1082_shows_os_matches(self):
        section = self.report.split("### T1082")[1].split("##")[0]
        assert "Linux 2.6.9 - 2.6.33" in section
        assert "95" in section

    def test_t1082_shows_osclass_details(self):
        section = self.report.split("### T1082")[1].split("##")[0]
        assert "general purpose" in section
        assert "Linux" in section

    def test_t1082_multi_osclass_joined(self, config):
        state = AgentState(
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
        )
        host = HostState(ip="192.168.56.101")
        host.os_matches = [
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
                    {
                        "type": "WAP",
                        "vendor": "Linux",
                        "os_family": "Linux",
                        "os_gen": "2.6.X",
                        "accuracy": 95,
                        "cpe": ["cpe:/o:linux:linux_kernel:2.6"],
                    },
                ],
            },
        ]
        state.discovered_hosts["192.168.56.101"] = host
        _write_synthetic_log(config.log_file, TRACE_ID)
        gen = ReportGenerator(config)
        path = gen.generate(state, config.log_file, trace_id=TRACE_ID)
        report = Path(path).read_text()
        section = report.split("### T1082")[1].split("##")[0]
        assert "general purpose" in section
        assert "WAP" in section


# ---------------------------------------------------------------------------
# TestServiceInventory
# ---------------------------------------------------------------------------


class TestServiceInventory:
    @pytest.fixture(autouse=True)
    def _generate(self, config, sample_state):
        _write_synthetic_log(config.log_file, TRACE_ID)
        gen = ReportGenerator(config)
        path = gen.generate(sample_state, config.log_file, trace_id=TRACE_ID)
        self.report = Path(path).read_text()

    def test_heading_present(self):
        assert "## Detailed Service Inventory" in self.report

    def test_no_severity_column(self):
        section = self.report.split("## Detailed Service Inventory")[1].split("##")[0]
        header_line = [line for line in section.split("\n") if line.startswith("| ")][0]
        assert "Severity" not in header_line

    def test_contains_cpe(self):
        assert "cpe:/a:vsftpd:vsftpd:2.3.4" in self.report

    def test_multi_cpe_joined(self):
        section = self.report.split("## Detailed Service Inventory")[1].split("##")[0]
        assert "cpe:/a:openbsd:openssh:4.7p1" in section
        assert "cpe:/o:linux:linux_kernel" in section

    def test_empty_cpe_handled(self):
        # SMB service has empty CPE list — should not crash
        section = self.report.split("## Detailed Service Inventory")[1].split("##")[0]
        assert "445" in section


# ---------------------------------------------------------------------------
# TestAgentAnalysis
# ---------------------------------------------------------------------------


class TestAgentAnalysis:
    @pytest.fixture(autouse=True)
    def _generate(self, config, sample_state):
        _write_synthetic_log(config.log_file, TRACE_ID)
        gen = ReportGenerator(config)
        path = gen.generate(sample_state, config.log_file, trace_id=TRACE_ID)
        self.report = Path(path).read_text()
        self.config = config

    def test_heading_present(self):
        assert "## Agent Analysis" in self.report

    def test_non_deterministic_label(self):
        section = self.report.split("## Agent Analysis")[1].split("##")[0]
        assert any(w in section.lower() for w in ["non-deterministic", "llm", "agent"])

    def test_per_stage_subsections(self):
        section = self.report.split("## Agent Analysis")[1].split("## Pipeline Execution Summary")[
            0
        ]
        assert "host_discovery" in section
        assert "port_scan" in section
        assert "service_enum" in section
        assert "os_fingerprint" in section

    def test_host_target_in_heading(self):
        section = self.report.split("## Agent Analysis")[1].split("## Pipeline Execution Summary")[
            0
        ]
        # port_scan has host_target="192.168.56.101"
        assert "192.168.56.101" in section

    def test_null_host_target_omitted(self):
        section = self.report.split("## Agent Analysis")[1].split("## Pipeline Execution Summary")[
            0
        ]
        # Find the host_discovery subsection heading — should not have an IP
        lines = section.split("\n")
        hd_headings = [
            line for line in lines if "host_discovery" in line and line.strip().startswith("###")
        ]
        assert len(hd_headings) >= 1
        assert "192.168.56" not in hd_headings[0]

    def test_contains_findings(self):
        section = self.report.split("## Agent Analysis")[1].split("## Pipeline Execution Summary")[
            0
        ]
        assert "vsftpd 2.3.4 is critically vulnerable" in section

    def test_contains_summary(self):
        section = self.report.split("## Agent Analysis")[1].split("## Pipeline Execution Summary")[
            0
        ]
        assert "Discovered 2 live hosts" in section

    def test_contains_severity(self):
        section = self.report.split("## Agent Analysis")[1].split("## Pipeline Execution Summary")[
            0
        ]
        assert "critical" in section.lower()

    def test_missing_log_shows_placeholder(self, config, sample_state):
        gen = ReportGenerator(config)
        path = gen.generate(sample_state, "/nonexistent/log.jsonl", trace_id=TRACE_ID)
        report = Path(path).read_text()
        section = report.split("## Agent Analysis")[1].split("##")[0]
        assert "No agent interpretation events available" in section

    def test_no_matching_trace_shows_placeholder(self, config, sample_state):
        _write_synthetic_log(config.log_file, "run_different_trace")
        gen = ReportGenerator(config)
        path = gen.generate(sample_state, config.log_file, trace_id=TRACE_ID)
        report = Path(path).read_text()
        section = report.split("## Agent Analysis")[1].split("##")[0]
        assert "No agent interpretation events available" in section

    def test_multi_host_separate_subsections(self, config, multi_host_state):
        _write_synthetic_log(config.log_file, TRACE_ID, multi_host=True)
        gen = ReportGenerator(config)
        path = gen.generate(multi_host_state, config.log_file, trace_id=TRACE_ID)
        report = Path(path).read_text()
        section = report.split("## Agent Analysis")[1].split("## Pipeline Execution Summary")[0]
        assert "192.168.56.101" in section
        assert "192.168.56.102" in section


# ---------------------------------------------------------------------------
# TestPipelineSummary
# ---------------------------------------------------------------------------


class TestPipelineSummary:
    @pytest.fixture(autouse=True)
    def _generate(self, config, sample_state):
        _write_synthetic_log(config.log_file, TRACE_ID)
        gen = ReportGenerator(config)
        path = gen.generate(sample_state, config.log_file, trace_id=TRACE_ID)
        self.report = Path(path).read_text()
        self.config = config

    def test_heading_present(self):
        assert "## Pipeline Execution Summary" in self.report

    def test_table_has_expected_columns(self):
        section = self.report.split("## Pipeline Execution Summary")[1]
        header_line = [line for line in section.split("\n") if line.startswith("| ")][0]
        for col in ["Stage", "Host", "MITRE Technique", "Duration", "Findings", "Status"]:
            assert col in header_line

    def test_contains_stage_data(self):
        section = self.report.split("## Pipeline Execution Summary")[1]
        assert "host_discovery" in section
        assert "T1595.001" in section
        assert "T1046" in section
        assert "T1082" in section

    def test_one_row_per_event(self, config, multi_host_state):
        _write_synthetic_log(config.log_file, TRACE_ID, multi_host=True)
        gen = ReportGenerator(config)
        path = gen.generate(multi_host_state, config.log_file, trace_id=TRACE_ID)
        report = Path(path).read_text()
        section = report.split("## Pipeline Execution Summary")[1]
        # port_scan should appear at least twice (once per host)
        port_scan_rows = [
            row for row in section.split("\n") if "port_scan" in row and row.startswith("| ")
        ]
        assert len(port_scan_rows) >= 2

    def test_host_column_from_host_target(self):
        section = self.report.split("## Pipeline Execution Summary")[1]
        lines = [row for row in section.split("\n") if row.startswith("| ")]
        # host_discovery row should have "-" for host
        hd_row = [row for row in lines if "host_discovery" in row]
        assert len(hd_row) >= 1
        assert "-" in hd_row[0]
        # port_scan row should have the host IP
        ps_row = [row for row in lines if "port_scan" in row]
        assert len(ps_row) >= 1
        assert "192.168.56.101" in ps_row[0]

    def test_missing_log_shows_placeholder(self, config, sample_state):
        gen = ReportGenerator(config)
        path = gen.generate(sample_state, "/nonexistent/log.jsonl", trace_id=TRACE_ID)
        report = Path(path).read_text()
        section = report.split("## Pipeline Execution Summary")[1]
        assert "No stage completion events available" in section


# ---------------------------------------------------------------------------
# TestEdgeCases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_state_generates_report(self, config, empty_state):
        gen = ReportGenerator(config)
        path = gen.generate(empty_state, "/nonexistent/log.jsonl", trace_id=TRACE_ID)
        report = Path(path).read_text()
        assert "## Executive Summary" in report
        assert "## Scope" in report
        assert "## Discovered Hosts" in report
        assert "## Findings by MITRE ATT&CK Technique" in report
        assert "## Detailed Service Inventory" in report
        assert "## Agent Analysis" in report
        assert "## Pipeline Execution Summary" in report
        assert Path(path).exists()

    def test_multi_host_report(self, config, multi_host_state):
        _write_synthetic_log(config.log_file, TRACE_ID, multi_host=True)
        gen = ReportGenerator(config)
        path = gen.generate(multi_host_state, config.log_file, trace_id=TRACE_ID)
        report = Path(path).read_text()
        assert "192.168.56.101" in report
        assert "192.168.56.102" in report

    def test_deterministic_sections_complete_without_log(self, config, sample_state):
        gen = ReportGenerator(config)
        path = gen.generate(sample_state, "/nonexistent/log.jsonl", trace_id=TRACE_ID)
        report = Path(path).read_text()
        # All 5 deterministic sections still fully generated
        assert "## Executive Summary" in report
        assert "## Scope" in report
        assert "## Discovered Hosts" in report
        assert "## Findings by MITRE ATT&CK Technique" in report
        assert "## Detailed Service Inventory" in report
        # Analysis and pipeline degrade gracefully
        assert "No agent interpretation events available" in report
        assert "No stage completion events available" in report
