"""Tests for tool_parser module — nmap XML parsing per stage."""

from pathlib import Path

from tool_parser import NmapParser

FIXTURES = Path(__file__).parent / "fixtures"


class TestParseHostDiscovery:
    def test_finds_up_hosts(self):
        results = NmapParser.parse_host_discovery(FIXTURES / "host_discovery.xml")
        ips = [h["ip"] for h in results]
        assert "192.168.56.1" in ips
        assert "192.168.56.101" in ips

    def test_excludes_down_hosts(self):
        results = NmapParser.parse_host_discovery(FIXTURES / "host_discovery.xml")
        ips = [h["ip"] for h in results]
        assert "192.168.56.200" not in ips

    def test_extracts_mac(self):
        results = NmapParser.parse_host_discovery(FIXTURES / "host_discovery.xml")
        host101 = next(h for h in results if h["ip"] == "192.168.56.101")
        assert host101["mac"] == "52:54:00:DA:01:01"

    def test_extracts_hostname(self):
        results = NmapParser.parse_host_discovery(FIXTURES / "host_discovery.xml")
        host101 = next(h for h in results if h["ip"] == "192.168.56.101")
        assert host101["hostname"] == "metasploitable.localdomain"

    def test_missing_hostname_is_none(self):
        results = NmapParser.parse_host_discovery(FIXTURES / "host_discovery.xml")
        host1 = next(h for h in results if h["ip"] == "192.168.56.1")
        assert host1["hostname"] is None

    def test_empty_xml_returns_empty(self):
        results = NmapParser.parse_host_discovery(FIXTURES / "empty.xml")
        assert results == []

    def test_nonexistent_file_returns_empty(self):
        results = NmapParser.parse_host_discovery(FIXTURES / "nonexistent.xml")
        assert results == []

    def test_malformed_xml_returns_empty(self):
        results = NmapParser.parse_host_discovery(FIXTURES / "malformed.xml")
        assert results == []


class TestParsePortScan:
    def test_extracts_open_ports(self):
        result = NmapParser.parse_port_scan(FIXTURES / "port_scan.xml")
        ports = result["ports"]
        assert len(ports) == 4
        port_numbers = [p["port"] for p in ports]
        assert 21 in port_numbers
        assert 22 in port_numbers
        assert 80 in port_numbers
        assert 445 in port_numbers

    def test_port_entry_structure(self):
        result = NmapParser.parse_port_scan(FIXTURES / "port_scan.xml")
        port = result["ports"][0]
        assert "port" in port
        assert "protocol" in port
        assert "state" in port
        assert port["protocol"] == "tcp"
        assert port["state"] == "open"

    def test_empty_xml_returns_empty_ports(self):
        result = NmapParser.parse_port_scan(FIXTURES / "empty.xml")
        assert result["ports"] == []

    def test_nonexistent_file_returns_empty_ports(self):
        result = NmapParser.parse_port_scan(FIXTURES / "nonexistent.xml")
        assert result["ports"] == []

    def test_malformed_xml_returns_empty_ports(self):
        result = NmapParser.parse_port_scan(FIXTURES / "malformed.xml")
        assert result["ports"] == []


class TestParseServiceEnum:
    def test_extracts_services(self):
        result = NmapParser.parse_service_enum(FIXTURES / "service_enum.xml")
        services = result["services"]
        assert len(services) == 4

    def test_service_entry_structure(self):
        result = NmapParser.parse_service_enum(FIXTURES / "service_enum.xml")
        ftp = next(s for s in result["services"] if s["port"] == 21)
        assert ftp["name"] == "ftp"
        assert ftp["product"] == "vsftpd"
        assert ftp["version"] == "2.3.4"
        assert ftp["cpe"] == "cpe:/a:vsftpd:vsftpd:2.3.4"

    def test_extrainfo_captured(self):
        result = NmapParser.parse_service_enum(FIXTURES / "service_enum.xml")
        ssh = next(s for s in result["services"] if s["port"] == 22)
        assert ssh["extrainfo"] == "Debian 8ubuntu1"

    def test_missing_cpe_is_empty(self):
        result = NmapParser.parse_service_enum(FIXTURES / "service_enum.xml")
        smb = next(s for s in result["services"] if s["port"] == 445)
        assert smb["cpe"] == ""

    def test_empty_xml_returns_empty_services(self):
        result = NmapParser.parse_service_enum(FIXTURES / "empty.xml")
        assert result["services"] == []

    def test_nonexistent_file_returns_empty_services(self):
        result = NmapParser.parse_service_enum(FIXTURES / "nonexistent.xml")
        assert result["services"] == []

    def test_malformed_xml_returns_empty_services(self):
        result = NmapParser.parse_service_enum(FIXTURES / "malformed.xml")
        assert result["services"] == []


class TestParseOsFingerprint:
    def test_extracts_os_matches(self):
        result = NmapParser.parse_os_fingerprint(FIXTURES / "os_fingerprint.xml")
        matches = result["os_matches"]
        assert len(matches) == 2

    def test_os_match_structure(self):
        result = NmapParser.parse_os_fingerprint(FIXTURES / "os_fingerprint.xml")
        best = result["os_matches"][0]
        assert best["name"] == "Linux 2.6.9 - 2.6.33"
        assert best["accuracy"] == 95
        assert best["vendor"] == "Linux"
        assert best["os_family"] == "Linux"
        assert best["os_gen"] == "2.6.X"
        assert best["cpe"] == "cpe:/o:linux:linux_kernel:2.6"

    def test_empty_xml_returns_empty_matches(self):
        result = NmapParser.parse_os_fingerprint(FIXTURES / "empty.xml")
        assert result["os_matches"] == []

    def test_nonexistent_file_returns_empty_matches(self):
        result = NmapParser.parse_os_fingerprint(FIXTURES / "nonexistent.xml")
        assert result["os_matches"] == []

    def test_malformed_xml_returns_empty_matches(self):
        result = NmapParser.parse_os_fingerprint(FIXTURES / "malformed.xml")
        assert result["os_matches"] == []
