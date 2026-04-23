"""Nmap XML output parsing — extracts structured data per pipeline stage."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path


class NmapParser:
    @staticmethod
    def parse_host_discovery(xml_path: Path) -> list[dict]:
        try:
            tree = ET.parse(xml_path)
        except (FileNotFoundError, ET.ParseError, OSError):
            return []
        root = tree.getroot()
        hosts = []
        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is None or status.get("state") != "up":
                continue

            ip = None
            mac = None
            for addr in host_el.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
                elif addr.get("addrtype") == "mac":
                    mac = addr.get("addr")

            if ip is None:
                continue

            hostname = None
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                hn = hostnames_el.find("hostname")
                if hn is not None:
                    hostname = hn.get("name")

            hosts.append({"ip": ip, "mac": mac, "hostname": hostname})
        return hosts

    @staticmethod
    def parse_port_scan(xml_path: Path) -> dict:
        try:
            tree = ET.parse(xml_path)
        except (FileNotFoundError, ET.ParseError, OSError):
            return {"ports": []}
        root = tree.getroot()
        ports = []
        host_el = root.find("host")
        if host_el is None:
            return {"ports": []}

        ports_el = host_el.find("ports")
        if ports_el is None:
            return {"ports": []}

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            ports.append(
                {
                    "port": int(port_el.get("portid", "0")),
                    "protocol": port_el.get("protocol", "tcp"),
                    "state": state_el.get("state", "open"),
                }
            )
        return {"ports": ports}

    @staticmethod
    def parse_service_enum(xml_path: Path) -> dict:
        try:
            tree = ET.parse(xml_path)
        except (FileNotFoundError, ET.ParseError, OSError):
            return {"services": []}
        root = tree.getroot()
        services = []
        host_el = root.find("host")
        if host_el is None:
            return {"services": []}

        ports_el = host_el.find("ports")
        if ports_el is None:
            return {"services": []}

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc = port_el.find("service")
            if svc is None:
                continue

            services.append(
                {
                    "port": int(port_el.get("portid", "0")),
                    "protocol": port_el.get("protocol", "tcp"),
                    "name": svc.get("name", ""),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "extrainfo": svc.get("extrainfo", ""),
                    "cpe": [el.text for el in svc.findall("cpe") if el.text],
                }
            )
        return {"services": services}

    @staticmethod
    def parse_os_fingerprint(xml_path: Path) -> dict:
        try:
            tree = ET.parse(xml_path)
        except (FileNotFoundError, ET.ParseError, OSError):
            return {"os_matches": []}
        root = tree.getroot()
        os_matches = []
        host_el = root.find("host")
        if host_el is None:
            return {"os_matches": []}

        os_el = host_el.find("os")
        if os_el is None:
            return {"os_matches": []}

        for match_el in os_el.findall("osmatch"):
            osclasses = []
            for osclass in match_el.findall("osclass"):
                osclasses.append(
                    {
                        "type": osclass.get("type", ""),
                        "vendor": osclass.get("vendor", ""),
                        "os_family": osclass.get("osfamily", ""),
                        "os_gen": osclass.get("osgen", ""),
                        "accuracy": int(osclass.get("accuracy", "0")),
                        "cpe": [el.text for el in osclass.findall("cpe") if el.text],
                    }
                )
            os_matches.append(
                {
                    "name": match_el.get("name", ""),
                    "accuracy": int(match_el.get("accuracy", "0")),
                    "osclasses": osclasses,
                }
            )
        return {"os_matches": os_matches}
