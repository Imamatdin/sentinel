"""Nmap wrapper for port scanning and service detection.

Provides async interface to nmap with structured output.
"""

import asyncio
import os
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sentinel.core import get_logger, ToolExecutionError

logger = get_logger(__name__)


@dataclass
class PortResult:
    """Result for a single port."""
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class HostResult:
    """Result for a single host."""
    ip: str
    hostname: str | None = None
    state: str = "unknown"
    os_match: str | None = None
    os_accuracy: int = 0
    ports: list[PortResult] = field(default_factory=list)
    mac_address: str | None = None
    vendor: str | None = None


@dataclass
class NmapResult:
    """Complete nmap scan result."""
    command: str
    start_time: datetime
    end_time: datetime | None = None
    hosts: list[HostResult] = field(default_factory=list)
    raw_xml: str | None = None
    errors: list[str] = field(default_factory=list)


def _find_nmap() -> str | None:
    """Find nmap executable, checking common Windows install paths."""
    found = shutil.which("nmap")
    if found:
        return found

    if sys.platform == "win32":
        candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe"),
        ]
        for path in candidates:
            if os.path.isfile(path):
                return path

    return None


class NmapTool:
    """Async wrapper for nmap scanning."""

    def __init__(self, nmap_path: str | None = None):
        resolved = nmap_path or _find_nmap()
        if not resolved or (nmap_path and not os.path.isfile(nmap_path)):
            raise ToolExecutionError(
                "nmap",
                "nmap not found in PATH or common install locations. "
                "Install via: choco install nmap -y (run as admin)",
            )
        self.nmap_path = resolved
        self.logger = get_logger("tool.nmap")

    async def scan(
        self,
        targets: list[str],
        ports: str | None = None,
        arguments: str = "-sV -sC",
        timeout: int = 300,
    ) -> NmapResult:
        """Run an nmap scan.

        Args:
            targets: List of IPs or hostnames to scan
            ports: Port specification (e.g., "22,80,443" or "1-1000")
            arguments: Nmap arguments (default: service version + scripts)
            timeout: Scan timeout in seconds

        Returns:
            NmapResult with structured scan data
        """
        cmd = [self.nmap_path]
        cmd.extend(arguments.split())

        if ports:
            cmd.extend(["-p", ports])

        # Output to XML for parsing
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            xml_file = f.name

        cmd.extend(["-oX", xml_file])
        cmd.extend(targets)

        command_str = " ".join(cmd)
        self.logger.info("Starting nmap scan", command=command_str, targets=targets)

        result = NmapResult(
            command=command_str,
            start_time=datetime.now(timezone.utc),
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                raise ToolExecutionError("nmap", f"Scan timed out after {timeout}s")

            if stderr:
                stderr_text = stderr.decode(errors="replace")
                if stderr_text.strip():
                    result.errors.append(stderr_text)

            # Parse XML output
            if os.path.exists(xml_file) and os.path.getsize(xml_file) > 0:
                with open(xml_file, "r", encoding="utf-8", errors="replace") as f:
                    result.raw_xml = f.read()
                result.hosts = self._parse_xml(result.raw_xml)

            result.end_time = datetime.now(timezone.utc)

            self.logger.info(
                "Nmap scan complete",
                hosts_found=len(result.hosts),
                total_ports=sum(len(h.ports) for h in result.hosts),
            )

            return result

        finally:
            if os.path.exists(xml_file):
                os.unlink(xml_file)

    async def quick_scan(
        self,
        target: str,
        top_ports: int = 100,
    ) -> NmapResult:
        """Quick scan of top ports."""
        return await self.scan(
            targets=[target],
            arguments=f"-sV --top-ports {top_ports} -T4",
            timeout=120,
        )

    async def service_scan(
        self,
        target: str,
        ports: list[int],
    ) -> NmapResult:
        """Detailed service scan on specific ports."""
        port_str = ",".join(str(p) for p in ports)
        return await self.scan(
            targets=[target],
            ports=port_str,
            arguments="-sV -sC -A",
            timeout=180,
        )

    def _parse_xml(self, xml_content: str) -> list[HostResult]:
        """Parse nmap XML output."""
        hosts = []

        try:
            root = ET.fromstring(xml_content)

            for host_elem in root.findall(".//host"):
                addr_elem = host_elem.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    addr_elem = host_elem.find("address[@addrtype='ipv6']")
                if addr_elem is None:
                    continue

                ip = addr_elem.get("addr", "")

                mac_elem = host_elem.find("address[@addrtype='mac']")
                mac = mac_elem.get("addr") if mac_elem is not None else None
                vendor = mac_elem.get("vendor") if mac_elem is not None else None

                hostname_elem = host_elem.find(".//hostname")
                hostname = hostname_elem.get("name") if hostname_elem is not None else None

                status_elem = host_elem.find("status")
                state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

                os_match = None
                os_accuracy = 0
                osmatch_elem = host_elem.find(".//osmatch")
                if osmatch_elem is not None:
                    os_match = osmatch_elem.get("name")
                    os_accuracy = int(osmatch_elem.get("accuracy", 0))

                port_results = []
                for port_elem in host_elem.findall(".//port"):
                    port_num = int(port_elem.get("portid", 0))
                    protocol = port_elem.get("protocol", "tcp")

                    state_elem = port_elem.find("state")
                    port_state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                    service_elem = port_elem.find("service")
                    service = None
                    product = None
                    version = None
                    extra_info = None

                    if service_elem is not None:
                        service = service_elem.get("name")
                        product = service_elem.get("product")
                        version = service_elem.get("version")
                        extra_info = service_elem.get("extrainfo")

                    scripts = {}
                    for script_elem in port_elem.findall("script"):
                        script_id = script_elem.get("id", "")
                        script_output = script_elem.get("output", "")
                        scripts[script_id] = script_output

                    port_results.append(PortResult(
                        port=port_num,
                        protocol=protocol,
                        state=port_state,
                        service=service,
                        product=product,
                        version=version,
                        extra_info=extra_info,
                        scripts=scripts,
                    ))

                hosts.append(HostResult(
                    ip=ip,
                    hostname=hostname,
                    state=state,
                    os_match=os_match,
                    os_accuracy=os_accuracy,
                    ports=port_results,
                    mac_address=mac,
                    vendor=vendor,
                ))

        except ET.ParseError as e:
            self.logger.error("Failed to parse nmap XML", error=str(e))

        return hosts
