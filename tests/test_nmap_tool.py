"""Tests for nmap tool XML parsing (no nmap binary required)."""

import pytest

from sentinel.tools.nmap_tool import NmapTool, HostResult, PortResult, _find_nmap


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p 22,80,443 192.168.1.1" start="1700000000">
  <host starttime="1700000000" endtime="1700000060">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TestVendor"/>
    <hostnames>
      <hostname name="web.example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0"/>
        <script id="http-title" output="Welcome Page"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4" accuracy="95"/>
    </os>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


class TestNmapXmlParsing:
    """Test nmap XML output parsing without requiring nmap binary."""

    def setup_method(self):
        """Create a NmapTool for parsing only (bypass nmap check)."""
        self.tool = object.__new__(NmapTool)
        self.tool.nmap_path = "fake"
        from sentinel.core import get_logger
        self.tool.logger = get_logger("test.nmap")

    def test_parse_hosts(self):
        hosts = self.tool._parse_xml(SAMPLE_NMAP_XML)
        assert len(hosts) == 2

    def test_parse_host_details(self):
        hosts = self.tool._parse_xml(SAMPLE_NMAP_XML)
        host = hosts[0]
        assert host.ip == "192.168.1.1"
        assert host.hostname == "web.example.com"
        assert host.state == "up"
        assert host.os_match == "Linux 5.4"
        assert host.os_accuracy == 95
        assert host.mac_address == "AA:BB:CC:DD:EE:FF"
        assert host.vendor == "TestVendor"

    def test_parse_open_ports(self):
        hosts = self.tool._parse_xml(SAMPLE_NMAP_XML)
        host = hosts[0]
        open_ports = [p for p in host.ports if p.state == "open"]
        assert len(open_ports) == 2

    def test_parse_port_service(self):
        hosts = self.tool._parse_xml(SAMPLE_NMAP_XML)
        ssh_port = next(p for p in hosts[0].ports if p.port == 22)
        assert ssh_port.service == "ssh"
        assert ssh_port.product == "OpenSSH"
        assert ssh_port.version == "8.9p1"
        assert ssh_port.extra_info == "Ubuntu"

    def test_parse_scripts(self):
        hosts = self.tool._parse_xml(SAMPLE_NMAP_XML)
        http_port = next(p for p in hosts[0].ports if p.port == 80)
        assert "http-title" in http_port.scripts
        assert http_port.scripts["http-title"] == "Welcome Page"

    def test_parse_closed_port(self):
        hosts = self.tool._parse_xml(SAMPLE_NMAP_XML)
        port_443 = next(p for p in hosts[0].ports if p.port == 443)
        assert port_443.state == "closed"

    def test_parse_down_host(self):
        hosts = self.tool._parse_xml(SAMPLE_NMAP_XML)
        down_host = hosts[1]
        assert down_host.ip == "192.168.1.2"
        assert down_host.state == "down"
        assert len(down_host.ports) == 0

    def test_parse_invalid_xml(self):
        hosts = self.tool._parse_xml("not xml at all")
        assert hosts == []

    def test_parse_empty_xml(self):
        hosts = self.tool._parse_xml('<?xml version="1.0"?><nmaprun></nmaprun>')
        assert hosts == []


class TestNmapToolInit:
    """Test nmap tool initialization."""

    def test_raises_if_nmap_not_found(self):
        """Should raise ToolExecutionError if nmap isn't found."""
        from sentinel.core import ToolExecutionError
        with pytest.raises(ToolExecutionError):
            NmapTool(nmap_path="/nonexistent/nmap")

    def test_find_nmap_returns_none_if_missing(self):
        """_find_nmap should return None if nmap not on PATH."""
        import os
        old_path = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = ""
            # May still find in Program Files on Windows, but shouldn't crash
            result = _find_nmap()
            # Result is either a valid path or None
            assert result is None or os.path.isfile(result)
        finally:
            os.environ["PATH"] = old_path
