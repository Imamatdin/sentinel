"""Tests for DNS tool."""

import pytest

from sentinel.tools.dns_tool import DNSTool, DNSResult, DNSRecord


class TestDNSToolResolve:
    """Test DNS resolution (requires network)."""

    @pytest.mark.asyncio
    async def test_resolve_google(self):
        """Resolve google.com A records."""
        tool = DNSTool()
        result = await tool.resolve("google.com", record_types=["A"])
        assert len(result.records) > 0
        assert result.records[0].record_type == "A"
        assert result.domain == "google.com"

    @pytest.mark.asyncio
    async def test_resolve_nonexistent_domain(self):
        """Resolving nonexistent domain should have errors."""
        tool = DNSTool()
        result = await tool.resolve("this-domain-does-not-exist-sentinel-test.invalid")
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_resolve_multiple_types(self):
        """Resolve multiple record types."""
        tool = DNSTool()
        result = await tool.resolve("google.com", record_types=["A", "MX"])
        types_found = {r.record_type for r in result.records}
        # At minimum, A records should exist
        assert "A" in types_found

    @pytest.mark.asyncio
    async def test_resolve_ns_records(self):
        """Resolve NS records."""
        tool = DNSTool()
        result = await tool.resolve("google.com", record_types=["NS"])
        ns_records = [r for r in result.records if r.record_type == "NS"]
        assert len(ns_records) > 0


class TestDNSToolSubdomains:
    """Test subdomain enumeration."""

    @pytest.mark.asyncio
    async def test_enumerate_finds_www(self):
        """www.google.com should be discoverable."""
        tool = DNSTool()
        result = await tool.enumerate_subdomains(
            "google.com",
            wordlist=["www", "nonexistent-prefix-xyzzy"],
            concurrency=5,
        )
        assert "www.google.com" in result.subdomains

    @pytest.mark.asyncio
    async def test_enumerate_empty_wordlist(self):
        """Empty wordlist should return no subdomains."""
        tool = DNSTool()
        result = await tool.enumerate_subdomains("google.com", wordlist=[])
        assert len(result.subdomains) == 0


class TestDNSToolReverse:
    """Test reverse DNS lookup."""

    @pytest.mark.asyncio
    async def test_reverse_lookup_google_dns(self):
        """8.8.8.8 should reverse to dns.google."""
        tool = DNSTool()
        hostname = await tool.reverse_lookup("8.8.8.8")
        assert hostname is not None
        assert "google" in hostname.lower() or "dns" in hostname.lower()

    @pytest.mark.asyncio
    async def test_reverse_lookup_private_ip(self):
        """Private IP likely has no PTR record."""
        tool = DNSTool()
        hostname = await tool.reverse_lookup("192.168.255.255")
        # May or may not resolve, but shouldn't crash
        assert hostname is None or isinstance(hostname, str)


class TestDNSResult:
    """Test DNSResult dataclass."""

    def test_empty_result(self):
        result = DNSResult(domain="test.com")
        assert result.domain == "test.com"
        assert result.records == []
        assert result.subdomains == []
        assert result.errors == []

    def test_dns_record(self):
        record = DNSRecord(
            name="test.com",
            record_type="A",
            value="1.2.3.4",
            ttl=300,
        )
        assert record.value == "1.2.3.4"
        assert record.ttl == 300
