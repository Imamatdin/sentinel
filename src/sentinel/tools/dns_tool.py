"""DNS resolution and subdomain enumeration tool."""

import asyncio
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class DNSRecord:
    """A single DNS record."""
    name: str
    record_type: str
    value: str
    ttl: int = 0


@dataclass
class DNSResult:
    """Result of DNS queries."""
    domain: str
    records: list[DNSRecord] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class DNSTool:
    """Async DNS resolution and enumeration."""

    def __init__(self, nameservers: list[str] | None = None):
        self.resolver = dns.asyncresolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.logger = get_logger("tool.dns")

    async def resolve(
        self,
        domain: str,
        record_types: list[str] | None = None,
    ) -> DNSResult:
        """Resolve DNS records for a domain.

        Args:
            domain: Domain to query
            record_types: Record types to query (default: A, AAAA, CNAME, MX, TXT, NS)
        """
        if record_types is None:
            record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]

        result = DNSResult(domain=domain)

        for rtype in record_types:
            try:
                answers = await self.resolver.resolve(domain, rtype)
                for rdata in answers:
                    result.records.append(DNSRecord(
                        name=domain,
                        record_type=rtype,
                        value=str(rdata),
                        ttl=answers.ttl,
                    ))
            except dns.resolver.NXDOMAIN:
                result.errors.append(f"Domain {domain} does not exist")
                break
            except dns.resolver.NoAnswer:
                pass  # No records of this type
            except dns.exception.DNSException as e:
                result.errors.append(f"DNS error for {rtype}: {e}")

        self.logger.info(
            "DNS resolution complete",
            domain=domain,
            records_found=len(result.records),
        )

        return result

    async def enumerate_subdomains(
        self,
        domain: str,
        wordlist: list[str] | None = None,
        concurrency: int = 50,
    ) -> DNSResult:
        """Enumerate subdomains via DNS brute force.

        Args:
            domain: Base domain
            wordlist: List of subdomain prefixes to try
            concurrency: Max concurrent lookups
        """
        if wordlist is None:
            wordlist = [
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
                "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "mx", "mx1",
                "api", "dev", "staging", "test", "prod", "admin", "portal",
                "vpn", "remote", "git", "gitlab", "github", "jenkins", "ci",
                "cdn", "static", "assets", "media", "images", "img", "files",
                "app", "apps", "mobile", "m", "beta", "alpha", "demo",
                "blog", "news", "shop", "store", "support", "help", "docs",
                "wiki", "forum", "community", "status", "monitor", "grafana",
                "kibana", "elastic", "prometheus", "metrics", "logs",
                "db", "database", "mysql", "postgres", "redis", "mongo",
                "s3", "aws", "cloud", "azure", "gcp", "storage",
                "internal", "intranet", "corp", "office", "extranet",
            ]

        result = DNSResult(domain=domain)
        semaphore = asyncio.Semaphore(concurrency)

        async def check_subdomain(prefix: str) -> str | None:
            async with semaphore:
                subdomain = f"{prefix}.{domain}"
                try:
                    await self.resolver.resolve(subdomain, "A")
                    return subdomain
                except dns.exception.DNSException:
                    return None

        self.logger.info(
            "Starting subdomain enumeration",
            domain=domain,
            wordlist_size=len(wordlist),
        )

        tasks = [check_subdomain(prefix) for prefix in wordlist]
        results = await asyncio.gather(*tasks)

        result.subdomains = [r for r in results if r is not None]

        self.logger.info(
            "Subdomain enumeration complete",
            domain=domain,
            subdomains_found=len(result.subdomains),
        )

        return result

    async def reverse_lookup(self, ip: str) -> str | None:
        """Reverse DNS lookup."""
        try:
            addr = dns.reversename.from_address(ip)
            answers = await self.resolver.resolve(addr, "PTR")
            return str(answers[0]).rstrip(".")
        except dns.exception.DNSException:
            return None

    async def get_nameservers(self, domain: str) -> list[str]:
        """Get authoritative nameservers for domain."""
        try:
            answers = await self.resolver.resolve(domain, "NS")
            return [str(ns).rstrip(".") for ns in answers]
        except dns.exception.DNSException:
            return []
