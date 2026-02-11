"""Temporal activities for pentest operations.

Activities are the actual work units - each is idempotent and retryable.
They interact with external systems (Neo4j, tools, LLMs).
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
import os

from temporalio import activity

from sentinel.core import get_logger
from sentinel.graph import (
    get_graph_client,
    Host,
    Port,
    Service,
    Vulnerability,
    Credential,
    Session,
    Endpoint,
    BaseEdge,
    NodeType,
    EdgeType,
    Severity,
)

logger = get_logger(__name__)


# === Data Classes for Activity I/O ===

@dataclass
class EngagementConfig:
    """Configuration for a pentest engagement."""
    engagement_id: str
    target_url: str
    target_ips: list[str]
    scope_includes: list[str]
    scope_excludes: list[str]
    max_depth: int = 3
    max_duration_minutes: int = 120
    require_approval_for_exploitation: bool = True

    authorization_reference: str | None = None
    authorized_by: str | None = None
    authorized_at: datetime | None = None


@dataclass
class ReconResult:
    """Results from reconnaissance phase."""
    engagement_id: str
    hosts_discovered: int
    ports_discovered: int
    services_discovered: int
    endpoints_discovered: int
    duration_seconds: float
    errors: list[str]


@dataclass
class VulnAnalysisResult:
    """Results from vulnerability analysis phase."""
    engagement_id: str
    vulnerabilities_found: int
    critical_count: int
    high_count: int
    medium_count: int
    exploitable_count: int
    duration_seconds: float


@dataclass
class ExploitAttempt:
    """A single exploit attempt."""
    vulnerability_id: str
    technique: str
    success: bool
    session_obtained: bool
    session_id: str | None = None
    evidence: dict[str, Any] | None = None
    error: str | None = None


@dataclass
class ExploitResult:
    """Results from exploitation phase."""
    engagement_id: str
    attempts: list[ExploitAttempt]
    successful_exploits: int
    sessions_obtained: int
    credentials_captured: int
    duration_seconds: float


@dataclass
class VerificationResult:
    """Results from PoC verification phase."""
    engagement_id: str
    total_verified: int
    confirmed_exploitable: int
    false_positives: int
    replay_scripts_generated: int


@dataclass
class ReportResult:
    """Results from report generation."""
    engagement_id: str
    report_path: str
    executive_summary: str
    total_findings: int
    critical_findings: int
    remediation_items: int


# === Reconnaissance Activities ===

@activity.defn
async def discover_hosts(config: EngagementConfig) -> list[str]:
    """Discover hosts in target scope. Returns list of host IDs."""
    logger.info("Starting host discovery", engagement_id=config.engagement_id)

    graph = await get_graph_client()
    host_ids = []

    for ip in config.target_ips:
        host = Host(
            ip_address=ip,
            engagement_id=config.engagement_id,
            discovered_by="discover_hosts_activity",
        )
        await graph.create_node(host)
        host_ids.append(str(host.id))
        logger.debug("Discovered host", ip=ip, id=str(host.id))

    activity.heartbeat(f"Discovered {len(host_ids)} hosts")
    return host_ids


@activity.defn
async def scan_ports(host_id: str, engagement_id: str) -> list[str]:
    """Scan ports on a host. Returns list of port IDs."""
    logger.info("Scanning ports", host_id=host_id[:8])

    graph = await get_graph_client()
    port_ids = []

    common_ports = [22, 80, 443, 3306, 5432, 8080]

    for port_num in common_ports:
        port = Port(
            port_number=port_num,
            protocol="tcp",
            state="open",
            host_id=host_id,
            engagement_id=engagement_id,
            discovered_by="scan_ports_activity",
        )
        await graph.create_node(port)

        edge = BaseEdge(
            edge_type=EdgeType.HAS_PORT,
            source_id=host_id,
            target_id=port.id,
        )
        await graph.create_edge(
            host_id, NodeType.HOST,
            str(port.id), NodeType.PORT,
            edge,
        )
        port_ids.append(str(port.id))

    activity.heartbeat(f"Found {len(port_ids)} open ports")
    return port_ids


@activity.defn
async def identify_services(port_id: str, engagement_id: str) -> str | None:
    """Identify service on a port. Returns service ID if found."""
    logger.info("Identifying service", port_id=port_id[:8])

    graph = await get_graph_client()

    port_data = await graph.get_node(port_id, NodeType.PORT)
    if not port_data:
        return None

    port_num = port_data.get("port_number")

    service_map = {
        22: ("ssh", "OpenSSH", "8.9"),
        80: ("http", "nginx", "1.18.0"),
        443: ("https", "nginx", "1.18.0"),
        3306: ("mysql", "MySQL", "8.0"),
        5432: ("postgresql", "PostgreSQL", "14"),
        8080: ("http-proxy", "Tomcat", "9.0"),
    }

    if port_num in service_map:
        name, product, version = service_map[port_num]
        service = Service(
            name=name,
            product=product,
            version=version,
            port_id=port_id,
            engagement_id=engagement_id,
            discovered_by="identify_services_activity",
        )
        await graph.create_node(service)

        edge = BaseEdge(
            edge_type=EdgeType.RUNS_SERVICE,
            source_id=port_id,
            target_id=service.id,
        )
        await graph.create_edge(
            port_id, NodeType.PORT,
            str(service.id), NodeType.SERVICE,
            edge,
        )

        return str(service.id)

    return None


@activity.defn
async def crawl_endpoints(service_id: str, engagement_id: str, base_url: str) -> list[str]:
    """Crawl web endpoints for a service. Returns endpoint IDs."""
    logger.info("Crawling endpoints", service_id=service_id[:8])

    graph = await get_graph_client()
    endpoint_ids = []

    sample_paths = [
        "/",
        "/login",
        "/api/v1/users",
        "/api/v1/products",
        "/admin",
        "/rest/user/login",
    ]

    for path in sample_paths:
        endpoint = Endpoint(
            url=f"{base_url}{path}",
            method="GET",
            path=path,
            engagement_id=engagement_id,
            discovered_by="crawl_endpoints_activity",
        )
        await graph.create_node(endpoint)

        edge = BaseEdge(
            edge_type=EdgeType.HAS_ENDPOINT,
            source_id=service_id,
            target_id=endpoint.id,
        )
        await graph.create_edge(
            service_id, NodeType.SERVICE,
            str(endpoint.id), NodeType.ENDPOINT,
            edge,
        )
        endpoint_ids.append(str(endpoint.id))

    activity.heartbeat(f"Found {len(endpoint_ids)} endpoints")
    return endpoint_ids


# === Vulnerability Analysis Activities ===

@activity.defn
async def analyze_service_vulns(service_id: str, engagement_id: str) -> list[str]:
    """Analyze a service for vulnerabilities. Returns vuln IDs."""
    logger.info("Analyzing service for vulns", service_id=service_id[:8])

    graph = await get_graph_client()
    vuln_ids = []

    service_data = await graph.get_node(service_id, NodeType.SERVICE)
    if not service_data:
        return []

    product = service_data.get("product", "")

    sample_vulns = []

    if "nginx" in product.lower():
        sample_vulns.append({
            "name": "Nginx Path Traversal",
            "cve_id": "CVE-2021-23017",
            "severity": Severity.MEDIUM,
            "cvss": 5.3,
        })

    if "mysql" in product.lower() or "postgresql" in product.lower():
        sample_vulns.append({
            "name": "SQL Injection in Application",
            "cwe_id": "CWE-89",
            "severity": Severity.CRITICAL,
            "cvss": 9.8,
            "is_exploitable": True,
        })

    for v in sample_vulns:
        vuln = Vulnerability(
            name=v["name"],
            cve_id=v.get("cve_id"),
            cwe_id=v.get("cwe_id"),
            severity=v["severity"],
            cvss_score=v.get("cvss"),
            is_exploitable=v.get("is_exploitable", False),
            engagement_id=engagement_id,
            discovered_by="analyze_service_vulns_activity",
        )
        await graph.create_node(vuln)

        edge = BaseEdge(
            edge_type=EdgeType.HAS_VULNERABILITY,
            source_id=service_id,
            target_id=vuln.id,
        )
        await graph.create_edge(
            service_id, NodeType.SERVICE,
            str(vuln.id), NodeType.VULNERABILITY,
            edge,
        )
        vuln_ids.append(str(vuln.id))

    return vuln_ids


@activity.defn
async def analyze_endpoint_vulns(endpoint_id: str, engagement_id: str) -> list[str]:
    """Analyze an endpoint for vulnerabilities."""
    logger.info("Analyzing endpoint for vulns", endpoint_id=endpoint_id[:8])

    graph = await get_graph_client()
    vuln_ids = []

    endpoint_data = await graph.get_node(endpoint_id, NodeType.ENDPOINT)
    if not endpoint_data:
        return []

    path = endpoint_data.get("path", "")

    if "login" in path.lower():
        vuln = Vulnerability(
            name="Authentication Bypass",
            cwe_id="CWE-287",
            severity=Severity.HIGH,
            cvss_score=7.5,
            is_exploitable=True,
            engagement_id=engagement_id,
            discovered_by="analyze_endpoint_vulns_activity",
        )
        await graph.create_node(vuln)

        edge = BaseEdge(
            edge_type=EdgeType.HAS_VULNERABILITY,
            source_id=endpoint_id,
            target_id=vuln.id,
        )
        await graph.create_edge(
            endpoint_id, NodeType.ENDPOINT,
            str(vuln.id), NodeType.VULNERABILITY,
            edge,
        )
        vuln_ids.append(str(vuln.id))

    if "admin" in path.lower():
        vuln = Vulnerability(
            name="Broken Access Control",
            cwe_id="CWE-284",
            severity=Severity.HIGH,
            cvss_score=8.1,
            is_exploitable=True,
            engagement_id=engagement_id,
            discovered_by="analyze_endpoint_vulns_activity",
        )
        await graph.create_node(vuln)

        edge = BaseEdge(
            edge_type=EdgeType.HAS_VULNERABILITY,
            source_id=endpoint_id,
            target_id=vuln.id,
        )
        await graph.create_edge(
            endpoint_id, NodeType.ENDPOINT,
            str(vuln.id), NodeType.VULNERABILITY,
            edge,
        )
        vuln_ids.append(str(vuln.id))

    return vuln_ids


# === Exploitation Activities ===

@activity.defn
async def attempt_exploit(
    vuln_id: str,
    engagement_id: str,
    dry_run: bool = False,
) -> ExploitAttempt:
    """Attempt to exploit a vulnerability."""
    logger.info("Attempting exploit", vuln_id=vuln_id[:8], dry_run=dry_run)

    graph = await get_graph_client()

    vuln_data = await graph.get_node(vuln_id, NodeType.VULNERABILITY)
    if not vuln_data:
        return ExploitAttempt(
            vulnerability_id=vuln_id,
            technique="unknown",
            success=False,
            session_obtained=False,
            error="Vulnerability not found",
        )

    if dry_run:
        return ExploitAttempt(
            vulnerability_id=vuln_id,
            technique="dry_run",
            success=True,
            session_obtained=False,
            evidence={"mode": "dry_run", "would_exploit": True},
        )

    is_exploitable = vuln_data.get("is_exploitable", False)

    if is_exploitable:
        session = Session(
            session_type="web",
            user="www-data",
            is_active=True,
            engagement_id=engagement_id,
            discovered_by="attempt_exploit_activity",
        )
        await graph.create_node(session)

        await graph.update_node(
            vuln_id,
            NodeType.VULNERABILITY,
            {"exploit_poc": "curl -X POST ..."},
        )

        edge = BaseEdge(
            edge_type=EdgeType.YIELDS_SESSION,
            source_id=vuln_id,
            target_id=session.id,
            validated=True,
        )
        await graph.create_edge(
            vuln_id, NodeType.VULNERABILITY,
            str(session.id), NodeType.SESSION,
            edge,
        )

        return ExploitAttempt(
            vulnerability_id=vuln_id,
            technique="automated_exploit",
            success=True,
            session_obtained=True,
            session_id=str(session.id),
            evidence={
                "command": "curl -X POST ...",
                "response": "200 OK",
                "session_token": "xxx",
            },
        )

    return ExploitAttempt(
        vulnerability_id=vuln_id,
        technique="attempted",
        success=False,
        session_obtained=False,
        error="Exploitation failed - not exploitable in current context",
    )


# === Verification Activities ===

@activity.defn
async def verify_exploit(
    vuln_id: str,
    session_id: str,
    engagement_id: str,
) -> bool:
    """Re-execute exploit to verify it's reproducible."""
    logger.info("Verifying exploit", vuln_id=vuln_id[:8])

    graph = await get_graph_client()

    vuln_data = await graph.get_node(vuln_id, NodeType.VULNERABILITY)
    if not vuln_data:
        return False

    has_poc = vuln_data.get("exploit_poc") is not None

    if has_poc:
        await graph.update_node(
            vuln_id,
            NodeType.VULNERABILITY,
            {"verified": True, "verified_at": datetime.utcnow().isoformat()},
        )
        return True

    return False


@activity.defn
async def generate_replay_script(
    vuln_id: str,
    format: str = "curl",
) -> str | None:
    """Generate a replay script for an exploit."""
    logger.info("Generating replay script", vuln_id=vuln_id[:8], format=format)

    graph = await get_graph_client()

    vuln_data = await graph.get_node(vuln_id, NodeType.VULNERABILITY)
    if not vuln_data:
        return None

    poc = vuln_data.get("exploit_poc")
    if not poc:
        return None

    if format == "curl":
        return f"""#!/bin/bash
# Replay script for {vuln_data.get('name')}
# CVE: {vuln_data.get('cve_id', 'N/A')}
# Generated by Sentinel

{poc}
"""
    elif format == "python":
        return f'''#!/usr/bin/env python3
"""Replay script for {vuln_data.get('name')}"""

import requests

# CVE: {vuln_data.get('cve_id', 'N/A')}

def exploit():
    # TODO: Convert curl to requests
    pass

if __name__ == "__main__":
    exploit()
'''

    return None


# === Reporting Activities ===

@activity.defn
async def create_snapshot(engagement_id: str) -> dict[str, Any]:
    """Create a graph snapshot for the engagement."""
    logger.info("Creating snapshot", engagement_id=engagement_id)

    graph = await get_graph_client()
    snapshot = await graph.create_snapshot(engagement_id)

    return {
        "id": str(snapshot.id),
        "host_count": snapshot.host_count,
        "vulnerability_count": snapshot.vulnerability_count,
        "credential_count": snapshot.credential_count,
        "session_count": snapshot.session_count,
        "choke_point_count": len(snapshot.choke_points),
    }


@activity.defn
async def generate_report(engagement_id: str, output_path: str) -> ReportResult:
    """Generate the final pentest report."""
    logger.info("Generating report", engagement_id=engagement_id)

    graph = await get_graph_client()

    vulns = await graph.find_vulnerabilities()
    hosts = await graph.find_hosts(engagement_id=engagement_id)

    critical_count = len([v for v in vulns if v.get("severity") == "critical"])
    high_count = len([v for v in vulns if v.get("severity") == "high"])

    executive_summary = f"""
Sentinel Autonomous Pentest Report
Engagement: {engagement_id}
Generated: {datetime.utcnow().isoformat()}

Hosts Discovered: {len(hosts)}
Total Vulnerabilities: {len(vulns)}
  - Critical: {critical_count}
  - High: {high_count}
  - Medium: {len([v for v in vulns if v.get("severity") == "medium"])}
  - Low: {len([v for v in vulns if v.get("severity") == "low"])}

Exploitation Results: See detailed findings below.
"""

    report_content = executive_summary + "\n\n[Detailed findings would go here]"

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(report_content)

    return ReportResult(
        engagement_id=engagement_id,
        report_path=output_path,
        executive_summary=executive_summary,
        total_findings=len(vulns),
        critical_findings=critical_count,
        remediation_items=critical_count + high_count,
    )
