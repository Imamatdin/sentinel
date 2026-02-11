"""Reconnaissance agent that orchestrates discovery tools.

Uses the tool-guarded execution pattern from Phase 3:
LLM proposes recon actions -> policy validates -> tools execute -> graph stores results.
"""

from typing import Any
from urllib.parse import urlparse

from sentinel.core import get_logger, ToolExecutionError
from sentinel.agents.guarded_base import GuardedBaseAgent, AgentContext
from sentinel.agents.policy import ActionType
from sentinel.agents.schemas import ActionProposal
from sentinel.agents.llm_client import BaseLLMClient, LLMProvider
from sentinel.tools.nmap_tool import NmapTool, _find_nmap
from sentinel.tools.dns_tool import DNSTool
from sentinel.tools.http_recon import HTTPReconTool, HTTPRequest
from sentinel.tools.crawler import WebCrawler

logger = get_logger(__name__)


class GuardedReconAgent(GuardedBaseAgent):
    """Agent for reconnaissance and discovery with policy enforcement.

    Orchestrates nmap, DNS, HTTP, and crawler tools via LLM-guided
    decision making, with all actions validated against engagement policy.
    """

    def __init__(
        self,
        llm_client: BaseLLMClient | None = None,
        provider: LLMProvider = LLMProvider.ANTHROPIC,
        nmap_path: str | None = None,
    ):
        super().__init__(name="recon", llm_client=llm_client, provider=provider)

        # Initialize tools (nmap is optional — may not be installed)
        self._nmap: NmapTool | None = None
        try:
            self._nmap = NmapTool(nmap_path=nmap_path)
        except ToolExecutionError:
            self.logger.warning("nmap not available — port scanning disabled")

        self._dns = DNSTool()
        self._http = HTTPReconTool()
        self._crawler = WebCrawler(http_tool=self._http)

    @property
    def system_prompt(self) -> str:
        nmap_note = "" if self._nmap else "\nNOTE: nmap is NOT installed. Skip nmap_scan actions."
        return f"""You are a reconnaissance agent for the Sentinel autonomous pentesting platform.

Your role is to discover and map the target's attack surface:
1. Identify hosts and subdomains
2. Discover open ports and running services
3. Find web endpoints and API routes
4. Extract useful information (versions, technologies, configurations)

## Available Actions
- nmap_scan: Scan ports and identify services
- dns_lookup: Resolve DNS records and enumerate subdomains
- http_request: Make HTTP requests to discover endpoints
- crawl_endpoint: Crawl web applications for pages and forms
- update_graph: Store discoveries in the knowledge graph
- create_finding: Record a potential vulnerability finding

## Rules
1. Always start with passive reconnaissance (DNS) before active scanning
2. Log all discoveries to the knowledge graph
3. Prioritize interesting ports (80, 443, 8080, 3000, etc.) for web apps
4. Extract version information when possible
5. Never fabricate discoveries - only report what tools actually find
6. When a target is a URL (http://...), start with http_request and crawl_endpoint
7. When a target is a domain or IP, start with dns_lookup and nmap_scan
{nmap_note}

## Output Format
Provide your analysis in structured format with:
- What you observed
- What you think it means
- What you want to do next
- Your confidence level in findings
"""

    @property
    def allowed_actions(self) -> list[ActionType]:
        actions = [
            ActionType.DNS_LOOKUP,
            ActionType.HTTP_REQUEST,
            ActionType.CRAWL_ENDPOINT,
            ActionType.UPDATE_GRAPH,
            ActionType.CREATE_FINDING,
        ]
        if self._nmap:
            actions.append(ActionType.NMAP_SCAN)
        return actions

    async def _execute_action(
        self,
        proposal: ActionProposal,
        context: AgentContext,
    ) -> dict[str, Any]:
        """Execute a reconnaissance action."""
        action = proposal.action_type
        params = proposal.parameters
        target = proposal.target

        self.logger.info("Executing recon action", action=action, target=target)

        try:
            if action == "nmap_scan":
                return await self._do_nmap_scan(params, target, context)
            elif action == "dns_lookup":
                return await self._do_dns_lookup(params, target, context)
            elif action == "http_request":
                return await self._do_http_request(params, target, context)
            elif action == "crawl_endpoint":
                return await self._do_crawl(params, target, context)
            elif action in ("update_graph", "create_finding"):
                return {"action": action, "status": "recorded", "data": params}
            else:
                return {"action": action, "status": "unsupported", "error": f"Unknown action: {action}"}
        except Exception as e:
            self.logger.error("Action failed", action=action, error=str(e))
            return {"action": action, "status": "error", "error": str(e)}

    async def _do_nmap_scan(
        self,
        params: dict[str, Any],
        target: str,
        context: AgentContext,
    ) -> dict[str, Any]:
        """Execute nmap scan."""
        if not self._nmap:
            return {"action": "nmap_scan", "status": "error", "error": "nmap not installed"}

        ports = params.get("ports", "1-1000")
        arguments = params.get("arguments", "-sV -sC")

        result = await self._nmap.scan(
            targets=[target],
            ports=str(ports),
            arguments=arguments,
        )

        # Summarize results
        host_summaries = []
        total_ports = 0
        total_services = 0

        for host in result.hosts:
            open_ports = [p for p in host.ports if p.state == "open"]
            total_ports += len(open_ports)

            port_info = []
            for p in open_ports:
                svc = f" ({p.service}" if p.service else ""
                ver = f" {p.version}" if p.version else ""
                svc_end = ")" if p.service else ""
                port_info.append(f"{p.port}/{p.protocol}{svc}{ver}{svc_end}")
                if p.service:
                    total_services += 1

            host_summaries.append({
                "ip": host.ip,
                "hostname": host.hostname,
                "state": host.state,
                "os": host.os_match,
                "open_ports": port_info,
            })

        return {
            "action": "nmap_scan",
            "status": "success",
            "target": target,
            "hosts_found": len(result.hosts),
            "total_open_ports": total_ports,
            "total_services": total_services,
            "hosts": host_summaries,
            "errors": result.errors,
            "output": f"Scanned {target}: {len(result.hosts)} hosts, {total_ports} open ports, {total_services} services",
        }

    async def _do_dns_lookup(
        self,
        params: dict[str, Any],
        target: str,
        context: AgentContext,
    ) -> dict[str, Any]:
        """Execute DNS lookup."""
        enumerate_subs = params.get("enumerate_subdomains", False)

        result = await self._dns.resolve(target)

        subdomains: list[str] = []
        if enumerate_subs:
            sub_result = await self._dns.enumerate_subdomains(target)
            subdomains = sub_result.subdomains

        return {
            "action": "dns_lookup",
            "status": "success",
            "target": target,
            "records_found": len(result.records),
            "records": [
                {"type": r.record_type, "value": r.value, "ttl": r.ttl}
                for r in result.records
            ],
            "subdomains_found": len(subdomains),
            "subdomains": subdomains,
            "errors": result.errors,
            "output": f"DNS {target}: {len(result.records)} records, {len(subdomains)} subdomains",
        }

    async def _do_http_request(
        self,
        params: dict[str, Any],
        target: str,
        context: AgentContext,
    ) -> dict[str, Any]:
        """Execute HTTP request."""
        method = params.get("method", "GET")
        headers = params.get("headers", {})
        data = params.get("data")

        response = await self._http.request(HTTPRequest(
            url=target,
            method=method,
            headers=headers,
            data=data,
        ))

        return {
            "action": "http_request",
            "status": "success" if response.status_code > 0 else "error",
            "url": target,
            "method": method,
            "status_code": response.status_code,
            "content_type": response.content_type,
            "title": response.title,
            "body_size": response.body_size,
            "forms": response.forms,
            "links_found": len(response.links),
            "scripts_found": len(response.scripts),
            "security_headers": response.security_headers,
            "cookies": response.cookies,
            "error": response.error,
            "output": f"{method} {target} -> {response.status_code} ({response.content_type or 'unknown'})",
        }

    async def _do_crawl(
        self,
        params: dict[str, Any],
        target: str,
        context: AgentContext,
    ) -> dict[str, Any]:
        """Execute web crawl."""
        max_depth = params.get("max_depth", 2)
        max_pages = params.get("max_pages", 50)

        self._crawler.max_depth = max_depth
        self._crawler.max_pages = max_pages

        result = await self._crawler.crawl(target)

        # Extract JS API endpoints if we found scripts
        api_from_js: list[dict[str, Any]] = []
        if result.static_files:
            js_files = [f for f in result.static_files if f.endswith(".js")][:10]
            if js_files:
                api_from_js = await self._crawler.extract_api_endpoints(js_files)

        return {
            "action": "crawl_endpoint",
            "status": "success",
            "base_url": target,
            "pages_crawled": result.pages_crawled,
            "endpoints_found": len(result.endpoints),
            "forms_found": len(result.forms),
            "api_endpoints_found": len(result.api_endpoints),
            "js_api_endpoints": len(api_from_js),
            "external_links": len(result.external_links),
            "duration_seconds": result.duration_seconds,
            "forms": result.forms[:10],
            "api_endpoints": result.api_endpoints[:10],
            "js_apis": api_from_js[:10],
            "errors": result.errors[:5],
            "output": (
                f"Crawled {result.pages_crawled} pages: "
                f"{len(result.endpoints)} endpoints, "
                f"{len(result.forms)} forms, "
                f"{len(result.api_endpoints)} API endpoints"
            ),
        }
