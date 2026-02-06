"""Port scanning and path bruteforce tools."""

import asyncio
from typing import Any

import aiohttp
import structlog

from sentinel.core.tools import ToolParameter, tool_schema
from sentinel.tools.base import ToolOutput, timed, run_subprocess
from sentinel.tools.http_tool import get_session
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


# Common web paths to check during recon
COMMON_PATHS = [
    "/", "/api", "/api/", "/api-docs", "/api-docs/",
    "/rest", "/rest/", "/admin", "/admin/",
    "/login", "/register", "/robots.txt", "/sitemap.xml",
    "/.well-known/security.txt", "/ftp", "/ftp/",
    "/assets", "/public", "/static",
    "/swagger.json", "/openapi.json",
    "/api/v1", "/api/v2",
    "/graphql", "/.git", "/.env",
    "/backup", "/dump", "/debug",
    "/metrics", "/health", "/status",
    "/socket.io", "/ws",
    "/profile", "/user", "/users",
    "/search", "/upload", "/download",
    "/redirect", "/proxy", "/file",
    "/b2bOrder", "/accounting",
    "/promotion", "/video",
    "/privacy-policy", "/legal",
]


@tool_schema(
    name="port_scan",
    description=(
        "Scan a target host for open ports. Use this at the start of reconnaissance "
        "to discover what services are running. Returns open ports with service names."
    ),
    parameters=[
        ToolParameter("target", "string", "Target hostname or IP address (e.g. 'localhost' or '192.168.1.1')"),
        ToolParameter(
            "scan_type",
            "string",
            "Type of scan to perform",
            required=False,
            enum=["quick", "common_web", "full"],
        ),
    ],
)
@timed
async def port_scan(target: str, scan_type: str = "quick") -> ToolOutput:
    """Scan ports on the target. Uses python-nmap if available, falls back to socket scanning."""
    try:
        import nmap

        scanner = nmap.PortScanner()

        if scan_type == "quick":
            nmap_args = "-sT -T4 --top-ports 100"
        elif scan_type == "common_web":
            nmap_args = "-sT -T4 -p 80,443,3000,3001,5000,8000,8080,8443,8888,9090"
        elif scan_type == "full":
            nmap_args = "-sT -T4 --top-ports 1000"
        else:
            nmap_args = "-sT -T4 --top-ports 100"

        # nmap.PortScanner.scan() is synchronous, so run in thread
        result = await asyncio.to_thread(scanner.scan, target, arguments=nmap_args)

        hosts = []
        for host in scanner.all_hosts():
            ports = []
            for proto in scanner[host].all_protocols():
                for port in sorted(scanner[host][proto].keys()):
                    port_info = scanner[host][proto][port]
                    if port_info["state"] == "open":
                        ports.append(
                            {
                                "port": port,
                                "protocol": proto,
                                "state": port_info["state"],
                                "service": port_info.get("name", "unknown"),
                                "product": port_info.get("product", ""),
                                "version": port_info.get("version", ""),
                            }
                        )
            hosts.append(
                {
                    "ip": host,
                    "hostname": scanner[host].hostname(),
                    "state": scanner[host].state(),
                    "ports": ports,
                }
            )

        return ToolOutput(
            tool_name="port_scan",
            success=True,
            data={
                "hosts": hosts,
                "scan_type": scan_type,
                "total_open_ports": sum(len(h["ports"]) for h in hosts),
            },
        )

    except ImportError:
        # Fallback: simple socket-based port scanning
        logger.warning("nmap_not_available", fallback="socket_scan")
        return await _socket_port_scan(target, scan_type)

    except Exception as e:
        # Also fallback on nmap errors (e.g. not installed)
        logger.warning(
            "nmap_scan_failed",
            error=str(e),
            fallback="socket_scan",
        )
        return await _socket_port_scan(target, scan_type)


async def _socket_port_scan(target: str, scan_type: str) -> ToolOutput:
    """Fallback port scanner using raw sockets."""
    import socket

    if scan_type == "common_web":
        ports_to_scan = [80, 443, 3000, 3001, 5000, 8000, 8080, 8443, 8888, 9090]
    elif scan_type == "full":
        ports_to_scan = list(range(1, 1001))
    else:
        ports_to_scan = [
            21, 22, 25, 53, 80, 110, 143, 443, 993, 995,
            3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 9090, 27017,
        ]

    open_ports = []
    semaphore = asyncio.Semaphore(50)  # Limit concurrent connections

    async def check_port(port: int) -> dict[str, Any] | None:
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": _guess_service(port),
                    "product": "",
                    "version": "",
                }
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return None

    results = await asyncio.gather(
        *[check_port(p) for p in ports_to_scan], return_exceptions=True
    )
    open_ports = [r for r in results if isinstance(r, dict)]

    return ToolOutput(
        tool_name="port_scan",
        success=True,
        data={
            "hosts": [
                {
                    "ip": target,
                    "hostname": target,
                    "state": "up" if open_ports else "unknown",
                    "ports": sorted(open_ports, key=lambda p: p["port"]),
                }
            ],
            "scan_type": scan_type,
            "total_open_ports": len(open_ports),
            "note": "Scanned with socket fallback (nmap not available)",
        },
    )


def _guess_service(port: int) -> str:
    """Guess service name from port number."""
    services = {
        21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http",
        110: "pop3", 143: "imap", 443: "https", 993: "imaps", 995: "pop3s",
        3000: "http-alt", 3306: "mysql", 5000: "http-alt", 5432: "postgresql",
        6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
        9090: "http-alt", 27017: "mongodb",
    }
    return services.get(port, "unknown")


@tool_schema(
    name="path_scan",
    description=(
        "Discover accessible paths and endpoints on a web application. "
        "Sends concurrent GET requests to common paths and reports which ones return "
        "non-404 responses. Use this during reconnaissance to map the attack surface."
    ),
    parameters=[
        ToolParameter("base_url", "string", "Base URL of the target (e.g. 'http://localhost:3000')"),
        ToolParameter(
            "wordlist",
            "string",
            "Which paths to scan: 'common' (50 paths, fast), 'extended' (150+ paths, slower)",
            required=False,
            enum=["common", "extended"],
        ),
        ToolParameter(
            "custom_paths",
            "string",
            "Comma-separated additional paths to check (e.g. '/api/v3,/internal,/hidden')",
            required=False,
        ),
    ],
)
@timed
async def path_scan(
    base_url: str,
    wordlist: str = "common",
    custom_paths: str | None = None,
) -> ToolOutput:
    """Scan for accessible paths on the target."""
    # Build path list
    paths = list(COMMON_PATHS)

    if wordlist == "extended":
        paths.extend([
            "/console", "/phpmyadmin", "/wp-admin", "/wp-login.php",
            "/administrator", "/manager", "/actuator", "/actuator/health",
            "/env", "/config", "/info", "/mappings",
            "/api/users", "/api/products", "/api/orders",
            "/api/BasketItems", "/api/Feedbacks", "/api/Complaints",
            "/api/Recycles", "/api/SecurityQuestions", "/api/SecurityAnswers",
            "/rest/products", "/rest/basket",
            "/rest/user", "/rest/admin",
            "/rest/captcha", "/rest/image-captcha",
            "/rest/continue-code", "/rest/continue-code-findIt",
            "/rest/saveLoginIp", "/rest/deluxe-membership",
            "/rest/memories", "/rest/chatbot",
            "/snippet", "/snippets",
            "/encryptionkeys", "/support/logs",
            "/metrics", "/b2bOrder",
            "/api/Cards", "/api/Addresss", "/api/Deliverys",
            "/dataerasure",
        ])

    if custom_paths:
        for p in custom_paths.split(","):
            p = p.strip()
            if p and not p.startswith("/"):
                p = "/" + p
            if p:
                paths.append(p)

    # Deduplicate
    paths = list(dict.fromkeys(paths))

    session = await get_session()
    semaphore = asyncio.Semaphore(20)  # Limit concurrency
    found: list[dict[str, Any]] = []

    async def check_path(path: str) -> dict[str, Any] | None:
        async with semaphore:
            url = base_url.rstrip("/") + path
            try:
                async with session.get(
                    url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    status = resp.status
                    if status != 404:
                        content_type = resp.headers.get("Content-Type", "")
                        content_length = resp.headers.get("Content-Length", "unknown")
                        return {
                            "path": path,
                            "status": status,
                            "content_type": content_type.split(";")[0].strip(),
                            "content_length": content_length,
                            "redirect": resp.headers.get("Location", None),
                        }
            except Exception:
                pass
            return None

    results = await asyncio.gather(
        *[check_path(p) for p in paths], return_exceptions=True
    )
    found = [r for r in results if isinstance(r, dict)]
    found.sort(key=lambda x: x["status"])

    # Categorize
    accessible = [f for f in found if f["status"] < 400]
    redirects = [f for f in found if 300 <= f["status"] < 400]
    auth_required = [f for f in found if f["status"] in (401, 403)]

    return ToolOutput(
        tool_name="path_scan",
        success=True,
        data={
            "base_url": base_url,
            "paths_scanned": len(paths),
            "paths_found": len(found),
            "accessible": accessible,
            "redirects": redirects,
            "auth_required": auth_required,
            "summary": {
                "total_found": len(found),
                "accessible": len(accessible),
                "redirects": len(redirects),
                "auth_required": len(auth_required),
            },
        },
    )
