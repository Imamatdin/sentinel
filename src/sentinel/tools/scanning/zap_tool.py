"""
ZAPTool — OWASP ZAP DAST scanner integration.

Connects to ZAP running as a daemon (Docker service) and orchestrates:
- Spider crawling
- Active scanning
- Alert retrieval and parsing
"""
import asyncio
import aiohttp
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from sentinel.tools.base import ToolOutput
from sentinel.core.config import get_settings
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


class ZAPRisk(str, Enum):
    HIGH = "3"
    MEDIUM = "2"
    LOW = "1"
    INFORMATIONAL = "0"


class ZAPConfidence(str, Enum):
    HIGH = "3"
    MEDIUM = "2"
    LOW = "1"
    FALSE_POSITIVE = "0"


@dataclass
class ZAPAlert:
    alert_id: int
    name: str
    risk: str
    confidence: str
    description: str
    url: str
    method: str
    param: str
    attack: str
    evidence: str
    solution: str
    reference: str
    cwe_id: int = 0
    wasc_id: int = 0
    tags: dict = field(default_factory=dict)


class ZAPTool:
    """
    Orchestrates OWASP ZAP scans via its REST API.

    Prerequisites:
    - ZAP running as daemon: docker run -u zap -p 8080:8080 zaproxy/zap-stable zap.sh -daemon -port 8080 -config api.disablekey=true
    - Or via docker-compose service (already defined in project)

    Supports:
    - Spider crawling (discover pages)
    - Ajax Spider (for SPAs)
    - Active scanning (find vulns)
    - Passive scanning (analyze traffic)
    - Authentication context setup
    """

    name = "zap_scan"
    description = "Run OWASP ZAP dynamic application security testing"

    def __init__(self):
        settings = get_settings()
        self.base_url = getattr(settings, "zap_api_url", "http://localhost:8080")
        self.api_key = getattr(settings, "zap_api_key", "")

    async def _api_call(self, endpoint: str, params: dict = None) -> dict:
        """Make ZAP API call."""
        params = params or {}
        if self.api_key:
            params["apikey"] = self.api_key

        url = f"{self.base_url}/{endpoint}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as resp:
                return await resp.json()

    async def spider(self, target: str, max_depth: int = 5) -> ToolOutput:
        """Run ZAP spider to discover URLs."""
        try:
            # Start spider
            result = await self._api_call("JSON/spider/action/scan/", {
                "url": target,
                "maxDepth": str(max_depth),
            })
            scan_id = result.get("scan")

            # Poll until complete
            while True:
                status = await self._api_call("JSON/spider/view/status/", {
                    "scanId": scan_id
                })
                progress = int(status.get("status", "0"))
                if progress >= 100:
                    break
                await asyncio.sleep(2)

            # Get results
            urls = await self._api_call("JSON/spider/view/results/", {
                "scanId": scan_id
            })

            return ToolOutput(
                success=True,
                data={"urls": urls.get("results", [])},
                tool_name=self.name,
                metadata={"phase": "spider", "urls_found": len(urls.get("results", []))}
            )
        except Exception as e:
            return ToolOutput(success=False, data={}, error=str(e), tool_name=self.name)

    async def active_scan(self, target: str, scan_policy: Optional[str] = None) -> ToolOutput:
        """Run ZAP active scan."""
        try:
            params = {"url": target}
            if scan_policy:
                params["scanPolicyName"] = scan_policy

            result = await self._api_call("JSON/ascan/action/scan/", params)
            scan_id = result.get("scan")

            # Poll until complete
            while True:
                status = await self._api_call("JSON/ascan/view/status/", {
                    "scanId": scan_id
                })
                progress = int(status.get("status", "0"))
                logger.info(f"ZAP active scan progress: {progress}%")
                if progress >= 100:
                    break
                await asyncio.sleep(5)

            # Get alerts
            alerts_data = await self._api_call("JSON/core/view/alerts/", {
                "baseurl": target
            })

            alerts = [
                ZAPAlert(
                    alert_id=int(a.get("id", 0)),
                    name=a.get("name", ""),
                    risk=a.get("risk", ""),
                    confidence=a.get("confidence", ""),
                    description=a.get("description", ""),
                    url=a.get("url", ""),
                    method=a.get("method", ""),
                    param=a.get("param", ""),
                    attack=a.get("attack", ""),
                    evidence=a.get("evidence", ""),
                    solution=a.get("solution", ""),
                    reference=a.get("reference", ""),
                    cwe_id=int(a.get("cweid", 0)),
                    wasc_id=int(a.get("wascid", 0)),
                    tags=a.get("tags", {}),
                )
                for a in alerts_data.get("alerts", [])
            ]

            return ToolOutput(
                success=True,
                data={"alerts": alerts},
                tool_name=self.name,
                metadata={
                    "phase": "active_scan",
                    "total_alerts": len(alerts),
                    "by_risk": self._count_by_risk(alerts),
                }
            )
        except Exception as e:
            return ToolOutput(success=False, data={}, error=str(e), tool_name=self.name)

    async def execute(self, target: str, full_scan: bool = True) -> ToolOutput:
        """Run full ZAP pipeline: spider → active scan → collect alerts."""
        spider_result = await self.spider(target)
        if not spider_result.success:
            return spider_result

        if full_scan:
            return await self.active_scan(target)

        return spider_result

    def _count_by_risk(self, alerts: list[ZAPAlert]) -> dict[str, int]:
        counts = {}
        for a in alerts:
            counts[a.risk] = counts.get(a.risk, 0) + 1
        return counts
