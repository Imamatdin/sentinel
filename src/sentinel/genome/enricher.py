"""Enrich vulnerability patterns with CWE, CAPEC, and optionally NVD CVE data.

The enricher operates in two stages:
1. Static mapping (fast, no network): Maps known payload families to CWE/CAPEC IDs
   using a comprehensive lookup table covering OWASP Top 10 + common vuln types.
2. NVD lookup (optional, network): Searches the NVD 2.0 API for related CVEs.
   This stage is wrapped in a try/except with a short timeout. If NVD is
   unreachable, the pattern retains its static CWE/CAPEC classification.

The pipeline NEVER fails because of NVD. Static enrichment always succeeds.
"""

import asyncio
import logging
from typing import Optional

from sentinel.genome.models import VulnPattern

logger = logging.getLogger("sentinel.genome.enricher")

# ── Static CWE Mapping ──
# Maps payload_family (normalized lowercase) to CWE ID.
# Covers OWASP Top 10 2021 + common vulnerability classes.
CWE_MAP: dict[str, str] = {
    "sql_injection": "CWE-89",
    "sqli": "CWE-89",
    "cross_site_scripting": "CWE-79",
    "xss": "CWE-79",
    "reflected_xss": "CWE-79",
    "stored_xss": "CWE-79",
    "dom_xss": "CWE-79",
    "server_side_request_forgery": "CWE-918",
    "ssrf": "CWE-918",
    "path_traversal": "CWE-22",
    "directory_traversal": "CWE-22",
    "command_injection": "CWE-78",
    "os_command_injection": "CWE-78",
    "insecure_direct_object_reference": "CWE-639",
    "idor": "CWE-639",
    "broken_authentication": "CWE-287",
    "auth_bypass": "CWE-287",
    "security_misconfiguration": "CWE-16",
    "sensitive_data_exposure": "CWE-200",
    "information_disclosure": "CWE-200",
    "missing_access_control": "CWE-862",
    "broken_access_control": "CWE-862",
    "csrf": "CWE-352",
    "cross_site_request_forgery": "CWE-352",
    "xxe": "CWE-611",
    "xml_external_entity": "CWE-611",
    "insecure_deserialization": "CWE-502",
    "open_redirect": "CWE-601",
    "file_upload": "CWE-434",
    "unrestricted_upload": "CWE-434",
    "ldap_injection": "CWE-90",
    "xpath_injection": "CWE-643",
    "header_injection": "CWE-113",
    "crlf_injection": "CWE-93",
    "mass_assignment": "CWE-915",
    "race_condition": "CWE-362",
    "buffer_overflow": "CWE-120",
    "integer_overflow": "CWE-190",
    "use_after_free": "CWE-416",
    "hardcoded_credentials": "CWE-798",
    "weak_password": "CWE-521",
    "insufficient_logging": "CWE-778",
}

# ── Static CAPEC Mapping ──
CAPEC_MAP: dict[str, str] = {
    "sql_injection": "CAPEC-66",
    "sqli": "CAPEC-66",
    "cross_site_scripting": "CAPEC-86",
    "xss": "CAPEC-86",
    "reflected_xss": "CAPEC-86",
    "stored_xss": "CAPEC-86",
    "ssrf": "CAPEC-664",
    "server_side_request_forgery": "CAPEC-664",
    "path_traversal": "CAPEC-126",
    "directory_traversal": "CAPEC-126",
    "command_injection": "CAPEC-88",
    "os_command_injection": "CAPEC-88",
    "idor": "CAPEC-1",
    "insecure_direct_object_reference": "CAPEC-1",
    "csrf": "CAPEC-62",
    "cross_site_request_forgery": "CAPEC-62",
    "xxe": "CAPEC-201",
    "xml_external_entity": "CAPEC-201",
    "broken_authentication": "CAPEC-49",
    "auth_bypass": "CAPEC-115",
    "file_upload": "CAPEC-1",
    "ldap_injection": "CAPEC-136",
    "header_injection": "CAPEC-105",
    "mass_assignment": "CAPEC-220",
}

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class PatternEnricher:
    """Enrich vulnerability patterns with CWE/CAPEC/CVE classifications.

    Usage:
        enricher = PatternEnricher()
        enriched = await enricher.enrich(patterns)
    """

    def __init__(
        self,
        nvd_api_key: Optional[str] = None,
        enable_nvd: bool = True,
        nvd_timeout: float = 5.0,
    ):
        """Initialize enricher.

        Args:
            nvd_api_key: Optional NVD API key (increases rate limit from 5 to 50 req/30s)
            enable_nvd: Whether to attempt NVD lookups at all
            nvd_timeout: Timeout in seconds for NVD API calls
        """
        self.nvd_api_key = nvd_api_key
        self.enable_nvd = enable_nvd
        self.nvd_timeout = nvd_timeout
        # NVD rate limit: 6s between calls without key, 0.6s with key
        self._rate_limit_delay = 0.6 if nvd_api_key else 6.0

    async def enrich(self, patterns: list[VulnPattern]) -> list[VulnPattern]:
        """Enrich all patterns with classification data.

        Static CWE/CAPEC mapping runs for every pattern (always succeeds).
        NVD CVE lookup runs only if enable_nvd=True and is best-effort.

        Args:
            patterns: List of patterns to enrich

        Returns:
            The same list (mutated in place for efficiency), now with
            cwe_id, capec_id, and optionally cve_ids populated.
        """
        for pattern in patterns:
            self._apply_static_mappings(pattern)

        if self.enable_nvd:
            nvd_successes = 0
            nvd_failures = 0
            for pattern in patterns:
                if pattern.cwe_id:
                    success = await self._search_nvd(pattern)
                    if success:
                        nvd_successes += 1
                    else:
                        nvd_failures += 1
                    # Rate limit between NVD calls
                    await asyncio.sleep(self._rate_limit_delay)

            logger.info(
                "nvd_enrichment_complete",
                successes=nvd_successes,
                failures=nvd_failures,
            )

        logger.info(
            "enrichment_complete",
            patterns_enriched=len(patterns),
            with_cwe=sum(1 for p in patterns if p.cwe_id),
            with_capec=sum(1 for p in patterns if p.capec_id),
            with_cves=sum(1 for p in patterns if p.cve_ids),
        )
        return patterns

    def _apply_static_mappings(self, pattern: VulnPattern) -> None:
        """Apply CWE and CAPEC IDs from static lookup tables.

        Normalizes the payload_family to lowercase with underscores
        and looks up in both maps. Only sets values if they are not
        already present (LLM extraction may have set them).
        """
        payload = (
            pattern.payload_family.lower()
            .strip()
            .replace(" ", "_")
            .replace("-", "_")
        )

        if not pattern.cwe_id:
            pattern.cwe_id = CWE_MAP.get(payload)

        if not pattern.capec_id:
            pattern.capec_id = CAPEC_MAP.get(payload)

        # Also try matching by attack_vector if payload didn't match
        if not pattern.cwe_id:
            vector = (
                pattern.attack_vector.lower()
                .strip()
                .replace(" ", "_")
                .replace("-", "_")
            )
            pattern.cwe_id = CWE_MAP.get(vector)

        if not pattern.capec_id:
            vector = (
                pattern.attack_vector.lower()
                .strip()
                .replace(" ", "_")
                .replace("-", "_")
            )
            pattern.capec_id = CAPEC_MAP.get(vector)

    async def _search_nvd(self, pattern: VulnPattern) -> bool:
        """Search NVD for CVEs matching this pattern's CWE.

        Returns True on success, False on failure. Never raises.
        """
        if not pattern.cwe_id:
            return False

        try:
            import aiohttp

            headers: dict[str, str] = {}
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key

            params = {
                "cweId": pattern.cwe_id,
                "resultsPerPage": "5",
            }

            # Add a technology keyword for more specific results
            if pattern.technology_stack:
                params["keywordSearch"] = pattern.technology_stack[0]

            timeout = aiohttp.ClientTimeout(total=self.nvd_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    NVD_API_BASE, params=params, headers=headers
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        vulnerabilities = data.get("vulnerabilities", [])
                        pattern.cve_ids = [
                            v["cve"]["id"]
                            for v in vulnerabilities[:5]
                            if "cve" in v and "id" in v["cve"]
                        ]
                        return True
                    elif resp.status == 403:
                        logger.warning("nvd_rate_limited")
                    else:
                        logger.warning("nvd_error", status=resp.status)

        except ImportError:
            logger.warning("aiohttp_not_installed_skipping_nvd")
        except asyncio.TimeoutError:
            logger.warning("nvd_timeout", cwe_id=pattern.cwe_id)
        except Exception as e:
            logger.warning("nvd_lookup_failed", error=str(e))

        return False
