"""Extract structured vulnerability patterns from raw findings using the LLM.

The extractor reads each finding from an engagement (the data stored in
AgentResult.findings by the ExploitAgent and ReconAgent) and prompts the
CerebrasClient to produce a structured VulnPattern.

The extraction prompt is designed for the Cerebras model's strengths:
fast, structured JSON output with security domain knowledge.

Integration point: Called by GenomePipeline after engagement completes.
Input: EngagementResult.agent_results (specifically exploit and recon findings)
Output: list[VulnPattern]
"""

import json
import logging
from uuid import uuid4
from typing import Any

from sentinel.core.client import CerebrasClient
from sentinel.core.client import ChatMessage
from sentinel.genome.models import VulnPattern

logger = logging.getLogger("sentinel.genome.extractor")

EXTRACTION_SYSTEM_PROMPT = """You are a security researcher analyzing vulnerability findings from a penetration test.
Your job is to extract a STRUCTURED vulnerability pattern from each finding.

For each finding, output a JSON object with EXACTLY these fields:
{
  "attack_vector": "specific attack method (e.g. sqli_union_based, reflected_xss_url_param, ssrf_to_internal_metadata)",
  "payload_family": "payload category (e.g. sql_injection, cross_site_scripting, server_side_request_forgery)",
  "detection_signature": "regex or string pattern that would detect this attack in network traffic",
  "root_cause": "why the vulnerability exists (e.g. string_concatenation_in_sql, unescaped_user_input_in_html)",
  "affected_component": "type of component (e.g. search_endpoint, user_profile_api, image_fetch)",
  "technology_stack": ["list", "of", "relevant", "technologies"],
  "severity": "critical|high|medium|low|info",
  "remediation_pattern": "how to fix (e.g. parameterized_queries, context_aware_output_encoding)",
  "remediation_code_example": "short code example of the fix or null if not applicable",
  "confidence": 0.0-1.0,
  "cwe_id": "CWE-XXX if known, null otherwise",
  "capec_id": "CAPEC-XXX if known, null otherwise"
}

Be precise and technical. The detection_signature should be a usable regex.
The remediation_code_example should be actual code, not pseudocode.
Output ONLY the JSON object, no explanation or markdown fences."""


class PatternExtractor:
    """Extract vulnerability patterns from engagement findings using LLM.

    Usage:
        extractor = PatternExtractor(client)
        patterns = await extractor.extract_from_results(engagement_result)
    """

    def __init__(self, client: CerebrasClient):
        self.client = client

    async def extract_from_results(
        self,
        agent_results: dict[str, Any],
        session_id: str = "",
    ) -> list[VulnPattern]:
        """Extract patterns from all agent results in an engagement.

        Looks for findings in exploit, recon, and any agent that produced
        vulnerability data. Each finding with enough context generates
        one VulnPattern.

        Args:
            agent_results: Dict of agent_name -> AgentResult from the engagement
            session_id: Engagement session identifier

        Returns:
            List of extracted VulnPattern objects
        """
        patterns: list[VulnPattern] = []
        findings = self._collect_findings(agent_results)

        for finding in findings:
            try:
                pattern = await self._extract_one(finding, session_id)
                if pattern:
                    patterns.append(pattern)
            except Exception as e:
                logger.error(
                    "pattern_extraction_failed",
                    finding_id=finding.get("id", "unknown"),
                    error=str(e),
                )

        logger.info(
            "extraction_complete",
            findings_processed=len(findings),
            patterns_extracted=len(patterns),
        )
        return patterns

    def _collect_findings(
        self, agent_results: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Collect all vulnerability findings from agent results.

        The exploit agent stores findings with keys like:
          - vulnerabilities_found: list of vuln dicts
          - tool_calls_made: int
          - exploitation_attempts: list of attempt dicts

        The recon agent stores findings with keys like:
          - endpoints_discovered: list
          - technologies_detected: list
          - potential_vulnerabilities: list

        We normalize these into a flat list of finding dicts,
        each with at minimum: id, type, description, severity.
        """
        findings: list[dict[str, Any]] = []
        finding_counter = 0

        for agent_name, result in agent_results.items():
            # AgentResult objects have a .findings dict attribute
            agent_findings = getattr(result, "findings", {})
            if not isinstance(agent_findings, dict):
                continue

            # Exploit agent findings
            vulns = agent_findings.get("vulnerabilities_found", [])
            if isinstance(vulns, list):
                for vuln in vulns:
                    if isinstance(vuln, dict):
                        finding_counter += 1
                        vuln.setdefault("id", f"finding-{finding_counter}")
                        vuln.setdefault("source_agent", agent_name)
                        findings.append(vuln)

            # Exploitation attempts that succeeded
            attempts = agent_findings.get("exploitation_attempts", [])
            if isinstance(attempts, list):
                for attempt in attempts:
                    if isinstance(attempt, dict) and attempt.get("success"):
                        finding_counter += 1
                        attempt.setdefault("id", f"exploit-{finding_counter}")
                        attempt.setdefault("source_agent", agent_name)
                        findings.append(attempt)

            # Recon potential vulnerabilities
            potential = agent_findings.get("potential_vulnerabilities", [])
            if isinstance(potential, list):
                for pv in potential:
                    if isinstance(pv, dict):
                        finding_counter += 1
                        pv.setdefault("id", f"recon-{finding_counter}")
                        pv.setdefault("source_agent", agent_name)
                        pv.setdefault("severity", "info")
                        findings.append(pv)

        # If no structured findings, try to extract from the raw findings dict
        # This handles cases where the agent stored findings in a flat format
        if not findings:
            for agent_name, result in agent_results.items():
                agent_findings = getattr(result, "findings", {})
                if isinstance(agent_findings, dict) and agent_findings:
                    # Create a single synthetic finding from the whole dict
                    finding_counter += 1
                    findings.append({
                        "id": f"raw-{finding_counter}",
                        "source_agent": agent_name,
                        "raw_data": agent_findings,
                        "severity": "medium",
                    })

        return findings

    async def _extract_one(
        self, finding: dict[str, Any], session_id: str
    ) -> VulnPattern | None:
        """Extract a single VulnPattern from a finding dict.

        Sends the finding context to the LLM and parses the structured
        JSON response into a VulnPattern.
        """
        finding_id = finding.get("id", str(uuid4())[:8])

        # Build context string from whatever fields the finding has
        context_parts = []
        for key in [
            "type", "vuln_type", "vulnerability_type",
            "severity", "title", "description",
            "endpoint", "url", "path",
            "method", "payload", "evidence",
            "reproduction_steps", "raw_data",
        ]:
            value = finding.get(key)
            if value:
                if isinstance(value, (list, dict)):
                    context_parts.append(
                        f"**{key}:** {json.dumps(value, indent=2, default=str)[:1500]}"
                    )
                else:
                    context_parts.append(f"**{key}:** {value}")

        # If we have almost nothing, skip
        if len(context_parts) < 2:
            logger.debug("skipping_sparse_finding", finding_id=finding_id)
            return None

        user_message = (
            "Analyze this vulnerability finding and extract a structured pattern:\n\n"
            + "\n".join(context_parts)
        )

        # Call the LLM
        messages = [
            ChatMessage(role="system", content=EXTRACTION_SYSTEM_PROMPT),
            ChatMessage(role="user", content=user_message),
        ]

        response_msg, _metrics = await self.client.chat(
            messages=messages,
            temperature=0.1,
            max_tokens=1000,
        )

        # Parse the JSON response
        text = (response_msg.content or "").strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            elif "```" in text:
                text = text.rsplit("```", 1)[0]
            text = text.strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            logger.warning(
                "json_parse_failed",
                finding_id=finding_id,
                error=str(e),
                response_preview=text[:200],
            )
            return None

        # Validate and construct VulnPattern
        try:
            return VulnPattern(
                id=str(uuid4()),
                source_finding_id=finding_id,
                source_session_id=session_id,
                attack_vector=data.get("attack_vector", "unknown"),
                payload_family=data.get("payload_family", "unknown"),
                detection_signature=data.get("detection_signature", ""),
                root_cause=data.get("root_cause", "unknown"),
                affected_component=data.get("affected_component", "unknown"),
                technology_stack=data.get("technology_stack", []),
                severity=data.get("severity", "medium"),
                remediation_pattern=data.get("remediation_pattern", "unknown"),
                remediation_code_example=data.get("remediation_code_example"),
                confidence=float(data.get("confidence", 0.5)),
                cwe_id=data.get("cwe_id"),
                capec_id=data.get("capec_id"),
            )
        except Exception as e:
            logger.warning(
                "pattern_construction_failed",
                finding_id=finding_id,
                error=str(e),
            )
            return None
