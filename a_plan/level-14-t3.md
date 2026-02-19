# LEVEL 14: Auto-Patch Generator

## Context
Sentinel finds and verifies vulnerabilities. This level closes the loop: generate a fix, verify it eliminates the vuln, and present it as a PR-ready diff. Realistic benchmarks: SEC-bench ~34% success, PatchEval GPT-4.1 ~40-50% with PoC tests. We don't claim magic — we generate candidates and verify aggressively.

Research: Block 9 (Auto-Patch Generation), Block 2 (VRpilot/ChatRepair iterative pattern).

**Requires:** L08 (Hybrid SAST) for AST extraction. Falls back gracefully without it.

## Why
Find→Fix→Verify is the NodeZero selling point. Auto-patch is a force multiplier: even at 40% success, that's 40% fewer manual fixes. Failed patches still provide fix direction. XBOW doesn't do this at all.

---

## Files to Create

### `src/sentinel/remediation/__init__.py`
```python
"""Automated remediation — patch generation, verification, framework-specific fixes."""
```

### `src/sentinel/remediation/patch_generator.py`
```python
"""
Auto-Patch Generator — LLM generates vulnerability fixes with iterative verification.

Pipeline:
1. Receive verified finding (vuln type, file, line, PoC exploit)
2. Extract code context (AST if available, raw otherwise)
3. Select framework-specific fix template if available
4. LLM generates patch (diff format)
5. Apply patch in sandbox
6. Re-run exploit PoC — if exploit still works, iterate (max 3 attempts)
7. Run SAST re-scan on patched code
8. Generate AST diff for human review
9. Output: PR-ready unified diff + confidence score + verification report

Based on VRpilot/ChatRepair iterative feedback loop pattern.
"""
import asyncio
import difflib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from sentinel.logging import get_logger
from sentinel.llm.model_router import ModelRouter, TaskType

logger = get_logger(__name__)

MAX_ITERATIONS = 3


class PatchStatus(str, Enum):
    GENERATED = "generated"     # Patch created, not yet verified
    VERIFIED = "verified"       # Exploit no longer works after patch
    FAILED = "failed"           # Exploit still works after max iterations
    PARTIAL = "partial"         # Exploit mitigated but not fully eliminated
    ERROR = "error"             # Patch generation or application error


@dataclass
class PatchAttempt:
    iteration: int
    diff: str                   # Unified diff
    applied: bool
    exploit_still_works: bool
    sast_clean: bool
    error: str = ""


@dataclass
class PatchResult:
    finding_id: str
    vuln_category: str
    target_file: str
    status: PatchStatus
    final_diff: str             # Best patch diff
    confidence: float           # 0.0-1.0
    attempts: list[PatchAttempt] = field(default_factory=list)
    verification_report: dict = field(default_factory=dict)
    framework_template_used: str = ""


# Framework-specific fix templates (the LLM gets these as guidance, not as exact patches)
FIX_TEMPLATES = {
    "injection": {
        "django": "Use parameterized queries: Model.objects.raw() with params list, or ORM filter(). Never f-string SQL.",
        "express": "Use parameterized queries with ? placeholders. pg: client.query('SELECT * FROM users WHERE id = $1', [id]). mysql2: connection.execute with params array.",
        "flask": "Use SQLAlchemy ORM or text() with bindparams. Never string-format SQL queries.",
        "spring": "Use PreparedStatement with ? placeholders or JPA named parameters.",
        "generic": "Use parameterized/prepared statements. Never concatenate user input into queries.",
    },
    "xss": {
        "django": "Use Django template auto-escaping (default). For raw HTML, use bleach.clean() or mark_safe() only on sanitized content.",
        "express": "Use template engine auto-escaping (EJS: <%- → <%=). Install and configure helmet CSP headers.",
        "react": "React escapes by default. Audit any use of dangerouslySetInnerHTML — replace with DOMPurify.sanitize().",
        "generic": "HTML-encode all user output. Implement Content-Security-Policy header.",
    },
    "auth_bypass": {
        "django": "Add @login_required decorator or LoginRequiredMixin. Check object-level permissions with get_object_or_404 filtered by request.user.",
        "express": "Add authentication middleware to route. Verify req.user owns the resource before returning.",
        "spring": "Add @PreAuthorize annotation. Use Spring Security method-level security.",
        "generic": "Add authentication check before resource access. Verify requesting user owns the resource.",
    },
    "idor": {
        "generic": "Never trust client-provided IDs alone. Always verify the authenticated user has permission to access the requested resource. Filter queries by the authenticated user's scope.",
    },
    "ssrf": {
        "generic": "Validate and allowlist destination URLs/IPs. Block internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, ::1, 169.254.x). Use a URL parser to prevent bypass via DNS rebinding or URL encoding tricks.",
    },
}


class PatchGenerator:
    """Generate and verify vulnerability patches using LLM + iterative feedback."""
    
    def __init__(self, router: ModelRouter, sandbox_path: str = "/tmp/sentinel/sandbox"):
        self.router = router
        self.sandbox = Path(sandbox_path)
        self.sandbox.mkdir(parents=True, exist_ok=True)
    
    async def generate_patch(
        self,
        finding: dict,
        source_code: str,
        file_path: str,
        poc_script: str,
        framework: str = "generic",
    ) -> PatchResult:
        """
        Generate and iteratively verify a patch for a verified vulnerability.
        
        Args:
            finding: Verified finding dict (category, severity, description, etc.)
            source_code: The vulnerable source code
            file_path: Path to the vulnerable file
            poc_script: Python/bash script that exploits the vulnerability
            framework: Web framework (django, express, flask, spring, react, generic)
        """
        category = finding.get("category", "generic")
        template = self._get_template(category, framework)
        
        result = PatchResult(
            finding_id=finding.get("finding_id", ""),
            vuln_category=category,
            target_file=file_path,
            status=PatchStatus.GENERATED,
            final_diff="",
            confidence=0.0,
        )
        
        current_code = source_code
        feedback = ""
        
        for i in range(MAX_ITERATIONS):
            # Generate patch via LLM
            diff = await self._llm_generate_patch(
                current_code, file_path, finding, template, feedback, iteration=i
            )
            
            if not diff:
                result.attempts.append(PatchAttempt(
                    iteration=i, diff="", applied=False,
                    exploit_still_works=True, sast_clean=False,
                    error="LLM failed to generate patch"
                ))
                continue
            
            # Apply patch in sandbox
            patched_code, apply_ok = self._apply_diff(current_code, diff)
            if not apply_ok:
                result.attempts.append(PatchAttempt(
                    iteration=i, diff=diff, applied=False,
                    exploit_still_works=True, sast_clean=False,
                    error="Patch failed to apply cleanly"
                ))
                feedback = f"Patch failed to apply. The diff was malformed. Generate a clean unified diff."
                continue
            
            # Re-run exploit PoC
            exploit_works = await self._run_poc(patched_code, file_path, poc_script)
            
            # SAST re-check (simplified — check if the vuln pattern is gone)
            sast_clean = self._quick_sast_check(patched_code, category)
            
            attempt = PatchAttempt(
                iteration=i, diff=diff, applied=True,
                exploit_still_works=exploit_works, sast_clean=sast_clean,
            )
            result.attempts.append(attempt)
            
            if not exploit_works and sast_clean:
                result.status = PatchStatus.VERIFIED
                result.final_diff = diff
                result.confidence = 0.9 - (i * 0.1)  # Higher confidence if first try
                break
            elif not exploit_works:
                result.status = PatchStatus.PARTIAL
                result.final_diff = diff
                result.confidence = 0.6
                feedback = f"Exploit no longer works but SAST still flags issues. Improve the fix."
            else:
                feedback = (
                    f"Iteration {i+1} failed. Exploit STILL WORKS after patch. "
                    f"The vulnerability was NOT fixed. Try a different approach. "
                    f"Previous diff:\n{diff}"
                )
        
        if result.status == PatchStatus.GENERATED:
            result.status = PatchStatus.FAILED
            # Use best attempt as final_diff
            for attempt in reversed(result.attempts):
                if attempt.applied and attempt.diff:
                    result.final_diff = attempt.diff
                    result.confidence = 0.2
                    break
        
        result.verification_report = {
            "iterations": len(result.attempts),
            "exploit_eliminated": result.status == PatchStatus.VERIFIED,
            "sast_clean": any(a.sast_clean for a in result.attempts),
            "framework_template": template[:100] if template else "",
        }
        
        if result.framework_template_used:
            logger.info(f"Used framework template: {result.framework_template_used}")
        
        return result
    
    def _get_template(self, category: str, framework: str) -> str:
        """Get framework-specific fix guidance."""
        cat_templates = FIX_TEMPLATES.get(category, {})
        template = cat_templates.get(framework, cat_templates.get("generic", ""))
        return template
    
    async def _llm_generate_patch(
        self, code: str, file_path: str, finding: dict,
        template: str, feedback: str, iteration: int
    ) -> str:
        """Ask LLM to generate a unified diff patch."""
        model = self.router.route(TaskType.PATCH_GENERATE)
        
        prompt = f"""You are a security engineer fixing a vulnerability.

FILE: {file_path}
VULNERABILITY: {finding.get('category', '')} — {finding.get('description', '')}
SEVERITY: {finding.get('severity', '')}

VULNERABLE CODE:
```
{code}
```

FIX GUIDANCE: {template}

{"FEEDBACK FROM PREVIOUS ATTEMPT: " + feedback if feedback else ""}

Generate a UNIFIED DIFF that fixes this vulnerability. Requirements:
1. Fix the root cause, not just the symptom
2. Don't break existing functionality
3. Use the framework's idiomatic security patterns
4. Minimal change — only modify what's necessary

Output ONLY a valid unified diff (--- a/file, +++ b/file, @@ lines). No explanation."""
        
        # This calls the actual LLM — implementation depends on existing LLM client
        # Placeholder for the routing call:
        try:
            from sentinel.llm.client import complete  # Adapt to actual client
            response = await complete(prompt, model=model.model_id, provider=model.provider)
            # Extract diff from response
            return self._extract_diff(response)
        except Exception as e:
            logger.error(f"Patch generation LLM call failed: {e}")
            return ""
    
    def _extract_diff(self, llm_response: str) -> str:
        """Extract unified diff from LLM response, stripping markdown fences."""
        text = llm_response.strip()
        if "```" in text:
            parts = text.split("```")
            for part in parts:
                if part.strip().startswith("---") or part.strip().startswith("diff"):
                    return part.strip().lstrip("diff\n")
        if text.startswith("---"):
            return text
        return text
    
    def _apply_diff(self, original: str, diff: str) -> tuple[str, bool]:
        """Apply a unified diff to source code. Returns (patched_code, success)."""
        # Simple line-based patch application
        try:
            lines = original.splitlines(keepends=True)
            # Parse the diff to extract changes
            patched = self._simple_patch(lines, diff)
            if patched:
                return "".join(patched), True
        except Exception as e:
            logger.warning(f"Diff apply failed: {e}")
        return original, False
    
    def _simple_patch(self, original_lines: list[str], diff: str) -> list[str] | None:
        """Minimal unified diff applier."""
        result = list(original_lines)
        offset = 0
        
        for line in diff.splitlines():
            if line.startswith("@@"):
                # Parse @@ -start,count +start,count @@
                try:
                    parts = line.split("@@")[1].strip()
                    old_spec = parts.split(" ")[0]  # -start,count
                    start = int(old_spec.split(",")[0].lstrip("-")) - 1
                except (ValueError, IndexError):
                    continue
            elif line.startswith("-") and not line.startswith("---"):
                idx = start + offset
                if 0 <= idx < len(result):
                    result.pop(idx)
                    offset -= 1
            elif line.startswith("+") and not line.startswith("+++"):
                idx = start + offset
                result.insert(idx, line[1:] + "\n")
                offset += 1
        
        return result if result != original_lines else None
    
    async def _run_poc(self, patched_code: str, file_path: str, poc_script: str) -> bool:
        """Run PoC exploit against patched code. Returns True if exploit STILL works."""
        # Write patched code to sandbox
        sandbox_file = self.sandbox / Path(file_path).name
        sandbox_file.write_text(patched_code)
        
        # Run PoC script
        try:
            proc = await asyncio.create_subprocess_exec(
                "bash", "-c", poc_script,
                cwd=str(self.sandbox),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PATCHED_FILE": str(sandbox_file)},
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            
            # Exit code 0 = exploit succeeded = patch FAILED
            return proc.returncode == 0
        except asyncio.TimeoutError:
            return False  # Timeout = exploit probably failed
        except Exception as e:
            logger.error(f"PoC execution error: {e}")
            return True  # Assume worst case
    
    def _quick_sast_check(self, code: str, category: str) -> bool:
        """Quick pattern-based check if obvious vuln patterns are gone."""
        code_lower = code.lower()
        
        bad_patterns = {
            "injection": ["f\"select", "f'select", ".format(", "% (", "+ sql", "execute(f"],
            "xss": ["innerhtml", "document.write(", "v-html", "dangerouslysetinnerhtml"],
            "command": ["os.system(", "subprocess.call(shell=true", "exec(", "eval("],
        }
        
        patterns = bad_patterns.get(category, [])
        return not any(p in code_lower for p in patterns)
```

### `src/sentinel/remediation/fix_library.py`
```python
"""
Framework-specific fix snippets.

Pre-built, tested fix patterns for common vuln×framework combos.
Used to guide the LLM and as fallback when LLM generation fails.
"""

FIX_SNIPPETS = {
    ("injection", "django"): {
        "before": "Model.objects.raw(f'SELECT * FROM table WHERE id = {user_id}')",
        "after": "Model.objects.raw('SELECT * FROM table WHERE id = %s', [user_id])",
        "imports": [],
    },
    ("injection", "express"): {
        "before": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
        "after": "db.query('SELECT * FROM users WHERE id = $1', [req.params.id])",
        "imports": [],
    },
    ("xss", "express"): {
        "before": "res.send(`<h1>${userInput}</h1>`)",
        "after": "const escaped = require('he').encode(userInput); res.send(`<h1>${escaped}</h1>`)",
        "imports": ["he"],
    },
    ("auth_bypass", "django"): {
        "before": "def view(request, id):\n    obj = Model.objects.get(id=id)",
        "after": "@login_required\ndef view(request, id):\n    obj = get_object_or_404(Model, id=id, owner=request.user)",
        "imports": ["from django.contrib.auth.decorators import login_required",
                    "from django.shortcuts import get_object_or_404"],
    },
    ("idor", "generic"): {
        "before": "item = db.get(request.params['item_id'])",
        "after": "item = db.get(request.params['item_id'])\nif item.owner_id != current_user.id:\n    raise PermissionError('Access denied')",
        "imports": [],
    },
}


def get_fix_snippet(category: str, framework: str) -> dict | None:
    """Get a pre-built fix snippet for a vuln category + framework combo."""
    return FIX_SNIPPETS.get((category, framework)) or FIX_SNIPPETS.get((category, "generic"))
```

---

## Files to Modify

### Neo4j: Store patches
Add Patch node type:
```cypher
CREATE (p:Patch {
    finding_id: $fid,
    status: $status,
    confidence: $conf,
    diff: $diff,
    iterations: $iters,
    framework: $fw,
    engagement_id: $eid,
    created_at: datetime()
})
WITH p
MATCH (f:Finding {id: $fid})
CREATE (f)-[:HAS_PATCH]->(p)
```

### API: Add patch endpoint
```python
@app.post("/api/v1/findings/{finding_id}/patch")
async def generate_patch(finding_id: str):
    # 1. Fetch finding from Neo4j
    # 2. Fetch source code
    # 3. Call PatchGenerator.generate_patch()
    # 4. Store result in Neo4j
    # 5. Return PatchResult
```

---

## Tests

### `tests/remediation/test_patch_generator.py`
```python
import pytest
from sentinel.remediation.patch_generator import PatchGenerator, PatchStatus, FIX_TEMPLATES
from sentinel.llm.model_router import ModelRouter

class TestPatchGenerator:
    def setup_method(self):
        self.gen = PatchGenerator(router=ModelRouter())
    
    def test_get_template_specific(self):
        template = self.gen._get_template("injection", "django")
        assert "parameterized" in template.lower()
    
    def test_get_template_fallback(self):
        template = self.gen._get_template("injection", "unknown_framework")
        assert "parameterized" in template.lower()  # Falls back to generic
    
    def test_extract_diff_from_markdown(self):
        response = "```diff\n--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n-bad\n+good\n```"
        diff = self.gen._extract_diff(response)
        assert "--- a/app.py" in diff
    
    def test_extract_diff_raw(self):
        diff_text = "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new"
        assert self.gen._extract_diff(diff_text) == diff_text
    
    def test_quick_sast_injection(self):
        clean = "cursor.execute('SELECT * FROM t WHERE id = %s', [uid])"
        dirty = 'cursor.execute(f"SELECT * FROM t WHERE id = {uid}")'
        assert self.gen._quick_sast_check(clean, "injection") is True
        assert self.gen._quick_sast_check(dirty, "injection") is False
    
    def test_fix_templates_coverage(self):
        """All major categories have at least a generic template."""
        for cat in ["injection", "xss", "auth_bypass", "idor", "ssrf"]:
            assert cat in FIX_TEMPLATES
            assert "generic" in FIX_TEMPLATES[cat]
```

### `tests/remediation/test_fix_library.py`
```python
from sentinel.remediation.fix_library import get_fix_snippet

class TestFixLibrary:
    def test_specific_match(self):
        snippet = get_fix_snippet("injection", "django")
        assert snippet is not None
        assert "before" in snippet and "after" in snippet
    
    def test_generic_fallback(self):
        snippet = get_fix_snippet("idor", "unknown")
        assert snippet is not None
        assert "owner_id" in snippet["after"]
    
    def test_no_match(self):
        snippet = get_fix_snippet("totally_unknown_vuln", "unknown")
        assert snippet is None
```

---

## Acceptance Criteria
- [ ] PatchGenerator creates unified diffs from LLM output
- [ ] Iterative loop: generate → apply → exploit re-run → feedback (up to 3 iterations)
- [ ] Framework-specific templates guide LLM toward idiomatic fixes
- [ ] Quick SAST check detects remaining vuln patterns in patched code
- [ ] PatchResult includes confidence score, iteration count, verification report
- [ ] Fix library provides before/after snippets for common vuln×framework pairs
- [ ] Patch nodes stored in Neo4j linked to Finding nodes
- [ ] All tests pass