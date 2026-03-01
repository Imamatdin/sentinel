"""Remediation module — Auto-Patch Generator for Sentinel.

Provides LLM-driven Find->Fix->Verify pipeline that generates patches,
applies them in sandbox, and re-runs PoC exploits to verify the fix.
"""

from sentinel.remediation.patch_generator import PatchGenerator, PatchResult, PatchStatus
from sentinel.remediation.fix_library import get_fix_snippet

__all__ = ["PatchGenerator", "PatchResult", "PatchStatus", "get_fix_snippet"]
