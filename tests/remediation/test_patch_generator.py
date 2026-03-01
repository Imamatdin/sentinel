"""Tests for the PatchGenerator module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.remediation.patch_generator import (
    PatchGenerator,
    PatchStatus,
    PatchResult,
    FIX_TEMPLATES,
)
from sentinel.llm.model_router import ModelRouter, TaskType


# === Fixtures ===


@pytest.fixture
def mock_llm():
    llm = AsyncMock()
    llm.complete = AsyncMock()
    return llm


@pytest.fixture
def router():
    return ModelRouter()


@pytest.fixture
def generator(router, mock_llm, tmp_path):
    return PatchGenerator(router=router, llm_client=mock_llm, sandbox_path=tmp_path)


SAMPLE_CODE = """\
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
"""

SAMPLE_FINDING = {
    "id": "finding-001",
    "category": "injection",
    "severity": "high",
    "evidence": "SQL injection via f-string interpolation",
}


# === Template tests ===


def test_get_template_specific(generator):
    """Django injection returns parameterized query guidance."""
    template = generator._get_template("injection", "django")
    assert "parameterized" in template.lower()


def test_get_template_fallback(generator):
    """Unknown framework falls back to generic."""
    template = generator._get_template("injection", "unknown_framework")
    assert "parameterized" in template.lower() or "prepared" in template.lower()


# === Diff extraction tests ===


def test_extract_diff_from_markdown(generator):
    """Strips ```diff fences from LLM response."""
    response = '```diff\n--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n-old line\n+new line\n```'
    diff = generator._extract_diff(response)
    assert diff.startswith("--- a/app.py")
    assert "```" not in diff


def test_extract_diff_raw(generator):
    """Passthrough for raw diff without fences."""
    raw = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n-old\n+new"
    diff = generator._extract_diff(raw)
    assert diff == raw


# === SAST check tests ===


def test_quick_sast_injection_clean(generator):
    """Clean code (parameterized query) passes SAST."""
    clean_code = 'cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])'
    assert generator._quick_sast_check(clean_code, "injection") is True


def test_quick_sast_injection_dirty(generator):
    """Dirty code (f-string SQL) fails SAST."""
    dirty_code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
    assert generator._quick_sast_check(dirty_code, "injection") is False


def test_quick_sast_xss(generator):
    """innerHTML usage detected."""
    code = 'element.innerHTML = userInput;'
    assert generator._quick_sast_check(code, "xss") is False


def test_quick_sast_command(generator):
    """os.system usage detected."""
    code = 'os.system("rm -rf " + user_path)'
    assert generator._quick_sast_check(code, "command_injection") is False


# === Fix templates coverage ===


def test_fix_templates_coverage():
    """All major categories have a generic template."""
    for category in ["injection", "xss", "auth_bypass", "idor", "ssrf"]:
        assert "generic" in FIX_TEMPLATES[category], f"Missing generic for {category}"


# === Diff application tests ===


def test_apply_diff_simple(generator):
    """Basic +/- line application works."""
    original = "line1\nline2\nline3\n"
    diff = (
        "--- a/file.py\n"
        "+++ b/file.py\n"
        "@@ -1,3 +1,3 @@\n"
        " line1\n"
        "-line2\n"
        "+replaced2\n"
        " line3\n"
    )
    patched, success = generator._apply_diff(original, diff)
    assert success is True
    assert "replaced2" in patched
    assert "line2" not in patched


def test_apply_diff_malformed(generator):
    """Malformed diff returns original unchanged."""
    original = "line1\nline2\n"
    diff = "@@ -1,2 +1,2 @@\n-nonexistent_line\n+replacement\n"
    patched, success = generator._apply_diff(original, diff)
    assert success is False
    assert patched == original


# === Full pipeline tests ===


@pytest.mark.asyncio
async def test_generate_patch_verified(generator, mock_llm, tmp_path):
    """Mock LLM returns good patch, PoC fails -> VERIFIED."""
    # LLM returns a clean diff
    good_diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def get_user(user_id):\n"
        '-    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        '+    query = "SELECT * FROM users WHERE id = %s"\n'
        "     return db.execute(query)\n"
    )
    mock_llm.complete.return_value = MagicMock(content=good_diff)

    # Mock _run_poc to return False (exploit no longer works)
    with patch.object(generator, "_run_poc", new_callable=AsyncMock, return_value=False):
        result = await generator.generate_patch(
            finding=SAMPLE_FINDING,
            source_code=SAMPLE_CODE,
            file_path="app.py",
            poc_script="print('exploit')",
            framework="generic",
        )

    assert result.status == PatchStatus.VERIFIED
    assert result.confidence > 0.8
    assert len(result.attempts) == 1
    assert result.attempts[0].applied is True


@pytest.mark.asyncio
async def test_generate_patch_iterates(generator, mock_llm, tmp_path):
    """First attempt fails (exploit still works), second succeeds."""
    bad_diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def get_user(user_id):\n"
        '-    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        '+    query = f"SELECT * FROM users WHERE id = {int(user_id)}"\n'
        "     return db.execute(query)\n"
    )
    good_diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def get_user(user_id):\n"
        '-    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        '+    query = "SELECT * FROM users WHERE id = %s"\n'
        "     return db.execute(query)\n"
    )

    # First call returns bad patch (SAST still fails), second returns good
    mock_llm.complete.side_effect = [
        MagicMock(content=bad_diff),
        MagicMock(content=good_diff),
    ]

    poc_returns = [True, False]  # First: exploit works; Second: exploit fixed
    with patch.object(generator, "_run_poc", new_callable=AsyncMock, side_effect=poc_returns):
        result = await generator.generate_patch(
            finding=SAMPLE_FINDING,
            source_code=SAMPLE_CODE,
            file_path="app.py",
            poc_script="print('exploit')",
        )

    assert result.status == PatchStatus.VERIFIED
    assert len(result.attempts) == 2
    assert result.attempts[0].exploit_still_works is True
    assert result.attempts[1].exploit_still_works is False


@pytest.mark.asyncio
async def test_generate_patch_max_iterations(generator, mock_llm, tmp_path):
    """All 3 iterations fail -> FAILED status."""
    bad_diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def get_user(user_id):\n"
        '-    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        '+    query = f"SELECT * FROM users WHERE id = {int(user_id)}"\n'
        "     return db.execute(query)\n"
    )
    mock_llm.complete.return_value = MagicMock(content=bad_diff)

    with patch.object(generator, "_run_poc", new_callable=AsyncMock, return_value=True):
        result = await generator.generate_patch(
            finding=SAMPLE_FINDING,
            source_code=SAMPLE_CODE,
            file_path="app.py",
            poc_script="print('exploit')",
        )

    assert result.status == PatchStatus.FAILED
    assert len(result.attempts) == 3
    assert result.confidence <= 0.2


@pytest.mark.asyncio
async def test_generate_patch_partial(generator, mock_llm, tmp_path):
    """Exploit eliminated but SAST still flags -> PARTIAL."""
    # Patch that stops exploit but still has f-string SQL (SAST will flag)
    partial_diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def get_user(user_id):\n"
        '-    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        '+    query = f"SELECT * FROM users WHERE id = {int(user_id)}"\n'
        "     return db.execute(query)\n"
    )
    mock_llm.complete.return_value = MagicMock(content=partial_diff)

    # Exploit no longer works but SAST still flags
    with patch.object(generator, "_run_poc", new_callable=AsyncMock, return_value=False):
        result = await generator.generate_patch(
            finding=SAMPLE_FINDING,
            source_code=SAMPLE_CODE,
            file_path="app.py",
            poc_script="print('exploit')",
        )

    assert result.status == PatchStatus.PARTIAL
    assert "SAST" in result.verification_report
