"""Tests for the fix_library module."""

from sentinel.remediation.fix_library import get_fix_snippet


def test_specific_match():
    """Injection x django returns the Django-specific snippet."""
    snippet = get_fix_snippet("injection", "django")
    assert snippet is not None
    assert "cursor.execute" in snippet["after"]
    assert "%s" in snippet["after"]


def test_generic_fallback():
    """IDOR x unknown_framework falls back to generic."""
    snippet = get_fix_snippet("idor", "unknown_framework")
    assert snippet is not None
    assert "owner" in snippet["after"].lower() or "Forbidden" in snippet["after"]


def test_no_match():
    """Completely unknown category returns None."""
    snippet = get_fix_snippet("zero_day_magic", "unknown")
    assert snippet is None
