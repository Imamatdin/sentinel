#!/usr/bin/env python3
"""Verify Sentinel Phase 0 setup is complete."""

import asyncio
import sys
from pathlib import Path


def check_mark(success: bool) -> str:
    try:
        mark = "\u2705" if success else "\u274c"
        mark.encode(sys.stdout.encoding or "utf-8")
        return mark
    except (UnicodeEncodeError, LookupError):
        return "[PASS]" if success else "[FAIL]"


async def verify_setup() -> bool:
    """Run all verification checks."""
    print("\n" + "=" * 60)
    print("SENTINEL PHASE 0 VERIFICATION")
    print("=" * 60 + "\n")

    all_passed = True

    # 1. Check Python version
    py_version = sys.version_info
    py_ok = py_version >= (3, 11)
    print(f"{check_mark(py_ok)} Python version: {py_version.major}.{py_version.minor}.{py_version.micro}")
    all_passed &= py_ok

    # 2. Check required directories
    required_dirs = [
        "src/sentinel/core",
        "src/sentinel/graph",
        "src/sentinel/orchestration",
        "src/sentinel/agents",
        "src/sentinel/tools",
        "src/sentinel/genome",
        "src/sentinel/api",
        "infrastructure",
        "benchmarks",
        "reports",
    ]
    for dir_path in required_dirs:
        exists = Path(dir_path).exists()
        print(f"{check_mark(exists)} Directory: {dir_path}")
        all_passed &= exists

    # 3. Check required files
    required_files = [
        "src/sentinel/core/config.py",
        "src/sentinel/core/logging.py",
        "src/sentinel/core/exceptions.py",
        "infrastructure/docker-compose.yml",
        ".env",
    ]
    for file_path in required_files:
        exists = Path(file_path).exists()
        print(f"{check_mark(exists)} File: {file_path}")
        all_passed &= exists

    # 4. Check imports
    print("\n--- Import Checks ---")
    try:
        from sentinel.core import get_settings, get_logger, setup_logging
        print(f"{check_mark(True)} Core imports successful")
    except ImportError as e:
        print(f"{check_mark(False)} Core imports failed: {e}")
        all_passed = False

    # 5. Check config loads
    try:
        from sentinel.core.config import get_settings
        settings = get_settings()
        print(f"{check_mark(True)} Config loaded: {settings.app_name}")
    except Exception as e:
        print(f"{check_mark(False)} Config failed: {e}")
        all_passed = False

    # 6. Check Docker services (if running)
    print("\n--- Docker Services ---")
    import subprocess

    services = ["neo4j", "temporal", "postgres", "zap", "juice-shop"]
    for service in services:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name=sentinel-{service}", "--format", "{{.Status}}"],
            capture_output=True,
            text=True,
        )
        running = "Up" in result.stdout
        status = result.stdout.strip() if running else "Not running"
        print(f"{check_mark(running)} {service}: {status}")

    # Summary
    print("\n" + "=" * 60)
    if all_passed:
        print(f"{check_mark(True)} PHASE 0 SETUP COMPLETE")
        print("Run: docker compose -f infrastructure/docker-compose.yml up -d")
        print("Then proceed to Phase 1: Knowledge Graph Engine")
    else:
        print(f"{check_mark(False)} SETUP INCOMPLETE - Fix issues above")
    print("=" * 60 + "\n")

    return all_passed


if __name__ == "__main__":
    success = asyncio.run(verify_setup())
    sys.exit(0 if success else 1)
