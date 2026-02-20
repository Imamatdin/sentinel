"""Tests for SCA Scanner."""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from sentinel.tools.supply_chain.sca_scanner import SCAScanner, PackageManager, VulnerableDependency


class TestSCAScanner:
    def setup_method(self):
        self.scanner = SCAScanner()

    def test_detect_npm(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        managers = self.scanner._detect_managers(tmp_path)
        assert PackageManager.NPM in managers

    def test_detect_pip(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==2.0")
        managers = self.scanner._detect_managers(tmp_path)
        assert PackageManager.PIP in managers

    def test_detect_multiple(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        (tmp_path / "requirements.txt").write_text("flask==2.0")
        managers = self.scanner._detect_managers(tmp_path)
        assert PackageManager.NPM in managers
        assert PackageManager.PIP in managers

    def test_detect_none(self, tmp_path):
        managers = self.scanner._detect_managers(tmp_path)
        assert managers == []

    def test_detect_pyproject(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.poetry]")
        managers = self.scanner._detect_managers(tmp_path)
        assert PackageManager.PIP in managers

    def test_detect_go_mod(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/foo")
        managers = self.scanner._detect_managers(tmp_path)
        assert PackageManager.GO in managers

    def test_detect_cargo(self, tmp_path):
        (tmp_path / "Cargo.lock").write_text("")
        managers = self.scanner._detect_managers(tmp_path)
        assert PackageManager.CARGO in managers

    @pytest.mark.asyncio
    async def test_execute_path_not_found(self):
        result = await self.scanner.execute("/nonexistent/path")
        assert not result.success
        assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_execute_no_manifests(self, tmp_path):
        result = await self.scanner.execute(str(tmp_path))
        assert not result.success
        assert "No supported manifest" in result.error

    @pytest.mark.asyncio
    async def test_scan_npm_parses_output(self):
        """Test npm audit JSON parsing."""
        npm_output = json.dumps({
            "vulnerabilities": {
                "express": {
                    "range": "<=4.17.1",
                    "isDirect": True,
                    "fixAvailable": {"version": "4.18.0"},
                    "via": [
                        {
                            "url": "https://github.com/advisories/GHSA-1234",
                            "severity": "high",
                            "title": "Path traversal in express",
                        }
                    ],
                }
            }
        })

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(npm_output.encode(), b""))
            mock_exec.return_value = mock_proc

            from pathlib import Path
            vulns = await self.scanner._scan_npm(Path("/fake"))
            assert len(vulns) == 1
            assert vulns[0].name == "express"
            assert vulns[0].severity == "high"
            assert vulns[0].is_direct is True
            assert vulns[0].package_manager == PackageManager.NPM

    @pytest.mark.asyncio
    async def test_scan_npm_handles_error(self):
        """npm audit failure should return empty list."""
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("npm not found")):
            from pathlib import Path
            vulns = await self.scanner._scan_npm(Path("/fake"))
            assert vulns == []

    def test_count_by_severity(self):
        vulns = [
            VulnerableDependency(
                name="a", version="1", cve_id="CVE-1", severity="high",
                fixed_version="2", description="", package_manager=PackageManager.NPM, is_direct=True,
            ),
            VulnerableDependency(
                name="b", version="1", cve_id="CVE-2", severity="high",
                fixed_version="2", description="", package_manager=PackageManager.NPM, is_direct=True,
            ),
            VulnerableDependency(
                name="c", version="1", cve_id="CVE-3", severity="critical",
                fixed_version="2", description="", package_manager=PackageManager.NPM, is_direct=True,
            ),
        ]
        counts = SCAScanner._count_by_severity(vulns)
        assert counts == {"high": 2, "critical": 1}

    def test_vulnerable_dependency_dataclass(self):
        v = VulnerableDependency(
            name="lodash",
            version="4.17.15",
            cve_id="CVE-2020-28500",
            severity="high",
            fixed_version="4.17.21",
            description="Prototype pollution",
            package_manager=PackageManager.NPM,
            is_direct=True,
        )
        assert v.name == "lodash"
        assert v.is_reachable is False
        assert v.call_chain == []
