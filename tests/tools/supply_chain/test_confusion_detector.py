"""Tests for Dependency Confusion Detector."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sentinel.tools.supply_chain.confusion_detector import ConfusionDetector, ConfusionAlert


class TestConfusionDetector:
    def setup_method(self):
        self.detector = ConfusionDetector()

    def test_typosquatting_detection_pip(self):
        alert = self.detector._check_typosquatting("reqeusts", "pip")
        assert alert is not None
        assert alert.alert_type == "typosquatting"
        assert alert.similar_to == "requests"

    def test_typosquatting_detection_npm(self):
        alert = self.detector._check_typosquatting("expresss", "npm")
        assert alert is not None
        assert alert.alert_type == "typosquatting"
        assert alert.similar_to == "express"

    def test_no_false_positive_on_exact(self):
        alert = self.detector._check_typosquatting("requests", "pip")
        assert alert is None

    def test_no_alert_on_dissimilar(self):
        alert = self.detector._check_typosquatting("my-internal-lib", "pip")
        assert alert is None

    def test_no_alert_on_unknown_registry(self):
        alert = self.detector._check_typosquatting("something", "cargo")
        assert alert is None

    @pytest.mark.asyncio
    async def test_execute_finds_typosquatting(self):
        deps = [{"name": "reqeusts", "version": "1.0"}]
        result = await self.detector.execute(deps, registry="pip")
        assert result.success
        alerts = result.data["alerts"]
        assert len(alerts) >= 1
        assert alerts[0]["alert_type"] == "typosquatting"

    @pytest.mark.asyncio
    async def test_execute_finds_dependency_confusion(self):
        deps = [{"name": "my-company-utils", "version": "1.0", "is_private": True}]

        with patch.object(self.detector, "_check_public_registry", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = True  # Exists on public registry
            result = await self.detector.execute(deps, registry="npm")

            assert result.success
            alerts = result.data["alerts"]
            confusion_alerts = [a for a in alerts if a["alert_type"] == "dependency_confusion"]
            assert len(confusion_alerts) == 1
            assert confusion_alerts[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_execute_no_confusion_when_not_public(self):
        deps = [{"name": "my-internal-only", "version": "1.0", "is_private": True}]

        with patch.object(self.detector, "_check_public_registry", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = False
            result = await self.detector.execute(deps, registry="npm")

            alerts = result.data["alerts"]
            confusion_alerts = [a for a in alerts if a["alert_type"] == "dependency_confusion"]
            assert len(confusion_alerts) == 0

    @pytest.mark.asyncio
    async def test_execute_empty_deps(self):
        result = await self.detector.execute([], registry="npm")
        assert result.success
        assert result.data["alerts"] == []

    def test_alert_dataclass(self):
        alert = ConfusionAlert(
            package_name="evil-pkg",
            alert_type="dependency_confusion",
            severity="critical",
            description="Bad package",
        )
        assert alert.package_name == "evil-pkg"
        assert alert.similar_to == ""
        assert alert.recommendation == ""

    @pytest.mark.asyncio
    async def test_check_public_registry_network_error(self):
        """Network errors should return False, not crash."""
        with patch("sentinel.tools.supply_chain.confusion_detector.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.head = AsyncMock(side_effect=Exception("timeout"))

            result = await self.detector._check_public_registry("test-pkg", "npm")
            assert result is False
