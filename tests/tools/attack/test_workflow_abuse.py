import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.tools.attack.workflow_abuse import (
    WorkflowAbuseTester, WorkflowStep, WorkflowAbuseFinding,
)


class TestWorkflowAbuseTester:
    def setup_method(self):
        self.tester = WorkflowAbuseTester()
        self.steps = [
            WorkflowStep("add_to_cart", "/cart/add", "POST", body={"item": 1}),
            WorkflowStep("enter_shipping", "/checkout/shipping", "POST", body={"addr": "123 St"}),
            WorkflowStep("enter_payment", "/checkout/payment", "POST", body={"card": "4111"}),
            WorkflowStep("confirm_order", "/checkout/confirm", "POST"),
        ]

    def test_step_dataclass(self):
        s = WorkflowStep("login", "/auth/login", "POST", body={"user": "a"})
        assert s.name == "login"
        assert s.expected_status == 200

    def test_finding_dataclass(self):
        f = WorkflowAbuseFinding(
            attack_type="step_skip",
            skipped_steps=["payment"],
            endpoint_accessed="/checkout/confirm",
            status_code=200,
            description="Skipped payment",
        )
        assert f.severity == "high"
        assert f.attack_type == "step_skip"

    def test_tool_name(self):
        assert self.tester.name == "workflow_abuse"

    @pytest.mark.asyncio
    async def test_detects_step_skip_to_final(self):
        """Jump to confirm without doing cart/shipping/payment -> detected."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await self.tester.execute(
                workflow_steps=self.steps,
                session_headers={"Cookie": "session=abc"},
                base_url="http://target.com",
            )

        assert result.success is True
        findings = result.data["findings"]
        # Should find skip-to-last + intermediate skips
        assert len(findings) >= 1
        skip_to_last = [f for f in findings if len(f["skipped_steps"]) > 1]
        assert len(skip_to_last) >= 1

    @pytest.mark.asyncio
    async def test_no_finding_when_server_rejects(self):
        """Server returns 403 for out-of-order access -> no finding."""
        mock_resp = MagicMock()
        mock_resp.status = 403
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await self.tester.execute(
                workflow_steps=self.steps,
                session_headers={},
                base_url="http://target.com",
            )

        assert result.success is True
        assert len(result.data["findings"]) == 0

    @pytest.mark.asyncio
    async def test_single_step_workflow_no_crash(self):
        """A single-step workflow shouldn't crash (no skip-to-last test)."""
        single = [WorkflowStep("login", "/login", "POST")]

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await self.tester.execute(
                workflow_steps=single,
                session_headers={},
                base_url="http://target.com",
            )

        assert result.success is True

    @pytest.mark.asyncio
    async def test_intermediate_skip_detected(self):
        """Skip only step 2 of 3 -> detected."""
        three_steps = [
            WorkflowStep("step1", "/step1", "POST"),
            WorkflowStep("step2", "/step2", "POST"),
            WorkflowStep("step3", "/step3", "POST"),
        ]

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await self.tester.execute(
                workflow_steps=three_steps,
                session_headers={},
                base_url="http://target.com",
            )

        findings = result.data["findings"]
        # Should detect skipping step2 to reach step3
        skip_names = []
        for f in findings:
            skip_names.extend(f["skipped_steps"])
        assert "step2" in skip_names

    @pytest.mark.asyncio
    async def test_connection_error_no_crash(self):
        """Network errors during partial execution -> graceful failure."""
        mock_session = MagicMock()
        mock_session.request = MagicMock(
            side_effect=Exception("connection reset")
        )
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await self.tester.execute(
                workflow_steps=self.steps,
                session_headers={},
                base_url="http://target.com",
            )

        assert result.success is True

    @pytest.mark.asyncio
    async def test_metadata_counts(self):
        """Metadata tracks test count and finding count."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await self.tester.execute(
                workflow_steps=self.steps,
                session_headers={},
                base_url="http://target.com",
            )

        assert result.metadata["tests_run"] == len(self.steps)
        assert result.metadata["findings"] == len(result.data["findings"])

    @pytest.mark.asyncio
    async def test_empty_workflow(self):
        """Empty workflow list -> no crash, no findings."""
        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await self.tester.execute(
                workflow_steps=[],
                session_headers={},
                base_url="http://target.com",
            )

        assert result.success is True
        assert len(result.data["findings"]) == 0
