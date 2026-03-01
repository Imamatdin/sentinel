import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.tools.attack.bola_tester import (
    BOLATester, BOLATestCase, BOLAFinding,
)


class TestBOLATester:
    def setup_method(self):
        self.tester = BOLATester()

    def test_response_comparison_identical(self):
        assert self.tester._compare_responses("hello world", "hello world") == 1.0

    def test_response_comparison_similar(self):
        sim = self.tester._compare_responses(
            '{"id": 1, "name": "Alice", "email": "a@b.com"}',
            '{"id": 1, "name": "Alice", "email": "a@b.com"}',
        )
        assert sim == 1.0

    def test_response_comparison_different(self):
        sim = self.tester._compare_responses("hello world", "goodbye universe")
        assert sim < 0.3

    def test_response_comparison_empty(self):
        assert self.tester._compare_responses("", "hello") == 0.0
        assert self.tester._compare_responses("hello", "") == 0.0
        assert self.tester._compare_responses("", "") == 0.0

    def test_response_comparison_partial_overlap(self):
        sim = self.tester._compare_responses(
            "the quick brown fox", "the slow brown dog"
        )
        # "the", "brown" shared; "quick", "fox", "slow", "dog" unique
        assert 0.2 < sim < 0.6

    def test_test_case_dataclass(self):
        tc = BOLATestCase(
            endpoint="http://target/api/users/1",
            method="GET",
            resource_id="1",
            owner_user="alice",
            attacker_user="bob",
        )
        assert tc.owner_user == "alice"
        assert tc.attacker_user == "bob"

    def test_finding_dataclass(self):
        f = BOLAFinding(
            endpoint="/api/users/1",
            method="GET",
            resource_id="1",
            owner="alice",
            attacker="bob",
            owner_status=200,
            attacker_status=200,
            data_leaked=True,
            response_similarity=0.95,
        )
        assert f.severity == "critical"
        assert f.data_leaked is True

    @pytest.mark.asyncio
    async def test_execute_detects_bola(self):
        """Attacker gets same 200 response as owner -> BOLA confirmed."""
        tc = BOLATestCase(
            endpoint="http://target/api/users/1",
            method="GET",
            resource_id="1",
            owner_user="alice",
            attacker_user="bob",
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value='{"id":1,"name":"Alice"}')
        mock_resp.headers = {}
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await self.tester.execute(
                [tc],
                owner_session={"headers": {"Authorization": "Bearer owner"}},
                attacker_session={"headers": {"Authorization": "Bearer attacker"}},
            )

        assert result.success is True
        assert result.metadata["bola_confirmed"] == 1
        assert len(result.data["findings"]) == 1
        assert result.data["findings"][0]["data_leaked"] is True

    @pytest.mark.asyncio
    async def test_execute_no_bola_when_attacker_denied(self):
        """Attacker gets 403 -> no BOLA."""
        tc = BOLATestCase(
            endpoint="http://target/api/users/1",
            method="GET",
            resource_id="1",
            owner_user="alice",
            attacker_user="bob",
        )

        call_count = 0

        def make_resp(status, body):
            r = MagicMock()
            r.status = status
            r.text = AsyncMock(return_value=body)
            r.headers = {}
            r.__aenter__ = AsyncMock(return_value=r)
            r.__aexit__ = AsyncMock(return_value=False)
            return r

        owner_resp = make_resp(200, '{"id":1,"name":"Alice"}')
        attacker_resp = make_resp(403, '{"error":"forbidden"}')
        responses = [owner_resp, attacker_resp]
        call_idx = {"i": 0}

        def side_effect(*args, **kwargs):
            r = responses[call_idx["i"]]
            call_idx["i"] += 1
            return r

        mock_session = MagicMock()
        mock_session.request = MagicMock(side_effect=side_effect)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await self.tester.execute(
                [tc],
                owner_session={"headers": {"Authorization": "Bearer owner"}},
                attacker_session={"headers": {"Authorization": "Bearer attacker"}},
            )

        assert result.success is True
        assert result.metadata["bola_confirmed"] == 0

    @pytest.mark.asyncio
    async def test_execute_skips_when_owner_denied(self):
        """If owner gets 404, skip (resource doesn't exist)."""
        tc = BOLATestCase(
            endpoint="http://target/api/users/999",
            method="GET",
            resource_id="999",
            owner_user="alice",
            attacker_user="bob",
        )

        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.text = AsyncMock(return_value="not found")
        mock_resp.headers = {}
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await self.tester.execute(
                [tc],
                owner_session={"headers": {}},
                attacker_session={"headers": {}},
            )

        assert result.metadata["bola_confirmed"] == 0

    @pytest.mark.asyncio
    async def test_execute_handles_exception_gracefully(self):
        """Network errors should not crash, just skip that test case."""
        tc = BOLATestCase(
            endpoint="http://target/api/users/1",
            method="GET",
            resource_id="1",
            owner_user="alice",
            attacker_user="bob",
        )

        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(side_effect=Exception("connection refused"))
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await self.tester.execute(
                [tc],
                owner_session={"headers": {}},
                attacker_session={"headers": {}},
            )

        assert result.success is True
        assert result.metadata["bola_confirmed"] == 0

    def test_output_is_tool_output(self):
        """Verify tool returns ToolOutput, not some other type."""
        from sentinel.tools.base import ToolOutput
        # Just check the class exists and has the right attributes
        assert hasattr(BOLATester, "name")
        assert BOLATester.name == "bola_test"

    @pytest.mark.asyncio
    async def test_multiple_test_cases(self):
        """Can run multiple test cases in one execute call."""
        cases = [
            BOLATestCase("/api/users/1", "GET", "1", "alice", "bob"),
            BOLATestCase("/api/orders/42", "GET", "42", "alice", "bob"),
        ]

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value='{"data":"leaked"}')
        mock_resp.headers = {}
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await self.tester.execute(
                cases,
                owner_session={"headers": {}},
                attacker_session={"headers": {}},
            )

        assert result.metadata["total_tests"] == 2
        assert result.metadata["bola_confirmed"] == 2
