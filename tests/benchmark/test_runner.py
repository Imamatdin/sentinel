import pytest
from sentinel.benchmark.runner import BenchmarkRunner
from sentinel.benchmark.scorer import Finding


class TestBenchmarkRunner:
    @pytest.mark.asyncio
    async def test_run_single_no_scanner(self):
        runner = BenchmarkRunner()
        score = await runner.run_single("dvwa")
        assert score.target_id == "dvwa"
        assert score.recall == 0.0  # No scanner provided

    @pytest.mark.asyncio
    async def test_run_single_with_scanner(self):
        async def mock_scanner(url):
            return [
                Finding("sqli", "/vulnerabilities/sqli/", "id", "high", "union"),
                Finding("command", "/vulnerabilities/exec/", "ip", "critical", "cmd"),
            ]

        runner = BenchmarkRunner()
        score = await runner.run_single("dvwa", scanner_fn=mock_scanner)
        assert score.true_positives >= 2

    @pytest.mark.asyncio
    async def test_run_suite(self):
        runner = BenchmarkRunner()
        run = await runner.run_suite(run_id="test-1", runner_name="test")
        assert run.run_id == "test-1"
        assert len(run.scores) >= 3
        assert "aggregate_f1" in run.aggregate

    def test_aggregate_empty(self):
        runner = BenchmarkRunner()
        agg = runner._aggregate([])
        assert agg == {}
