import pytest
from unittest.mock import AsyncMock, MagicMock

from sentinel.rag.knowledge_ingestor import KnowledgeIngestor, ANONYMIZE_PATTERNS


class TestAnonymization:
    def setup_method(self):
        self.ingestor = KnowledgeIngestor(None, None)

    def test_ip_anonymized(self):
        result = self.ingestor._anonymize("Found at 192.168.1.100 on port 8080")
        assert "192.168.1.100" not in result
        assert "[IP]" in result

    def test_email_anonymized(self):
        result = self.ingestor._anonymize("Contact admin@example.com for details")
        assert "admin@example.com" not in result
        assert "[EMAIL]" in result

    def test_bearer_token_anonymized(self):
        result = self.ingestor._anonymize(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc"
        )
        assert "eyJ" not in result

    def test_url_anonymized(self):
        result = self.ingestor._anonymize("Target: https://internal.corp.com/api/users")
        assert "internal.corp.com" not in result
        assert "[URL]" in result

    def test_home_path_anonymized(self):
        result = self.ingestor._anonymize("Found in /home/admin/.ssh/id_rsa")
        assert "/home/admin" not in result
        assert "/home/[USER]" in result

    def test_hash_anonymized(self):
        result = self.ingestor._anonymize(
            "API key: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        )
        assert "a1b2c3d4e5f6" not in result
        assert "[HASH]" in result

    def test_plain_text_unchanged(self):
        text = "SQL injection found in login endpoint"
        result = self.ingestor._anonymize(text)
        assert result == text


class TestFindingToText:
    def setup_method(self):
        self.ingestor = KnowledgeIngestor(None, None)

    def test_finding_to_text(self):
        finding = {
            "category": "sqli",
            "severity": "high",
            "target_url": "http://target.com/api",
            "description": "SQL injection in login",
            "tech_stack": ["django", "postgresql"],
        }
        text = self.ingestor._finding_to_text(finding)
        assert "sqli" in text
        assert "high" in text
        assert "SQL injection" in text

    def test_finding_missing_fields(self):
        text = self.ingestor._finding_to_text({"category": "xss"})
        assert "xss" in text


class TestSummaryToText:
    def setup_method(self):
        self.ingestor = KnowledgeIngestor(None, None)

    def test_summary_to_text(self):
        summary = {
            "target": "corp.example.com",
            "tech_stack": ["django", "nginx"],
            "total_findings": 5,
            "critical": 2,
            "techniques": ["sqli", "idor"],
        }
        text = self.ingestor._summary_to_text(summary)
        assert "corp.example.com" in text
        assert "django" in text
        assert "sqli" in text


class TestIngestFinding:
    @pytest.mark.asyncio
    async def test_ingest_finding_calls_embed_and_store(self):
        mock_embed_mgr = MagicMock()
        mock_embed_mgr.chunk_text = MagicMock(return_value=[
            {"chunk_id": "abc123", "text": "test chunk", "metadata": {"source": "finding"}},
        ])
        mock_embed_mgr.embed_batch = AsyncMock(return_value=[[0.1] * 1536])

        mock_store = MagicMock()
        mock_store.upsert = AsyncMock()

        ingestor = KnowledgeIngestor(mock_embed_mgr, mock_store)
        await ingestor.ingest_finding(
            {"category": "sqli", "description": "SQL injection"},
            engagement_id="eng-1",
        )

        mock_embed_mgr.embed_batch.assert_called_once()
        mock_store.upsert.assert_called_once()

    @pytest.mark.asyncio
    async def test_ingest_engagement_summary(self):
        mock_embed_mgr = MagicMock()
        mock_embed_mgr.chunk_text = MagicMock(return_value=[
            {"chunk_id": "sum123", "text": "summary chunk", "metadata": {}},
        ])
        mock_embed_mgr.embed_batch = AsyncMock(return_value=[[0.1] * 1536])

        mock_store = MagicMock()
        mock_store.upsert = AsyncMock()

        ingestor = KnowledgeIngestor(mock_embed_mgr, mock_store)
        await ingestor.ingest_engagement_summary(
            {"target": "test.com", "total_findings": 3},
            engagement_id="eng-1",
        )

        mock_store.upsert.assert_called_once()
