"""Tests for RAGPoisoningTester payloads."""

from sentinel.tools.ai_security.rag_poisoning import RAG_POISON_PAYLOADS


class TestRAGPoisonPayloads:
    def test_minimum_payload_count(self):
        assert len(RAG_POISON_PAYLOADS) >= 4

    def test_all_payloads_have_required_fields(self):
        for p in RAG_POISON_PAYLOADS:
            assert p.name, "Payload missing name"
            assert p.document_content, f"Payload {p.name} missing document_content"
            assert p.trigger_query, f"Payload {p.name} missing trigger_query"
            assert p.severity in ("critical", "high", "medium", "low")

    def test_poison_content_contains_hidden_instructions(self):
        hidden_markers = [
            "<!--", "note to ai", "system note", "automated instruction",
            "important update", "you are a", "you must",
        ]
        for p in RAG_POISON_PAYLOADS:
            content_lower = p.document_content.lower()
            has_hidden = any(marker in content_lower for marker in hidden_markers)
            assert has_hidden, (
                f"Payload '{p.name}' should contain hidden instruction markers"
            )

    def test_includes_html_comment_technique(self):
        assert any(
            "<!--" in p.document_content for p in RAG_POISON_PAYLOADS
        ), "Should include at least one HTML comment injection payload"

    def test_includes_bracketed_note_technique(self):
        assert any(
            "[" in p.document_content and "Note" in p.document_content
            for p in RAG_POISON_PAYLOADS
        ), "Should include at least one bracketed note injection payload"

    def test_includes_inline_directive_technique(self):
        assert any(
            "INSTRUCTION" in p.document_content or "UPDATE" in p.document_content
            for p in RAG_POISON_PAYLOADS
        ), "Should include at least one inline directive payload"

    def test_payloads_have_distinct_names(self):
        names = [p.name for p in RAG_POISON_PAYLOADS]
        assert len(names) == len(set(names)), "All payload names must be unique"
