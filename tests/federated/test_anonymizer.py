"""Tests for Anonymizer."""

from sentinel.federated.anonymizer import Anonymizer


class TestAnonymizeText:
    def setup_method(self):
        self.anon = Anonymizer()

    def test_ip_anonymization(self):
        result = self.anon.anonymize_text("Target is 192.168.1.100 on port 8080")
        assert "192.168.1.100" not in result
        assert "HOST_" in result

    def test_domain_anonymization(self):
        result = self.anon.anonymize_text("Scanning api.example.com for vulns")
        assert "example.com" not in result
        assert "DOMAIN_" in result

    def test_token_redaction(self):
        result = self.anon.anonymize_text(
            "Bearer eyJhbGciOiJIUzI1NiJ9.test.signature"
        )
        assert "eyJ" not in result
        assert "REDACTED_TOKEN" in result

    def test_email_redaction(self):
        result = self.anon.anonymize_text("Contact admin@company.com")
        assert "admin@company.com" not in result
        assert "REDACTED_EMAIL" in result

    def test_uuid_redaction(self):
        result = self.anon.anonymize_text(
            "Session a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        )
        assert "a1b2c3d4" not in result
        assert "REDACTED_UUID" in result

    def test_path_id_normalization(self):
        result = self.anon.anonymize_text("/api/v1/users/12345/orders/67890")
        assert "12345" not in result
        assert "67890" not in result
        assert "{id}" in result

    def test_consistent_ip_mapping(self):
        r1 = self.anon.anonymize_text("Host 10.0.0.1")
        r2 = self.anon.anonymize_text("Same host 10.0.0.1")
        placeholder = r1.split()[-1]
        assert placeholder in r2

    def test_consistent_domain_mapping(self):
        r1 = self.anon.anonymize_text("Site evil.com")
        r2 = self.anon.anonymize_text("Same site evil.com")
        placeholder = r1.split()[-1]
        assert placeholder in r2

    def test_multiple_ips_get_different_placeholders(self):
        result = self.anon.anonymize_text("10.0.0.1 connects to 10.0.0.2")
        assert "HOST_1" in result
        assert "HOST_2" in result


class TestTechniqueClassification:
    def setup_method(self):
        self.anon = Anonymizer()

    def test_sqli_union(self):
        finding = {"category": "sqli", "payload": "' UNION SELECT * FROM users--"}
        record = self.anon.anonymize_finding(finding)
        assert record.technique_family == "sqli_union"

    def test_sqli_blind_time(self):
        finding = {"category": "sqli", "payload": "'; WAITFOR DELAY '0:0:5'; SLEEP(5)--"}
        record = self.anon.anonymize_finding(finding)
        assert record.technique_family == "sqli_blind_time"

    def test_xss_script(self):
        finding = {"category": "xss", "payload": "<script>alert(1)</script>"}
        record = self.anon.anonymize_finding(finding)
        assert record.technique_family == "xss_script"

    def test_xss_event(self):
        finding = {"category": "xss", "payload": '<img onerror="alert(1)" src=x>'}
        record = self.anon.anonymize_finding(finding)
        assert record.technique_family == "xss_event"

    def test_ssrf(self):
        finding = {"category": "ssrf", "payload": "http://169.254.169.254/"}
        record = self.anon.anonymize_finding(finding)
        assert record.technique_family == "ssrf_internal"

    def test_unknown_category(self):
        finding = {"category": "misc", "payload": "test"}
        record = self.anon.anonymize_finding(finding)
        assert record.technique_family == "misc_generic"
