import pytest
from sentinel.tenancy.context import set_tenant
from sentinel.tenancy.neo4j_isolation import tenant_label, scoped_create, scoped_match, scoped_query


class TestNeo4jIsolation:
    def test_tenant_label(self):
        set_tenant("acme-corp")
        assert tenant_label() == "Tenant_acme_corp"

    def test_scoped_create(self):
        set_tenant("t1")
        query = scoped_create("Host", {"ip": "10.0.0.1"})
        assert "Tenant_t1" in query
        assert ":Host" in query

    def test_scoped_match(self):
        set_tenant("t1")
        query = scoped_match("Vulnerability", "n.severity = 'critical'")
        assert "Tenant_t1" in query
        assert "severity" in query

    def test_scoped_query_injection(self):
        set_tenant("t2")
        cypher = "MATCH (:Host)-[:HAS]->(:Vulnerability) RETURN count(*)"
        scoped = scoped_query(cypher)
        assert "Tenant_t2:Host" in scoped
        assert "Tenant_t2:Vulnerability" in scoped

    def test_label_sanitizes_special_chars(self):
        set_tenant("my.tenant@123!")
        label = tenant_label()
        assert label == "Tenant_my_tenant_123_"
        # No special chars in the label
        assert all(c.isalnum() or c == "_" for c in label)

    def test_scoped_create_props(self):
        set_tenant("t1")
        query = scoped_create("Service", {"name": "http", "port": "80"})
        assert "$name" in query
        assert "$port" in query

    def test_scoped_match_no_conditions(self):
        set_tenant("t1")
        query = scoped_match("Host")
        assert "WHERE" not in query
        assert "Tenant_t1:Host" in query
