import pytest
from sentinel.tenancy.postgres_rls import generate_migration_sql, RLS_SETUP_SQL


class TestPostgresRLS:
    def test_migration_generation(self):
        sql = generate_migration_sql(["engagements", "findings"])
        assert "ALTER TABLE engagements" in sql
        assert "ENABLE ROW LEVEL SECURITY" in sql
        assert "tenant_id" in sql
        assert "CREATE POLICY" in sql
        assert "ALTER TABLE findings" in sql

    def test_migration_index(self):
        sql = generate_migration_sql(["scans"])
        assert "CREATE INDEX" in sql
        assert "idx_scans_tenant" in sql

    def test_migration_multiple_tables(self):
        sql = generate_migration_sql(["a", "b", "c"])
        assert "tenant_a" in sql
        assert "tenant_b" in sql
        assert "tenant_c" in sql

    def test_rls_setup_sql_has_all_tables(self):
        for table in ["engagements", "findings", "scans", "reports", "api_keys"]:
            assert table in RLS_SETUP_SQL

    def test_migration_force_rls(self):
        sql = generate_migration_sql(["users"])
        assert "FORCE ROW LEVEL SECURITY" in sql
