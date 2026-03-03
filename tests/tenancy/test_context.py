import pytest
from sentinel.tenancy.context import set_tenant, get_tenant, require_tenant, get_tenant_config


class TestTenantContext:
    def test_set_and_get(self):
        set_tenant("tenant_abc")
        assert get_tenant() == "tenant_abc"

    def test_require_raises_when_empty(self):
        set_tenant("")
        with pytest.raises(PermissionError):
            require_tenant()

    def test_require_returns_when_set(self):
        set_tenant("t1")
        assert require_tenant() == "t1"

    def test_config_stored(self):
        set_tenant("t1", {"plan": "enterprise"})
        config = get_tenant_config()
        assert config["plan"] == "enterprise"

    def test_config_defaults_to_empty(self):
        set_tenant("t1")
        config = get_tenant_config()
        assert config == {}

    def test_overwrite_tenant(self):
        set_tenant("t1")
        set_tenant("t2")
        assert get_tenant() == "t2"
