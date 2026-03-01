"""Tests for TripwireManager."""

from sentinel.blue_team.tripwire import TripwireManager


class TestTripwireManager:
    def setup_method(self):
        self.manager = TripwireManager()

    def test_plant_aws_creds(self):
        wire = self.manager.plant_aws_creds()
        assert wire.wire_type == "aws_creds"
        assert "AKIA" in wire.content
        assert wire.callback_url.endswith(self.manager.canary_domain)

    def test_plant_db_dump(self):
        wire = self.manager.plant_db_dump()
        assert "CREATE TABLE" in wire.content
        assert wire.callback_url in wire.content

    def test_plant_admin_endpoint(self):
        wire = self.manager.plant_admin_endpoint()
        assert wire.wire_type == "admin_endpoint"
        assert "maintenance" in wire.content

    def test_plant_config_file(self):
        wire = self.manager.plant_config_file()
        assert "DATABASE_URL" in wire.content
        assert "SECRET_KEY" in wire.content

    def test_trigger(self):
        wire = self.manager.plant_admin_endpoint()
        alert = self.manager.trigger(wire.wire_id, "192.168.1.100", "curl/7.68")
        assert alert is not None
        assert alert.source_ip == "192.168.1.100"
        assert wire.triggered is True

    def test_trigger_unknown_returns_none(self):
        alert = self.manager.trigger("nonexistent", "10.0.0.1")
        assert alert is None

    def test_active_vs_triggered(self):
        w1 = self.manager.plant_aws_creds()
        w2 = self.manager.plant_db_dump()
        self.manager.trigger(w1.wire_id, "10.0.0.1")
        assert len(self.manager.get_active_wires()) == 1
        assert len(self.manager.get_triggered_wires()) == 1
