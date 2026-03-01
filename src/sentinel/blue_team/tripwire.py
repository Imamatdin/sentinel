"""
Deception Tripwires -- Plant honeytokens that alert when accessed.

Placement strategy: use Neo4j attack graph to find high-attacker-probability,
low-legitimate-use locations (e.g., fake .env files, decoy database dumps,
fake admin endpoints).
"""

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class Tripwire:
    wire_id: str
    wire_type: str       # "aws_creds", "db_dump", "admin_endpoint", "config_file"
    location: str        # Where planted (file path, endpoint, etc.)
    callback_url: str    # DNS/HTTP canary URL that fires on access
    content: str         # The decoy content placed at location
    planted_at: datetime | None = None
    triggered: bool = False
    triggered_at: datetime | None = None
    triggered_by: str = ""  # Source IP / user-agent that tripped it


@dataclass
class TripwireAlert:
    wire_id: str
    wire_type: str
    location: str
    triggered_at: datetime
    source_ip: str
    user_agent: str
    details: str


class TripwireManager:
    """Plant and monitor deception tripwires."""

    def __init__(self, canary_domain: str = "canary.sentinel.local"):
        self.canary_domain = canary_domain
        self.wires: dict[str, Tripwire] = {}
        self.alerts: list[TripwireAlert] = []

    def plant_aws_creds(self, file_path: str = "/.aws/credentials") -> Tripwire:
        """Generate fake AWS credentials that phone home when used."""
        wire_id = f"tw-{uuid.uuid4().hex[:8]}"
        callback = f"{wire_id}.aws.{self.canary_domain}"

        content = (
            "[default]\n"
            f"aws_access_key_id = AKIA{uuid.uuid4().hex[:16].upper()}\n"
            f"aws_secret_access_key = {uuid.uuid4().hex}\n"
            f"# endpoint_url = https://{callback}\n"
            f"region = us-east-1\n"
        )

        wire = Tripwire(
            wire_id=wire_id,
            wire_type="aws_creds",
            location=file_path,
            callback_url=callback,
            content=content,
            planted_at=datetime.now(timezone.utc),
        )
        self.wires[wire_id] = wire
        logger.info("tripwire_planted", wire_type="aws_creds", location=file_path)
        return wire

    def plant_db_dump(self, file_path: str = "/backup/users.sql") -> Tripwire:
        """Generate a fake database dump with DNS-canary email addresses."""
        wire_id = f"tw-{uuid.uuid4().hex[:8]}"
        callback = f"{wire_id}.db.{self.canary_domain}"

        content = (
            "-- MySQL dump 10.13\n"
            "-- Server version: 8.0.32\n"
            "CREATE TABLE `users` (\n"
            "  `id` int NOT NULL AUTO_INCREMENT,\n"
            "  `email` varchar(255) DEFAULT NULL,\n"
            "  `password_hash` varchar(255) DEFAULT NULL,\n"
            "  `role` varchar(50) DEFAULT 'user',\n"
            "  PRIMARY KEY (`id`)\n"
            ") ENGINE=InnoDB;\n\n"
            "INSERT INTO `users` VALUES\n"
            f"(1, 'admin@{callback}', '$2b$12$LJ3m4ks92jf84kDj3mf0s.fake', 'admin'),\n"
            f"(2, 'cto@{callback}', '$2b$12$9fK3jf84Kfj38fj3Dkf0s.fake', 'admin'),\n"
            f"(3, 'dev@{callback}', '$2b$12$Kf83jfD93kfj38fDk3f0s.fake', 'user');\n"
        )

        wire = Tripwire(
            wire_id=wire_id,
            wire_type="db_dump",
            location=file_path,
            callback_url=callback,
            content=content,
            planted_at=datetime.now(timezone.utc),
        )
        self.wires[wire_id] = wire
        logger.info("tripwire_planted", wire_type="db_dump", location=file_path)
        return wire

    def plant_admin_endpoint(self, path: str = "/admin/debug") -> Tripwire:
        """Register a decoy admin endpoint. Any request to it = attacker probing."""
        wire_id = f"tw-{uuid.uuid4().hex[:8]}"
        callback = f"{wire_id}.http.{self.canary_domain}"

        content = json.dumps({
            "status": "maintenance",
            "debug_token": f"dbg-{uuid.uuid4().hex}",
            "note": "Service temporarily unavailable. Contact admin.",
        })

        wire = Tripwire(
            wire_id=wire_id,
            wire_type="admin_endpoint",
            location=path,
            callback_url=callback,
            content=content,
            planted_at=datetime.now(timezone.utc),
        )
        self.wires[wire_id] = wire
        logger.info("tripwire_planted", wire_type="admin_endpoint", location=path)
        return wire

    def plant_config_file(self, file_path: str = "/.env.backup") -> Tripwire:
        """Plant a fake .env file with canary tokens."""
        wire_id = f"tw-{uuid.uuid4().hex[:8]}"
        callback = f"{wire_id}.env.{self.canary_domain}"

        content = (
            f"DATABASE_URL=postgresql://admin:supersecret@{callback}:5432/prod\n"
            f"REDIS_URL=redis://:{uuid.uuid4().hex[:12]}@{callback}:6379\n"
            f"SECRET_KEY={uuid.uuid4().hex}\n"
            f"STRIPE_SECRET_KEY=sk_live_{uuid.uuid4().hex}\n"
            f"SENDGRID_API_KEY=SG.{uuid.uuid4().hex[:22]}\n"
        )

        wire = Tripwire(
            wire_id=wire_id,
            wire_type="config_file",
            location=file_path,
            callback_url=callback,
            content=content,
            planted_at=datetime.now(timezone.utc),
        )
        self.wires[wire_id] = wire
        logger.info("tripwire_planted", wire_type="config_file", location=file_path)
        return wire

    def trigger(
        self, wire_id: str, source_ip: str, user_agent: str = ""
    ) -> TripwireAlert | None:
        """Record a tripwire being triggered."""
        wire = self.wires.get(wire_id)
        if not wire:
            return None

        wire.triggered = True
        wire.triggered_at = datetime.now(timezone.utc)
        wire.triggered_by = source_ip

        alert = TripwireAlert(
            wire_id=wire_id,
            wire_type=wire.wire_type,
            location=wire.location,
            triggered_at=wire.triggered_at,
            source_ip=source_ip,
            user_agent=user_agent,
            details=f"Tripwire '{wire.wire_type}' at {wire.location} accessed by {source_ip}",
        )
        self.alerts.append(alert)
        logger.warning("tripwire_triggered", wire_id=wire_id, source_ip=source_ip)
        return alert

    def get_active_wires(self) -> list[Tripwire]:
        return [w for w in self.wires.values() if not w.triggered]

    def get_triggered_wires(self) -> list[Tripwire]:
        return [w for w in self.wires.values() if w.triggered]
