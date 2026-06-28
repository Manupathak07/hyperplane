"""Seed one example incident so the dashboard has data when Week 3 lands.

Run from inside the backend container:
    docker exec hyperplane-backend python scripts/seed.py
"""
import asyncio
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from app.db import AsyncSessionLocal
from app.models import Domain, Incident, IncidentStatus, Severity


async def seed() -> None:
    async with AsyncSessionLocal() as session:
        existing = await session.execute(select(Incident).limit(1))
        if existing.scalar_one_or_none() is not None:
            print("[seed] incidents table not empty — skipping")
            return

        now = datetime.now(timezone.utc)
        incident = Incident(
            id=uuid.uuid4(),
            title="Brute-force SSH login attempts from external IP",
            description=(
                "Auth log shows 47 failed sshd password attempts from "
                "203.0.113.42 targeting the 'root' account within 60 seconds."
            ),
            source="syslog",
            domain=Domain.IT,
            severity=Severity.HIGH,
            status=IncidentStatus.TRIAGING,
            raw_event={
                "log_source": "/var/log/auth.log",
                "timestamp": now.isoformat(),
                "event_type": "ssh_failed_password",
                "attempts": 47,
                "source_ip": "203.0.113.42",
                "target_user": "root",
                "window_seconds": 60,
            },
            created_at=now,
            updated_at=now,
        )
        session.add(incident)
        await session.commit()
        await session.refresh(incident)

        print(f"[seed] created incident {incident.id}")
        print(f"[seed] title:    {incident.title}")
        print(f"[seed] severity: {incident.severity.value}")
        print(f"[seed] domain:   {incident.domain.value}")


if __name__ == "__main__":
    asyncio.run(seed())
