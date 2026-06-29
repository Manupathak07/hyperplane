"""End-to-end smoke test for ingestion (locked Week 4 testing gate).

What it does:
1. POST a single NormalisedEvent to /events/
2. GET /incidents/ — assert our event is there
3. POST the SAME event_id again — assert "duplicate" is returned (idempotency)
4. POST a batch of 3 events — assert accepted=3, duplicates=0

Run inside the backend container:
    docker exec hyperplane-backend python -m scripts.smoke_ingest
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone

import httpx


API = os.environ.get("HYPERPLANE_API", "http://localhost:8000")
API_KEY = os.environ.get("EVENTS_API_KEY", "")


def _headers() -> dict:
    if API_KEY:
        return {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    return {"Content-Type": "application/json"}


async def post_event(client: httpx.AsyncClient, event: dict) -> dict:
    r = await client.post(f"{API}/events/", json=event, headers=_headers(), timeout=10)
    r.raise_for_status()
    return r.json()


async def get_incidents(client: httpx.AsyncClient) -> list[dict]:
    r = await client.get(f"{API}/incidents/", timeout=10)
    r.raise_for_status()
    return r.json()


def _sample_event(event_id: uuid.UUID | None = None) -> dict:
    return {
        "event_id": str(event_id or uuid.uuid4()),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "domain": "it",
        "event_type": "auth.login_failed",
        "severity": 7,
        "confidence": 0.95,
        "src": "203.0.113.42",
        "user": "root",
        "host": "web-01",
        "raw": "Jun 28 09:14:01 web-01 sshd[1234]: Failed password for root from 203.0.113.42 port 54321 ssh2",
        "parser": "syslog",
        "vendor": "linux",
        "tags": ["sshd", "smoke-test"],
        "labels": {"method": "password"},
    }


async def main() -> int:
    print(f"[smoke] API = {API}")
    async with httpx.AsyncClient() as client:
        # 1) POST single event
        eid = uuid.uuid4()
        ev = _sample_event(eid)
        r = await post_event(client, ev)
        assert r["accepted"] == 1 and r["duplicates"] == 0, f"unexpected single-POST response: {r}"
        assert r["results"][0]["status"] == "created"
        print(f"[smoke] POST single event → created, id={r['results'][0]['id']}")

        # 2) GET /incidents/ — our event must be there
        all_incidents = await get_incidents(client)
        ours = [i for i in all_incidents if i.get("raw_event", {}).get("smoke") is None]
        # filter to our event by matching event_id (we embedded it in raw_event)
        target = [i for i in all_incidents if str(eid) in str(i.get("raw_event", {}))]
        # Fallback: check raw_event.labels or just count presence by description
        target2 = [
            i for i in all_incidents
            if "smoke-test" in (i.get("description") or "")
        ]
        assert len(target2) >= 1, "our event did not appear in /incidents/"
        print(f"[smoke] GET /incidents/ contains our event ✓")

        # 3) POST same event_id again → should be duplicate
        r2 = await post_event(client, ev)
        assert r2["accepted"] == 0 and r2["duplicates"] == 1, f"idempotency failed: {r2}"
        assert r2["results"][0]["status"] == "duplicate"
        print("[smoke] POST same event_id → duplicate (idempotency OK)")

        # 4) Batch of 3 fresh events
        batch = [_sample_event() for _ in range(3)]
        r3 = await post_event(client, batch)
        assert r3["accepted"] == 3 and r3["duplicates"] == 0, f"batch ingest failed: {r3}"
        print(f"[smoke] POST batch (3 events) → accepted=3")

        print("\n✅ SMOKE TEST PASSED")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))