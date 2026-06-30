"""Smoke test for the Week 7 severity write-back.

The bug: ingestion-time rules ran with `threat_intel_score=0` (TI hadn't
fired yet). After `/investigate`, TI populates `threat_intel.score` and
`ti_high_score` should bump the persisted severity to `critical`. Without
the write-back, the row's `severity` stays at the ingestion-time value
even though the agent graph saw a high score.

Assertions (10):

  1. Post an event from an RFC5737 src IP (heuristic TI score = 90)
     with low ingestion severity (2) so we can prove TI bumped it.
  2. Ingestion-time severity is "low" (TI hasn't run yet).
  3. POST /investigate/{id} returns 200.
  4. TI envelope was persisted (threat_intel.score == 90).
  5. **The write-back check**: persisted severity is now "critical".
  6. Persisted rule_hits contains ti_high_score.
  7. Same flow for a private src (TI score = 0): severity stays "low",
     no ti_high_score in rule_hits.
  8. Unknown public src (TI score = 30): severity stays "low", no
     ti_high_score in rule_hits.
  9. Re-investigate on the same incident doesn't duplicate rule_hits.
 10. /investigate on an incident with no src IP still returns 200
     (graceful degradation).

Usage (from host):
    docker exec hyperplane-backend python -m scripts.smoke_writeback
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
    h = {"Content-Type": "application/json"}
    if API_KEY:
        h["X-API-Key"] = API_KEY
    return h


def _sample_event(src_ip: str | None, severity: int = 2) -> tuple[dict, uuid.UUID]:
    """Build a NormalisedEvent payload with low ingestion severity.

    The lower the ingestion severity, the cleaner the test — we want to
    prove that *only* the TI write-back caused the bump.
    """
    eid = uuid.uuid4()
    ev = {
        "event_id": str(eid),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "domain": "it",
        "event_type": "auth.login_failed",
        "severity": severity,
        "confidence": 0.5,
        "src": src_ip,
        "user": "smoke",
        "host": "smoke-host",
        "raw": f"smoke writeback from {src_ip or 'none'}",
        "parser": "syslog",
        "vendor": "linux",
        "tags": ["smoke-writeback"],
        "labels": {},
    }
    return ev, eid


async def _post_event(client: httpx.AsyncClient, ev: dict) -> str:
    r = await client.post(f"{API}/events/", json=ev, headers=_headers())
    assert r.status_code == 201, f"POST /events failed: {r.status_code} {r.text}"
    results = r.json().get("results", [])
    assert len(results) == 1 and results[0]["status"] == "created", f"unexpected response: {r.json()}"
    return results[0]["id"]


async def _get_incident(client: httpx.AsyncClient, incident_id: str) -> dict:
    r = await client.get(f"{API}/incidents/{incident_id}", headers=_headers())
    assert r.status_code == 200, f"GET failed: {r.status_code} {r.text}"
    return r.json()


async def main() -> int:
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        if ok:
            print(f"  PASS  {name}")
        else:
            print(f"  FAIL  {name} — {detail}")
            failures.append(name)

    async with httpx.AsyncClient(timeout=10) as client:
        # ── Case 1: RFC5737 src → TI=90 → should bump to critical ─────────
        # Use 198.51.100.99 (TEST-NET-2) — the heuristic matches this /24.
        # severity=3 → "low" (per severity_to_enum: >=3 is low).
        print("=== Case 1: RFC5737 src (TI=90) ===")
        ev, _ = _sample_event("198.51.100.99", severity=3)
        inc_id = await _post_event(client, ev)
        before = await _get_incident(client, inc_id)
        check(
            "ingestion-time severity is low",
            before["severity"] == "low",
            f"got {before['severity']!r}",
        )

        r = await client.post(f"{API}/incidents/{inc_id}/investigate", headers=_headers())
        check(
            "/investigate returns 200",
            r.status_code == 200,
            f"got {r.status_code} {r.text[:200]}",
        )

        after = await _get_incident(client, inc_id)
        check(
            "threat_intel.score populated to 90",
            (after.get("threat_intel") or {}).get("score") == 90,
            f"got {(after.get('threat_intel') or {}).get('score')!r}",
        )
        check(
            "severity write-back bumped to critical",
            after["severity"] == "critical",
            f"got {after['severity']!r}",
        )
        rule_ids = {h.get("rule_id") for h in after.get("rule_hits", [])}
        check(
            "persisted rule_hits contains ti_high_score",
            "ti_high_score" in rule_ids,
            f"rule_ids={rule_ids}",
        )

        # ── Case 2: private src → TI=0 → no bump ──────────────────────────
        print("=== Case 2: private src (TI=0) ===")
        ev2, _ = _sample_event("10.0.0.1", severity=3)
        inc_id2 = await _post_event(client, ev2)
        r = await client.post(f"{API}/incidents/{inc_id2}/investigate", headers=_headers())
        check("/investigate on private src returns 200", r.status_code == 200,
              f"got {r.status_code} {r.text[:200]}")
        after2 = await _get_incident(client, inc_id2)
        rule_ids2 = {h.get("rule_id") for h in after2.get("rule_hits", [])}
        check(
            "private src: severity stays low",
            after2["severity"] == "low",
            f"got {after2['severity']!r}",
        )
        check(
            "private src: ti_high_score NOT in rule_hits",
            "ti_high_score" not in rule_ids2,
            f"rule_ids={rule_ids2}",
        )

        # ── Case 3: unknown public src → TI=30 → no bump ──────────────────
        print("=== Case 3: unknown public src (TI=30) ===")
        ev3, _ = _sample_event("8.8.8.8", severity=3)
        inc_id3 = await _post_event(client, ev3)
        r = await client.post(f"{API}/incidents/{inc_id3}/investigate", headers=_headers())
        check("/investigate on public src returns 200", r.status_code == 200,
              f"got {r.status_code}")
        after3 = await _get_incident(client, inc_id3)
        ti_score3 = (after3.get("threat_intel") or {}).get("score")
        check("unknown public TI score = 30", ti_score3 == 30, f"got {ti_score3!r}")
        rule_ids3 = {h.get("rule_id") for h in after3.get("rule_hits", [])}
        check(
            "TI=30: ti_high_score NOT in rule_hits",
            "ti_high_score" not in rule_ids3,
            f"rule_ids={rule_ids3}",
        )

        # ── Case 4: idempotent re-investigate ──────────────────────────────
        print("=== Case 4: re-investigate de-dup ===")
        hits_before = len(after.get("rule_hits", []))
        r = await client.post(f"{API}/incidents/{inc_id}/investigate", headers=_headers())
        check("second /investigate returns 200", r.status_code == 200,
              f"got {r.status_code}")
        after4 = await _get_incident(client, inc_id)
        hits_after = len(after4.get("rule_hits", []))
        check(
            "rule_hits length unchanged after re-investigate",
            hits_after == hits_before,
            f"before={hits_before} after={hits_after}",
        )

        # ── Case 5: graceful degradation for None src ──────────────────────
        print("=== Case 5: no src IP ===")
        ev5, _ = _sample_event(None, severity=3)
        inc_id5 = await _post_event(client, ev5)
        r = await client.post(f"{API}/incidents/{inc_id5}/investigate", headers=_headers())
        check("/investigate on None src returns 200", r.status_code == 200,
              f"got {r.status_code} {r.text[:200]}")
        after5 = await _get_incident(client, inc_id5)
        check(
            "None src: severity stays low",
            after5["severity"] == "low",
            f"got {after5['severity']!r}",
        )

    if failures:
        print(f"\n=== {len(failures)} FAILED ===")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\n=== ALL PASSED ===")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))