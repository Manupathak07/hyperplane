"""Smoke test for the Threat Intel agent (Week 6).

Runs inside the backend container, no API keys needed (uses the deterministic
heuristic fallback). Six assertions:

  1. Heuristic scores RFC5737 src → 90
  2. Heuristic scores private src → 0
  3. Heuristic scores unknown public src → 30
  4. ti_high_score rule fires on a context with threat_intel_score=80
  5. recompute_severity bumps to critical when ti_high_score is present
  6. End-to-end: POST /events + POST /investigate → response has
     threat_intel.score and 3-element trace_ids

Usage (from host):
    docker exec hyperplane-backend python -m scripts.smoke_threatintel
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone

import httpx

from app.rules import (
    EvalContext,
    evaluate,
    recompute_severity,
)
from app.threatintel import cache, lookup


API = os.environ.get("HYPERPLANE_API", "http://localhost:8000")
API_KEY = os.environ.get("EVENTS_API_KEY", "")


def _headers() -> dict:
    if API_KEY:
        return {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    return {"Content-Type": "application/json"}


def _assert(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}  {detail}")
        raise AssertionError(label)


# ---------------------------------------------------------------------------
# 1-5: Pure logic assertions (no network, no DB)
# ---------------------------------------------------------------------------
async def test_heuristic_scores() -> None:
    print("--- heuristic scores ---")
    await cache.clear()  # fresh start
    # RFC5737
    env = await lookup("198.51.100.42")
    _assert("RFC5737 src → score 90", env["score"] == 90, f"got {env['score']}")
    # Private
    env = await lookup("10.0.0.5")
    _assert("private src → score 0", env["score"] == 0, f"got {env['score']}")
    # Public unknown
    env = await lookup("8.8.8.8")
    _assert("public unknown src → score 30", env["score"] == 30, f"got {env['score']}")
    # None
    env = await lookup(None)
    _assert("None src → score 0", env["score"] == 0, f"got {env['score']}")


def test_ti_high_score_rule_fires() -> None:
    print("--- ti_high_score rule ---")
    ctx = EvalContext(
        incident_id="x", title="x", description=None,
        event_type="auth.login_failed", domain="IT",
        severity="low", severity_numeric=4,
        source="syslog", src="198.51.100.42", asset_id=None,
        user=None, host=None, raw="x", tags=[], correlation_id=None,
        threat_intel_score=80,
    )
    hits = evaluate(ctx)
    hit_ids = {h["rule_id"] for h in hits}
    _assert("ti_high_score fires on score=80", "ti_high_score" in hit_ids)
    floor_hit = next(h for h in hits if h["rule_id"] == "ti_high_score")
    _assert(
        "ti_high_score carries severity_floor=critical",
        floor_hit.get("matched", {}).get("severity_floor") == "critical",
        f"got {floor_hit.get('matched')}",
    )


def test_high_score_bumps_severity() -> None:
    print("--- severity bump ---")
    ctx = EvalContext(
        incident_id="x", title="x", description=None,
        event_type="auth.login_failed", domain="IT",
        severity="low", severity_numeric=4,
        source="syslog", src="198.51.100.42", asset_id=None,
        user=None, host=None, raw="x", tags=[], correlation_id=None,
        threat_intel_score=85,
    )
    hits = evaluate(ctx)
    final = recompute_severity("low", hits)
    _assert("low → critical when ti_high_score hits", final == "critical", f"got {final}")


# ---------------------------------------------------------------------------
# 6: End-to-end through the API
# ---------------------------------------------------------------------------
def _sample_event(src_ip: str, eid: uuid.UUID) -> dict:
    return {
        "event_id": str(eid),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "domain": "it",
        "event_type": "auth.login_failed",
        "severity": 7,
        "confidence": 0.95,
        "src": src_ip,
        "user": "root",
        "host": "web-01",
        "raw": f"smoke: ti from {src_ip}",
        "parser": "syslog",
        "vendor": "linux",
        "tags": ["smoke-ti"],
        "labels": {"method": "password"},
    }


async def test_investigate_e2e() -> None:
    print("--- e2e investigate ---")
    async with httpx.AsyncClient(timeout=10) as client:
        # Use an RFC5737 src so the deterministic heuristic gives a high score.
        eid = uuid.uuid4()
        ev = _sample_event("198.51.100.99", eid)
        r = await client.post(f"{API}/events/", json=ev, headers=_headers())
        r.raise_for_status()
        results = r.json().get("results", [])
        _assert("POST /events accepted", len(results) == 1 and results[0]["status"] == "created")
        incident_id = results[0]["id"]

        # Run investigate.
        r2 = await client.post(f"{API}/incidents/{incident_id}/investigate", headers=_headers())
        r2.raise_for_status()
        body = r2.json()
        ti = body.get("threat_intel") or {}
        _assert(
            "response includes threat_intel.score",
            isinstance(ti.get("score"), int),
            f"got {ti}",
        )
        _assert(
            "trace_ids has 3 entries (triage + threat_intel + decide)",
            len(body.get("trace_ids", [])) == 3,
            f"got {len(body.get('trace_ids', []))} trace_ids",
        )
        print(f"  [info] ti.score={ti.get('score')} final_decision={body.get('final_decision')}")


async def main() -> None:
    print("=== Threat Intel smoke test ===")
    await test_heuristic_scores()
    test_ti_high_score_rule_fires()
    test_high_score_bumps_severity()
    await test_investigate_e2e()
    print("=== ALL PASSED ===")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except AssertionError:
        sys.exit(1)