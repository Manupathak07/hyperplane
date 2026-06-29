"""Rule-engine unit-style smoke test.

Runs each rule against a hand-crafted EvalContext and asserts expected hits.
Does NOT hit Postgres or Elasticsearch — pure logic.

Usage (from host):
    docker exec hyperplane-backend python -m scripts.smoke_rules

Exit code 0 on success, 1 on any assertion failure.
"""
from __future__ import annotations

import asyncio
import sys

from app.rules import EvalContext, evaluate, recompute_severity, severity_enum_for


def _assert(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}  {detail}")
        raise AssertionError(label)


def _ids(hits: list[dict]) -> set[str]:
    return {h["rule_id"] for h in hits}


def test_numeric_critical() -> None:
    """numeric >= 9 → critical hit + severity floor."""
    ctx = EvalContext(
        incident_id="x", title="x", description=None, event_type="ssh.auth_fail",
        domain="IT", severity="low", severity_numeric=9,
        source="syslog", src="10.0.0.5", asset_id=None, user=None, host=None,
        raw="x", tags=[], correlation_id=None,
    )
    hits = evaluate(ctx)
    _assert("numeric>=9 fires severity_numeric_critical", "severity_numeric_critical" in _ids(hits))
    final = recompute_severity("low", hits)
    _assert("numeric>=9 bumps severity to critical", final == "critical", f"got {final}")


def test_ot_critical_asset() -> None:
    """modbus register_read on plc-N → ot_critical_asset, severity bumped to high."""
    ctx = EvalContext(
        incident_id="x", title="x", description=None, event_type="modbus.register_read",
        domain="OT", severity="low", severity_numeric=2,
        source="modbus", src="10.0.0.6", asset_id="plc-7", user=None, host=None,
        raw="x", tags=[], correlation_id=None,
    )
    hits = evaluate(ctx)
    _assert("OT + plc-7 fires ot_critical_asset", "ot_critical_asset" in _ids(hits))
    final = recompute_severity("low", hits)
    _assert("OT critical asset bumps to high", final == "high", f"got {final}")


def test_modbus_write_tamper() -> None:
    """modbus.register_write on any asset → modbus_write_tamper + high floor."""
    ctx = EvalContext(
        incident_id="x", title="x", description=None, event_type="modbus.register_write",
        domain="OT", severity="medium", severity_numeric=5,
        source="modbus", src="10.0.0.7", asset_id="plc-1", user=None, host=None,
        raw="x", tags=[], correlation_id=None,
    )
    hits = evaluate(ctx)
    _assert("modbus.register_write fires modbus_write_tamper", "modbus_write_tamper" in _ids(hits))
    _assert("modbus.register_write also fires ot_critical_asset", "ot_critical_asset" in _ids(hits))


def test_known_test_net() -> None:
    """src in 198.51.100.0/24 → ti_known_test_net hit."""
    ctx = EvalContext(
        incident_id="x", title="x", description=None, event_type="ssh.auth_fail",
        domain="IT", severity="medium", severity_numeric=5,
        source="syslog", src="198.51.100.7", asset_id=None, user=None, host=None,
        raw="x", tags=[], correlation_id=None,
    )
    hits = evaluate(ctx)
    _assert("RFC5737 src fires ti_known_test_net", "ti_known_test_net" in _ids(hits))


def test_correlation_marker() -> None:
    """correlation_id present → chain_correlated hit."""
    ctx = EvalContext(
        incident_id="x", title="x", description=None, event_type="modbus.register_write",
        domain="OT", severity="high", severity_numeric=7,
        source="modbus", src="10.0.0.6", asset_id="plc-7", user=None, host=None,
        raw="x", tags=[], correlation_id="abc-123",
    )
    hits = evaluate(ctx)
    _assert("correlation_id fires chain_correlated", "chain_correlated" in _ids(hits))


def test_no_hits_on_benign() -> None:
    """An internal, low-severity, non-OT, non-chain event should have zero hits."""
    ctx = EvalContext(
        incident_id="x", title="x", description=None, event_type="heartbeat",
        domain="IT", severity="low", severity_numeric=1,
        source="internal", src="10.0.0.50", asset_id=None, user=None, host="h1",
        raw="ok", tags=[], correlation_id=None,
    )
    hits = evaluate(ctx)
    _assert("benign heartbeat has no hits", len(hits) == 0, f"got {len(hits)} hits: {[h['rule_id'] for h in hits]}")


def test_severity_floor_never_lowers() -> None:
    """recompute_severity never lowers an existing severity."""
    ctx = EvalContext(
        incident_id="x", title="x", description=None, event_type="heartbeat",
        domain="IT", severity="high", severity_numeric=1,  # critical num, but starting HIGH
        source="x", src=None, asset_id=None, user=None, host=None,
        raw="x", tags=[], correlation_id=None,
    )
    hits = evaluate(ctx)  # would have wanted high (numeric>=7 is FALSE, so no floor hit)
    final = recompute_severity("critical", hits)  # current is critical, nothing bumps above
    _assert("recompute never lowers", final == "critical", f"got {final}")


async def main() -> None:
    print("=== Rule engine smoke test ===")
    test_numeric_critical()
    test_ot_critical_asset()
    test_modbus_write_tamper()
    test_known_test_net()
    test_correlation_marker()
    test_no_hits_on_benign()
    test_severity_floor_never_lowers()
    print("=== ALL PASSED ===")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except AssertionError:
        sys.exit(1)