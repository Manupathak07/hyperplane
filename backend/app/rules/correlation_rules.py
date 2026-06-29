"""Correlation / chain rules.

Per-incident rules here are cheap (no DB lookup). The Week 9 Detection agent
will do the heavier cross-incident chain analysis; for now we surface the
basics:
  - If the incident shares a correlation_id, flag the chain presence.
  - If the incident is a known scenario event_type (e.g. ssh_bruteforce), mark
    it as part of an attack chain.

These rules are informational (severity: info/low, no severity floor) — they
enrich the operator's view, not change the urgency.
"""
from __future__ import annotations

from .engine import EvalContext

# Event types that are by definition part of an attack chain.
_CHAIN_EVENT_TYPES = {
    "ssh.auth_fail",
    "auth.login_failed",
    "modbus.register_write",
    "opcua.node_out_of_range",
}


def evaluate(ctx: EvalContext) -> list[dict]:
    hits: list[dict] = []

    # Correlation-id presence
    if ctx.correlation_id:
        hits.append({
            "rule_id": "chain_correlated",
            "rule_name": "Part of correlated chain",
            "severity": "info",
            "confidence": 1.0,
            "matched": {"correlation_id": ctx.correlation_id},
            "description": (
                f"Incident carries correlation_id {ctx.correlation_id[:8]}... — "
                f"linked to one or more other events."
            ),
        })

    # Known-chain event type
    if ctx.event_type in _CHAIN_EVENT_TYPES:
        hits.append({
            "rule_id": "chain_known_pattern",
            "rule_name": "Known chain event type",
            "severity": "info",
            "confidence": 0.7,
            "matched": {"event_type": ctx.event_type},
            "description": (
                f"Event type '{ctx.event_type}' is a known chain indicator "
                f"(brute-force, tamper, etc.)."
            ),
        })

    return hits