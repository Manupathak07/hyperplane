"""Threat-intel rules (lightweight, in-memory).

Two layers:

  1. IP-range heuristics (ti_known_test_net, ti_internal_suspicious) — cheap
     static checks that don't need a network call. Useful even when the
     Threat Intel agent has no signal (e.g. no `src` on the event).

  2. ti_high_score — fires when the Week-6 Threat Intel agent has already
     attached a score ≥ 70 to this incident. Bumps severity to `critical`.
     This is the integration point between the agent pipeline and the rule
     engine: rules raise severity floors based on agent output, the agent
     then re-reads rule_hits on the next investigate pass.
"""
from __future__ import annotations

import ipaddress

from .engine import EvalContext

# Score ≥ this → severity floor = critical. Matches the spec locked in the
# 2026-06-29 checkpoint.
TI_CRITICAL_THRESHOLD = 70

# Known test/documentation ranges (RFC5737). In real life this would be a
# cache of OTX pulses + AbuseIPDB responses.
_KNOWN_BAD_NETS = [
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

# Private RFC1918 ranges — these get a different label (internal noise, not
# inherently malicious, but worth noting when they appear as `src`).
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _in_any(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, nets: list) -> bool:
    return any(ip in net for net in nets)


def evaluate(ctx: EvalContext) -> list[dict]:
    hits: list[dict] = []
    if not ctx.src:
        return hits

    try:
        ip = ipaddress.ip_address(ctx.src)
    except ValueError:
        # Not a valid IP (could be a hostname). Skip the IP-based rules.
        return hits

    if _in_any(ip, _KNOWN_BAD_NETS):
        hits.append({
            "rule_id": "ti_known_test_net",
            "rule_name": "Source in known test/documentation range",
            "severity": "medium",
            "confidence": 0.7,
            "matched": {"src": ctx.src, "range": "RFC5737"},
            "description": (
                f"Source IP {ctx.src} is in a documentation-only range "
                f"(RFC5737) — likely synthetic or test traffic."
            ),
        })
    elif _in_any(ip, _PRIVATE_NETS):
        # Internal src is normal for many events (RFC1918 is most enterprise
        # traffic). Only flag if the parser already rated it ≥6 (i.e. the
        # parser saw something suspicious).
        if ctx.severity_numeric is not None and ctx.severity_numeric >= 6:
            hits.append({
                "rule_id": "ti_internal_suspicious",
                "rule_name": "Suspicious internal source",
                "severity": "medium",
                "confidence": 0.5,
                "matched": {"src": ctx.src, "severity_numeric": ctx.severity_numeric},
                "description": (
                    f"Internal IP {ctx.src} generated a high-confidence event — "
                    f"possible lateral movement."
                ),
            })

    # Agent-driven rule: if the Threat Intel agent already attached a high
    # score, escalate to critical. This is what makes "TI score ≥ 70 → critical"
    # flow through the rest of the pipeline (severity bump + dashboard badge).
    if ctx.threat_intel_score >= TI_CRITICAL_THRESHOLD:
        hits.append({
            "rule_id": "ti_high_score",
            "rule_name": "Threat intel score ≥ 70",
            "severity": "high",
            "confidence": 0.9,
            "matched": {
                "threat_intel_score": ctx.threat_intel_score,
                "threshold": TI_CRITICAL_THRESHOLD,
                "severity_floor": "critical",
            },
            "description": (
                f"Threat intel score {ctx.threat_intel_score}/100 ≥ "
                f"{TI_CRITICAL_THRESHOLD} → severity bumped to critical."
            ),
        })

    return hits