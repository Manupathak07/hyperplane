"""Threat-intel rules (lightweight, in-memory).

This is the cheap pre-LLM layer. Real Threat Intel agent (Week 7) will hit
OTX/AbuseIPDB and produce richer findings; these rules give us something to
say immediately for known-bad test IPs.

For now we hard-code:
  - 198.51.100.0/24 — "attacker" test net (RFC5737 documentation range)
  - 192.0.2.0/24    — second test net
  - 203.0.113.0/24  — third test net
Any src in these ranges is flagged as "known-test-net" — a low-confidence
indicator that the operator can dismiss.

Production: replace with OTX pulse cache + AbuseIPDB check (Week 7).
"""
from __future__ import annotations

import ipaddress

from .engine import EvalContext

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

    return hits