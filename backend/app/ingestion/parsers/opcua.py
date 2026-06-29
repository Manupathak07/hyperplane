"""OPC UA parser — modern industrial protocol.

OPC UA publishes node value changes. Typical log lines from an OPC UA
gateway (e.g. Prosys, Kepware):
    opcua://plant/furnace-3/temp  value=842.3  status=Good  ts=2026-06-28T08:00:00Z
    node=ns=2;s=Channel1.Device4.ActualSpeed  value=1234.5  quality=Good

Recognised event types (locked Week 4):
- opcua.node_reading        (numeric value, in-range)
- opcua.node_out_of_range   (value outside expected min/max)
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from app.ingestion.normalizer import NormalisedEvent, parse_failed_event

PARSER_NAME = "opcua"

_RE_NODE = re.compile(
    r"(?:opcua://)?(?P<node>[\w\-\./=]+).*?value=(?P<val>-?[\d\.]+)(?:.*?quality=(?P<qual>\w+))?",
    re.IGNORECASE,
)

# Toy "expected range" for demo purposes. In production this would be a
# per-node config. We use very loose defaults so most readings are in-range
# and only a small fraction are flagged.
_DEFAULT_RANGE = (0.0, 1000.0)


def parse(line: str, *, host: str | None = None) -> NormalisedEvent:
    observed = datetime.now(timezone.utc)
    m = _RE_NODE.search(line)
    if not m:
        return parse_failed_event(line, PARSER_NAME, "no OPC UA node pattern matched")

    try:
        value = float(m["val"])
    except ValueError:
        return parse_failed_event(line, PARSER_NAME, "non-numeric value")

    node = m["node"]
    asset_id = node.split("/")[1] if "/" in node else None
    lo, hi = _DEFAULT_RANGE
    in_range = lo <= value <= hi

    return NormalisedEvent(
        observed_at=observed,
        domain="ot",
        event_type="opcua.node_out_of_range" if not in_range else "opcua.node_reading",
        severity=6 if not in_range else 1,
        host=host,
        asset_id=asset_id,
        raw=line,
        parser=PARSER_NAME,
        vendor="opc-ua",
        tags=["opcua", "node"],
        labels={"node": node, "quality": m["qual"] or "", "value": str(value)},
    )
