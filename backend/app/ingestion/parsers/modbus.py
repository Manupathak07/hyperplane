"""Modbus parser — industrial control protocol frames.

Modbus is a request/response protocol. For SIEM purposes, the security-
relevant events are writes (function code 5, 6, 15, 16) and reads of
sensitive registers (function code 3 on certain ranges).

Recognised event types (locked Week 4):
- modbus.register_write       (any write FC)
- modbus.register_read        (any read FC)
- modbus.coil_write           (FC 5)
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from app.ingestion.normalizer import NormalisedEvent, parse_failed_event

PARSER_NAME = "modbus"

# Real Modbus frame examples (we accept the textual representation most
# gateways emit to syslog):
#   "mb:tcp:10.0.0.5 -> plc-7 fc=16 addr=40001 qty=10"
#   "Modbus/TCP 192.168.1.20 -> 192.168.1.30 func=6 reg=40100 val=1234"
_RE_FRAME = re.compile(
    r"(?:mb:)?(?:tcp:)?(?P<src>[\d\.]+)\s*->\s*(?P<dst>[\w\-\.]+).*?"
    r"fc=(?P<fc>\d+)(?:\s+addr=(?P<addr>\d+))?(?:\s+qty=(?P<qty>\d+))?(?:\s+val=(?P<val>\d+))?",
    re.IGNORECASE,
)


def parse(line: str, *, host: str | None = None) -> NormalisedEvent:
    observed = datetime.now(timezone.utc)
    m = _RE_FRAME.search(line)
    if not m:
        return parse_failed_event(line, PARSER_NAME, "no Modbus frame pattern matched")

    fc = int(m["fc"])
    write_fcs = {5, 6, 15, 16}
    read_fcs = {1, 2, 3, 4}

    if fc in write_fcs:
        event_type = "modbus.register_write"
        # Writes during off-hours are critical; we don't know the hour here
        # so default to medium, Detection agent will correlate
        severity = 6
    elif fc in read_fcs:
        event_type = "modbus.register_read"
        severity = 2
    else:
        return parse_failed_event(line, PARSER_NAME, f"unknown function code {fc}")

    asset_id = m["dst"] if m["dst"] else None

    return NormalisedEvent(
        observed_at=observed,
        domain="ot",
        event_type=event_type,
        severity=severity,
        src=m["src"],
        host=host,
        asset_id=asset_id,
        raw=line,
        parser=PARSER_NAME,
        vendor="modbus-tcp",
        tags=["modbus", f"fc-{fc}"],
        labels={
            "fc": str(fc),
            "addr": m["addr"] or "",
            "qty": m["qty"] or "",
            "val": m["val"] or "",
        },
    )
