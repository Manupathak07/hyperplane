"""EVTX parser — Windows Event Log.

We don't depend on python-evtx (binary format) for Week 4 — instead we parse
the XML representation that Windows exports and most SIEM ingesters forward.
This keeps the dependency surface small and avoids a C extension.

Recognised Event IDs (locked Week 4):
- 4625  — Logon failure          → windows.logon_failure
- 4624  — Successful logon       → windows.logon_success
- 7045  — Service installed      → windows.service_install
- 4688  — Process created        → windows.process_exec
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from app.ingestion.normalizer import NormalisedEvent, parse_failed_event

PARSER_NAME = "evtx"

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse(xml_or_text: str, *, host: str | None = None) -> NormalisedEvent:
    """Parse a Windows Event Log XML record."""
    observed = datetime.now(timezone.utc)

    try:
        root = ET.fromstring(xml_or_text)
    except ET.ParseError as e:
        return parse_failed_event(xml_or_text, PARSER_NAME, f"xml parse: {e}")

    eid_el = root.find("e:System/e:EventID", _NS)
    if eid_el is None or not eid_el.text:
        return parse_failed_event(xml_or_text, PARSER_NAME, "missing EventID")

    eid = int(eid_el.text)
    data = _collect_event_data(root)
    src = data.get("IpAddress") or data.get("WorkstationName") or data.get("TargetUserName")
    user = data.get("TargetUserName")

    if eid == 4625:
        return NormalisedEvent(
            observed_at=observed,
            domain="it",
            event_type="windows.logon_failure",
            severity=6,
            src=src,
            user=user,
            host=host or data.get("WorkstationName"),
            raw=xml_or_text,
            parser=PARSER_NAME,
            vendor="microsoft",
            tags=["evtx", "logon"],
            labels={"logon_type": data.get("LogonType", "")},
        )

    if eid == 4624:
        return NormalisedEvent(
            observed_at=observed,
            domain="it",
            event_type="windows.logon_success",
            severity=2,
            src=src,
            user=user,
            host=host or data.get("WorkstationName"),
            raw=xml_or_text,
            parser=PARSER_NAME,
            vendor="microsoft",
            tags=["evtx", "logon"],
        )

    if eid == 7045:
        return NormalisedEvent(
            observed_at=observed,
            domain="it",
            event_type="windows.service_install",
            severity=5,
            host=host,
            raw=xml_or_text,
            parser=PARSER_NAME,
            vendor="microsoft",
            tags=["evtx", "persistence"],
            labels={"service": data.get("ServiceName", "")},
        )

    if eid == 4688:
        return NormalisedEvent(
            observed_at=observed,
            domain="it",
            event_type="windows.process_exec",
            severity=3,
            user=user,
            host=host,
            raw=xml_or_text,
            parser=PARSER_NAME,
            vendor="microsoft",
            tags=["evtx", "process"],
            labels={"process": data.get("NewProcessName", "")},
        )

    return parse_failed_event(xml_or_text, PARSER_NAME, f"unhandled EventID {eid}")


def _collect_event_data(root: ET.Element) -> dict[str, str]:
    out: dict[str, str] = {}
    for d in root.findall("e:EventData/e:Data", _NS):
        name = d.get("Name")
        if name and d.text:
            out[name] = d.text
    return out
