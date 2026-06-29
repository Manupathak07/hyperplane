"""Parser implementations — one per source type.

Each parser exposes a single function:
    parse(raw: str | bytes, **context) -> NormalisedEvent

Parsers are PURE format → NormalisedEvent mappings. No correlation, no
severity enrichment beyond the parser's own heuristic for this source.
"""
from app.ingestion.parsers import evtx, modbus, mqtt, opcua, syslog

__all__ = ["syslog", "evtx", "modbus", "mqtt", "opcua"]
