"""MQTT parser — IoT pub/sub messaging.

Most MQTT brokers forward messages as JSON or "topic payload" lines:
    factory/sensor-7/temp  23.4
    factory/plc/cmd  {"action":"write","reg":40100,"val":1}

Recognised event types (locked Week 4):
- mqtt.sensor_reading      (numeric payload on a /sensor topic)
- mqtt.command             (any "cmd" or "command" topic)
- mqtt.command_injection   (cmd topic with suspicious keywords)
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from app.ingestion.normalizer import NormalisedEvent, parse_failed_event

PARSER_NAME = "mqtt"

_RE_TOPIC = re.compile(r"^(?P<topic>\S+)\s+(?P<payload>.+)$")

_SUSPICIOUS = re.compile(r"\b(rm\s+-rf|wget|curl|chmod\s+777|/etc/passwd)\b", re.IGNORECASE)


def parse(line: str, *, host: str | None = None) -> NormalisedEvent:
    observed = datetime.now(timezone.utc)
    m = _RE_TOPIC.match(line.strip())
    if not m:
        return parse_failed_event(line, PARSER_NAME, "no MQTT topic pattern matched")

    topic = m["topic"]
    payload = m["payload"]

    asset_id = _asset_from_topic(topic)
    is_cmd_topic = "/cmd" in topic or "/command" in topic
    is_sensor_topic = "/sensor" in topic or "/temp" in topic or "/reading" in topic

    # Try JSON payload first — most modern IoT publishes JSON
    parsed_json: dict | None = None
    try:
        parsed_json = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        pass

    if is_cmd_topic:
        if _SUSPICIOUS.search(payload):
            return NormalisedEvent(
                observed_at=observed,
                domain="iot",
                event_type="mqtt.command_injection",
                severity=9,
                host=host,
                asset_id=asset_id,
                raw=line,
                parser=PARSER_NAME,
                vendor="mqtt",
                tags=["mqtt", "injection", "critical"],
            )
        return NormalisedEvent(
            observed_at=observed,
            domain="iot",
            event_type="mqtt.command",
            severity=5,
            host=host,
            asset_id=asset_id,
            raw=line,
            parser=PARSER_NAME,
            vendor="mqtt",
            tags=["mqtt", "command"],
        )

    if is_sensor_topic or parsed_json is not None:
        return NormalisedEvent(
            observed_at=observed,
            domain="iot",
            event_type="mqtt.sensor_reading",
            severity=1,
            host=host,
            asset_id=asset_id,
            raw=line,
            parser=PARSER_NAME,
            vendor="mqtt",
            tags=["mqtt", "sensor"],
            labels={"topic": topic},
        )

    return parse_failed_event(line, PARSER_NAME, "unrecognised MQTT topic shape")


def _asset_from_topic(topic: str) -> str | None:
    parts = topic.split("/")
    if len(parts) >= 2:
        return parts[1]
    return None
