"""Severity-floor rules.

Two rules:
  - OT-domain critical asset (plc-*, hvac, scada): minimum severity HIGH
  - High numeric severity (>=8): floor CRITICAL
  - Out-of-range OT write (modbus.register_write to non-standard register): HIGH
"""
from __future__ import annotations

import re

from .engine import EvalContext

# Critical OT assets — any event on one of these is at least HIGH severity.
_CRITICAL_OT_ASSET = re.compile(r"^(plc-\d+|hvac|scada|hmi-\d+)$", re.IGNORECASE)


def evaluate(ctx: EvalContext) -> list[dict]:
    hits: list[dict] = []

    # 1. Numeric severity floor
    if ctx.severity_numeric is not None:
        n = int(ctx.severity_numeric)
        if n >= 9:
            hits.append({
                "rule_id": "severity_numeric_critical",
                "rule_name": "Critical numeric severity",
                "severity": "critical",
                "confidence": 0.95,
                "matched": {"severity_numeric": n, "severity_floor": "critical"},
                "description": f"Parser scored severity {n}/10 — escalating to critical.",
            })
        elif n >= 7:
            hits.append({
                "rule_id": "severity_numeric_high",
                "rule_name": "High numeric severity",
                "severity": "high",
                "confidence": 0.85,
                "matched": {"severity_numeric": n, "severity_floor": "high"},
                "description": f"Parser scored severity {n}/10 — escalating to high.",
            })

    # 2. Critical OT asset — anything on a PLC/HVAC/SCADA warrants HIGH minimum
    if ctx.domain == "OT" and ctx.asset_id and _CRITICAL_OT_ASSET.match(ctx.asset_id):
        hits.append({
            "rule_id": "ot_critical_asset",
            "rule_name": "Critical OT asset involved",
            "severity": "high",
            "confidence": 0.9,
            "matched": {"asset_id": ctx.asset_id, "severity_floor": "high"},
            "description": f"Event on critical OT asset '{ctx.asset_id}' — minimum HIGH.",
        })

    # 3. Modbus write to high register range (likely tamper)
    if ctx.event_type == "modbus.register_write":
        hits.append({
            "rule_id": "modbus_write_tamper",
            "rule_name": "Modbus register write",
            "severity": "high",
            "confidence": 0.75,
            "matched": {"event_type": ctx.event_type, "severity_floor": "high"},
            "description": "Modbus write to register — potential OT tamper, escalating to high.",
        })

    # 4. OPC UA out-of-range
    if ctx.event_type == "opcua.node_out_of_range":
        hits.append({
            "rule_id": "opcua_out_of_range",
            "rule_name": "OPC UA out-of-range write",
            "severity": "high",
            "confidence": 0.9,
            "matched": {"event_type": ctx.event_type, "severity_floor": "high"},
            "description": "OPC UA write to out-of-range node — sensor/PLC misbehaviour.",
        })

    return hits