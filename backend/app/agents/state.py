"""State carried through the LangGraph pipeline.

Every agent reads `incident` + `rule_hits` and writes its own output back into
state. The state is serialised into `agent_traces.input` / `output` so the
Trace Viewer can show what each node saw and produced.

Why a TypedDict (not a Pydantic BaseModel):
  - LangGraph state is expected to be a TypedDict — it gives us partial updates
    and proper merge semantics for free.
  - We can still validate boundaries via Pydantic models in each node if we
    need to (we do, in `_record_trace`).
"""
from __future__ import annotations

import uuid
from typing import Any, Optional, TypedDict


class AgentState(TypedDict, total=False):
    # Inputs (set by the entry point).
    incident_id: str
    incident: dict          # serialised Incident row
    rule_hits: list[dict]   # output of the rule engine

    # Populated as agents run.
    triage: dict            # TriageAgent output
    # Week 6 — ThreatIntelAgent output envelope (see app/threatintel/agent.py):
    #   {"ip", "score", "sources", "hits", "checked_at"}.
    threat_intel: dict
    # Week 8 — EnrichmentAgent output envelope:
    #   {"source_ip", "destination_ip", "geo", "asset_id", "user_id",
    #    "mitre_tactics", "mitre_techniques", "threat_score", "indicators"}
    enrichment: dict
    # Week 9 — DetectionAgent output envelope:
    #   {"detection_score", "attack_stage", "reasoning",
    #    "related_incident_ids", "detection_details"}
    detection: dict
    needs_investigation: bool
    summary: str            # one-line human summary for the dashboard

    # Bookkeeping.
    trace_ids: list[str]    # agent_traces row ids created during this run
    final_decision: str     # "investigate" | "dismiss"
