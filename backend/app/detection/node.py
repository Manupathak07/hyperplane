"""Detection LangGraph node.

Week 9 — async node that runs after Enrichment (or in parallel) and produces a
detection score, attack stage, and basic correlation info.
"""
from __future__ import annotations

from app.agents.state import AgentState
from app.detection.agent import detect


async def detection_node(state: AgentState) -> AgentState:
    """Run detection on the enriched incident."""
    incident = state.get("incident") or {}
    threat_intel = state.get("threat_intel") or {}
    enrichment = state.get("enrichment") or {}

    detection_result = detect(incident, threat_intel, enrichment)
    return {"detection": detection_result}
