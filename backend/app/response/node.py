"""Response LangGraph node.

Week 10 — async node that runs after Detection (or in parallel) and produces
a report and recommended actions.
"""
from __future__ import annotations

from app.agents.state import AgentState
from app.response.agent import respond


async def response_node(state: AgentState) -> AgentState:
    """Generate response artifacts for the investigated incident."""
    incident = state.get("incident") or {}
    threat_intel = state.get("threat_intel") or {}
    enrichment = state.get("enrichment") or {}
    detection = state.get("detection") or {}

    response_result = respond(incident, threat_intel, enrichment, detection)
    return {"response": response_result}