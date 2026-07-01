"""Enrichment LangGraph node.

Week 8 — async node that runs between Threat Intel and Decide steps.
Extracts and enriches contextual information from incidents:
- GeoIP lookups
- Asset/user enrichment  
- MITRE ATT&CK mapping
- Threat score calculation

Populates enrichment data that gets stored in the NormalizedIncident table.
"""
from __future__ import annotations

from app.agents.state import AgentState
from app.enrichment.agent import enrich


async def enrichment_node(state: AgentState) -> AgentState:
    """Enrich incident with contextual information."""
    incident = state.get("incident") or {}
    threat_intel = state.get("threat_intel") or {}

    enrichment_data = await enrich(incident, threat_intel)
    return {"enrichment": enrichment_data}
