"""Threat Intel LangGraph node.

Week 6 — async node (the only async one in the graph so far; the rest of the
pipeline is sync). Reads `incident.raw_event.src`, calls `lookup()` from
`app.threatintel.agent`, and writes the envelope back into AgentState.

If `src` is missing or empty, returns a zero-score envelope — the rule
engine then produces no `ti_high_score` hit, the existing IP-range rules
still apply if `src` was set.
"""
from __future__ import annotations

from app.agents.state import AgentState
from app.threatintel.agent import lookup


async def threat_intel_node(state: AgentState) -> AgentState:
    """Look up the incident's src IP and return the TI envelope."""
    incident = state.get("incident") or {}
    raw = incident.get("raw_event") or {}
    src = raw.get("src")

    envelope = await lookup(src)
    return {"threat_intel": envelope}