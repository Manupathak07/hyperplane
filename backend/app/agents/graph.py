"""LangGraph state graph for the HyperPlane investigation pipeline.

Topology (Week 6):

    START
      │
      ▼
    triage_step ──▶ threat_intel_step ──▶ decide_step ──▶ END

Week 5 had just triage → decide. Week 6 inserts the Threat Intel agent in
between, persisting its envelope as both:
  - AgentState["threat_intel"]     (in-memory, for the decide node)
  - Incident.threat_intel           (JSONB column, for the dashboard)
  - one AgentTrace row              (step=2, agent=threat_intel)

Weeks 7-10 will add Enrichment / Detection / Response between TI and decide
and wrap the whole thing in an LLM-backed Supervisor.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from langgraph.graph import END, START, StateGraph

from app.agents.state import AgentState
from app.agents.threat_intel_node import threat_intel_node
from app.agents.tracing import record_trace
from app.agents.triage import decide_node, triage_node

log = logging.getLogger(__name__)


def build_graph() -> Any:
    """Construct (but don't compile) the investigation graph.

    Returning the builder (not the compiled graph) lets callers instrument
    each node before compile — e.g. attach persistence or interrupt hooks.

    Node names are distinct from state keys (LangGraph enforces this — node
    names become graph channels). We use `triage_step`, `threat_intel_step`,
    and `decide_step`.
    """
    g = StateGraph(AgentState)
    g.add_node("triage_step", triage_node)
    g.add_node("threat_intel_step", threat_intel_node)
    g.add_node("decide_step", decide_node)
    g.add_edge(START, "triage_step")
    g.add_edge("triage_step", "threat_intel_step")
    g.add_edge("threat_intel_step", "decide_step")
    g.add_edge("decide_step", END)
    return g


async def run_investigation(
    session,
    incident_row,
    rule_hits: list[dict],
) -> dict:
    """Top-level helper: build initial state, run the graph, persist traces.

    `session` is an AsyncSession; `incident_row` is the ORM Incident instance
    we just read from Postgres (must already be persisted). Returns the final
    AgentState for the caller to surface to the operator.
    """
    # Serialise incident for the state dict. Pydantic-style dict via the
    # existing IncidentRead schema would be ideal but we'd need a session;
    # we have the ORM object right here, so just to_dict it.
    incident_dict = _incident_to_dict(incident_row)

    initial: AgentState = {
        "incident_id": str(incident_row.id),
        "incident": incident_dict,
        "rule_hits": list(rule_hits or []),
        "trace_ids": [],
    }

    # Build + compile the graph fresh each run (cheap; small graph).
    graph = build_graph().compile()

    # Run the graph. LangGraph awaits the async node automatically.
    final_state: AgentState = await graph.ainvoke(initial)

    # Persist the Threat Intel envelope onto the Incident row so the
    # dashboard / API can show it without re-running the pipeline.
    threat_intel_envelope = final_state.get("threat_intel") or {}
    if threat_intel_envelope:
        incident_row.threat_intel = threat_intel_envelope

    # Persist trace rows for the agents that ran (1 per node, plus the
    # terminal Decide which is the Supervisor stub).
    from app.models import AgentName

    incident_uuid = uuid.UUID(str(incident_row.id))

    trace_ids: list[str] = []

    triage_output = final_state.get("triage") or {}
    if triage_output:
        trace_id = await record_trace(
            session,
            incident_id=incident_uuid,
            agent_name=AgentName.TRIAGE,
            step=1,
            input_={"incident": incident_dict, "rule_hits": initial["rule_hits"]},
            output=triage_output,
            reasoning=triage_output.get("reasoning"),
            started_at=0.0,  # graph already ran; duration not recoverable here
        )
        trace_ids.append(str(trace_id))

    if threat_intel_envelope:
        hits = threat_intel_envelope.get("hits") or []
        reasoning = (
            f"Threat intel score {threat_intel_envelope.get('score', 0)}/100; "
            f"sources: {', '.join(h.get('source', '?') for h in hits) or 'none'}"
        )
        trace_id = await record_trace(
            session,
            incident_id=incident_uuid,
            agent_name=AgentName.THREAT_INTEL,
            step=2,
            input_={
                "src": (incident_dict.get("raw_event") or {}).get("src"),
            },
            output=threat_intel_envelope,
            reasoning=reasoning,
            started_at=0.0,
        )
        trace_ids.append(str(trace_id))

    # Decide is trivial but we record it too — Trace Viewer wants every step.
    decide_output = {"final_decision": final_state.get("final_decision")}
    trace_id = await record_trace(
        session,
        incident_id=incident_uuid,
        agent_name=AgentName.SUPERVISOR,  # decide is the supervisor stub
        step=3,
        input_={
            "triage": triage_output,
            "threat_intel": threat_intel_envelope,
        },
        output=decide_output,
        reasoning=f"Routed to: {final_state.get('final_decision')}",
        started_at=0.0,
    )
    trace_ids.append(str(trace_id))

    final_state["trace_ids"] = trace_ids
    return final_state


def _incident_to_dict(inc) -> dict:
    """Lightweight serialiser for the ORM row (no nested trace fetching)."""
    return {
        "id": str(inc.id),
        "event_id": str(inc.event_id) if inc.event_id else None,
        "correlation_id": str(inc.correlation_id) if inc.correlation_id else None,
        "title": inc.title,
        "description": inc.description,
        "source": inc.source,
        "event_type": inc.event_type,
        "domain": inc.domain.value if hasattr(inc.domain, "value") else inc.domain,
        "severity": inc.severity.value if hasattr(inc.severity, "value") else inc.severity,
        "status": inc.status.value if hasattr(inc.status, "value") else inc.status,
        "raw_event": inc.raw_event,
        "rule_hits": list(getattr(inc, "rule_hits", []) or []),
        "threat_intel": getattr(inc, "threat_intel", None) or {},
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
    }