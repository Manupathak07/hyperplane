"""LangGraph state graph for the HyperPlane investigation pipeline.

Topology (Week 5 Chunk 3):

    START
      │
      ▼
    triage_node ──▶ decide_node ──▶ END

Weeks 6-10 will add nodes between triage and decide (Threat Intel,
Enrichment, Detection, Response) and wrap the whole thing in a Supervisor
that decides which agents to invoke. For now we keep it simple so the
scaffold + trace schema are demonstrably correct.
"""
from __future__ import annotations

import uuid
from typing import Any

from langgraph.graph import END, START, StateGraph

from app.agents.state import AgentState
from app.agents.tracing import record_trace
from app.agents.triage import decide_node, triage_node


def build_graph() -> Any:
    """Construct (but don't compile) the investigation graph.

    Returning the builder (not the compiled graph) lets callers instrument
    each node before compile — e.g. attach persistence or interrupt hooks.

    Node names are distinct from state keys (LangGraph enforces this — node
    names become graph channels). We use `triage_step` and `decide_step`.
    """
    g = StateGraph(AgentState)
    g.add_node("triage_step", triage_node)
    g.add_node("decide_step", decide_node)
    g.add_edge(START, "triage_step")
    g.add_edge("triage_step", "decide_step")
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

    # Run the graph — node functions are sync because we do no I/O inside
    # them yet. LangGraph handles the orchestration.
    final_state: AgentState = graph.invoke(initial)

    # Persist trace rows for the agents that ran. Week 5 = just triage.
    # We record the trace AFTER the graph completes so the row reflects the
    # actual output the agent produced.
    from app.models import AgentName

    incident_uuid = uuid.UUID(str(incident_row.id))

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
        final_state["trace_ids"] = [str(trace_id)]

    # Decide is trivial but we record it too — Trace Viewer wants every step.
    decide_output = {"final_decision": final_state.get("final_decision")}
    trace_id = await record_trace(
        session,
        incident_id=incident_uuid,
        agent_name=AgentName.SUPERVISOR,  # decide is the supervisor stub
        step=2,
        input_={"triage": triage_output},
        output=decide_output,
        reasoning=f"Routed to: {final_state.get('final_decision')}",
        started_at=0.0,
    )
    final_state.setdefault("trace_ids", []).append(str(trace_id))

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
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
    }