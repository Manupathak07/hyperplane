"""LangGraph state graph for the HyperPlane investigation pipeline.

Topology (Week 9):

    START
      │
      ▼
    triage_step ──▶ threat_intel_step ──▶ enrichment_step ──▶ detection_step ──▶ decide_step ──▶ END

Week 5 had just triage → decide. Week 6 inserts the Threat Intel agent in
between, persisting its envelope as both:
  - AgentState["threat_intel"]     (in-memory, for the decide node)
  - Incident.threat_intel           (JSONB column, for the dashboard)
  - one AgentTrace row              (step=2, agent=threat_intel)

Week 7 adds a **severity write-back** at the tail of `run_investigation`:
after the graph runs, we re-evaluate rules against the now-TI-populated
state and bump the persisted Incident.severity if any rule (typically
`ti_high_score`) demands a higher floor. Without this, ingestion-time
severity (computed before the agent graph populates `threat_intel`) is
what the dashboard shows — even if TI then sees a score of 90.

Week 8 adds the Enrichment agent between Threat Intel and Decide,
adding contextual information like GeoIP, asset/user enrichment,
MITRE ATT&CK mapping, and threat scoring.

Week 9 adds the Detection agent after Enrichment, producing a detection
score, attack stage, and basic correlation info.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from langgraph.graph import END, START, StateGraph

from app.agents.state import AgentState
from app.detection.node import detection_node
from app.enrichment.node import enrichment_node
from app.response.node import response_node
from app.agents.threat_intel_node import threat_intel_node
from app.agents.tracing import record_trace
from app.agents.triage import decide_node, triage_node
from app.rules import EvalContext, evaluate, recompute_severity, severity_enum_for

log = logging.getLogger(__name__)


def build_graph() -> Any:
    """Construct (but don't compile) the investigation graph.

    Returning the builder (not the compiled graph) lets callers instrument
    each node before compile — e.g. attach persistence or interrupt hooks.

    Node names are distinct from state keys (LangGraph enforces this — node
    names become graph channels). We use `triage_step`, `threat_intel_step`,
    `enrichment_step`, `detection_step`, and `decide_step`.
    """
    g = StateGraph(AgentState)
    g.add_node("triage_step", triage_node)
    g.add_node("threat_intel_step", threat_intel_node)
    g.add_node("enrichment_step", enrichment_node)
    g.add_node("detection_step", detection_node)
    g.add_node("response_step", response_node)
    g.add_node("decide_step", decide_node)
    g.add_edge(START, "triage_step")
    g.add_edge("triage_step", "threat_intel_step")
    g.add_edge("threat_intel_step", "enrichment_step")
    g.add_edge("enrichment_step", "detection_step")
    g.add_edge("detection_step", "response_step")
    g.add_edge("response_step", "decide_step")
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

    # Persist the Enrichment envelope (optional, for debugging/audit).
    enrichment_envelope = final_state.get("enrichment") or {}
    if enrichment_envelope:
        # Not persisted to Incident by default; could be added to a separate
        # table or to Incident if desired. For now we keep it in AgentState
        # and traces only.
        pass

    # Persist the Detection envelope.
    detection_envelope = final_state.get("detection") or {}
    if detection_envelope:
        # Store detection fields on the Incident row.
        incident_row.detection_score = detection_envelope.get("detection_score")
        incident_row.attack_stage = detection_envelope.get("attack_stage")
        incident_row.related_incident_ids = detection_envelope.get("related_incident_ids")
        incident_row.detection_details = detection_envelope.get("detection_details")

    # Persist the Response envelope.
    response_envelope = final_state.get("response") or {}
    if response_envelope:
        # Store response fields on the Incident row.
        incident_row.response = response_envelope

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

    enrichment_output = final_state.get("enrichment") or {}
    if enrichment_output:
        # Build reasoning string for enrichment
        geo_info = enrichment_output.get('geo', {})
        src_geo = geo_info.get('source') if isinstance(geo_info, dict) else None
        dst_geo = geo_info.get('destination') if isinstance(geo_info, dict) else None
        
        geo_desc = []
        if src_geo:
            geo_desc.append(f"src:{src_geo.get('country', 'Unknown')}")
        if dst_geo:
            geo_desc.append(f"dst:{dst_geo.get('country', 'Unknown')}")
        
        mitre_tactics = enrichment_output.get('mitre_tactics', [])
        mitre_techniques = enrichment_output.get('mitre_techniques', [])
        
        reasoning_parts = []
        if geo_desc:
            reasoning_parts.append(f"Geo: {', '.join(geo_desc)}")
        if mitre_tactics:
            reasoning_parts.append(f"MITRE Tactics: {', '.join(mitre_tactics[:3])}")
        if mitre_techniques:
            reasoning_parts.append(f"MITRE Tech: {', '.join(mitre_techniques[:3])}")
        if enrichment_output.get('threat_score') is not None:
            reasoning_parts.append(f"Threat Score: {enrichment_output['threat_score']}")
        
        reasoning = "; ".join(reasoning_parts) if reasoning_parts else "Enrichment completed"
        
        trace_id = await record_trace(
            session,
            incident_id=incident_uuid,
            agent_name=AgentName.ENRICHMENT,
            step=3,
            input_={
                "threat_intel": threat_intel_envelope,
                "src_ip": (incident_dict.get("raw_event") or {}).get("src"),
            },
            output=enrichment_output,
            reasoning=reasoning,
            started_at=0.0,
        )
        trace_ids.append(str(trace_id))

    detection_output = final_state.get("detection") or {}
    if detection_output:
        # Build reasoning string for detection
        reasoning_parts = []
        if detection_output.get('detection_score') is not None:
            reasoning_parts.append(f"Detection Score: {detection_output['detection_score']}")
        if detection_output.get('attack_stage'):
            reasoning_parts.append(f"Attack Stage: {detection_output['attack_stage']}")
        if detection_output.get('reasoning'):
            # reasoning is a list of strings; join first few
            reason_list = detection_output['reasoning']
            if isinstance(reason_list, list):
                reasoning_parts.append(f"Details: {'; '.join(reason_list[:3])}")
            else:
                reasoning_parts.append(f"Details: {reason_list}")
        if detection_output.get('related_incident_ids'):
            rid = detection_output['related_incident_ids']
            if isinstance(rid, list):
                reasoning_parts.append(f"Related Incidents: {len(rid)}")
        
        reasoning = "; ".join(reasoning_parts) if reasoning_parts else "Detection completed"
        
        trace_id = await record_trace(
            session,
            incident_id=incident_uuid,
            agent_name=AgentName.DETECTION,
            step=4,
            input_={
                "enrichment": enrichment_output,
                "threat_intel": threat_intel_envelope,
            },
            output=detection_output,
            reasoning=reasoning,
            started_at=0.0,
        )
        trace_ids.append(str(trace_id))

    # Response tracing
    response_output = final_state.get("response") or {}
    if response_output:
        # Build reasoning string for response
        reasoning_parts = []
        if response_output.get('response_summary'):
            reasoning_parts.append(f"Summary: {response_output['response_summary']}")
        if response_output.get('recommended_actions'):
            actions = response_output['recommended_actions']
            if isinstance(actions, list):
                reasoning_parts.append(f"Actions: {len(actions)} recommended")
        reasoning = "; ".join(reasoning_parts) if response_output else "Response completed"

        trace_id = await record_trace(
            session,
            incident_id=incident_uuid,
            agent_name=AgentName.RESPONSE,
            step=5,
            input_={
                "enrichment": enrichment_output,
                "detection": detection_output,
            },
            output=response_output,
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
        step=6,
        input_={
            "triage": triage_output,
            "threat_intel": threat_intel_envelope,
            "enrichment": enrichment_output,
            "detection": detection_output,
            "response": response_output,
        },
        output=decide_output,
        reasoning=f"Routed to: {final_state.get('final_decision')}",
        started_at=0.0,
    )
    trace_ids.append(str(trace_id))

    # ── Week 7 — severity write-back ────────────────────────────────────────
    # Ingestion-time rules ran with threat_intel_score=0 (TI hadn't fired
    # yet). Now that TI has populated `incident.threat_intel`, re-run the
    # rules and bump the persisted severity if any new hit demands a higher
    # floor (typically `ti_high_score` → critical).
    try:
        # Re-serialise so the EvalContext sees the *just-written* TI envelope.
        refreshed_dict = _incident_to_dict(incident_row)
        post_ctx = EvalContext.from_incident_dict(refreshed_dict)
        post_hits = evaluate(post_ctx)

        current_sev = (
            incident_row.severity.value
            if hasattr(incident_row.severity, "value")
            else str(incident_row.severity)
        )
        new_sev_label = recompute_severity(current_sev, post_hits)

        if new_sev_label != current_sev:
            log.info(
                "severity write-back: %s → %s for incident %s",
                current_sev, new_sev_label, incident_uuid,
            )
            incident_row.severity = severity_enum_for(new_sev_label)

        # Merge any new post-graph hits into the persisted rule_hits list.
        # De-dup by (rule_id, severity_floor) so re-running investigate on
        # the same incident doesn't double-append.
        existing_keys = {
            (h.get("rule_id"), (h.get("matched") or {}).get("severity_floor"))
            for h in (incident_row.rule_hits or [])
        }
        for h in post_hits:
            key = (h.get("rule_id"), (h.get("matched") or {}).get("severity_floor"))
            if key not in existing_keys:
                incident_row.rule_hits = (incident_row.rule_hits or []) + [h]
                existing_keys.add(key)
    except Exception as e:
        # Never let a write-back bug block an investigation from completing.
        log.warning("severity write-back failed for %s: %s", incident_uuid, e)
    # ────────────────────────────────────────────────────────────────────────

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
        "detection_score": getattr(inc, "detection_score", None),
        "attack_stage": getattr(inc, "attack_stage", None),
        "related_incident_ids": getattr(inc, "related_incident_ids", None),
        "detection_details": getattr(inc, "detection_details", None),
        "response": getattr(inc, "response", None) or {},
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
    }
