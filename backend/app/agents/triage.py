"""Triage agent — first node in the investigation pipeline.

Week 5 version is purely deterministic: it inspects the rule hits and decides
whether to escalate, dismiss, or hold for more info. It does NOT call an LLM.
That's deliberate — we want a known-good baseline before adding non-determinism
(Week 6 will swap in the Supervisor agent's LLM call).

Decision rubric:
  - Critical severity OR (High severity + ≥2 rule hits)  → investigate
  - No rule hits AND low/medium severity                 → dismiss
  - Otherwise                                           → investigate (default)
"""
from __future__ import annotations

from app.agents.state import AgentState


def triage_node(state: AgentState) -> AgentState:
    """Pure function — reads state, returns state delta."""
    incident = state.get("incident") or {}
    rule_hits = state.get("rule_hits") or []
    severity = (incident.get("severity") or "low").lower()

    high_severity = severity in ("high", "critical")
    many_hits = len(rule_hits) >= 2

    if severity == "critical" or (severity == "high" and many_hits):
        decision = "investigate"
        reasoning = (
            f"Severity={severity} with {len(rule_hits)} rule hits — "
            f"warrants full investigation."
        )
    elif not rule_hits and severity in ("low", "medium"):
        decision = "dismiss"
        reasoning = (
            f"No rule hits, severity={severity} — likely benign. "
            f"Archive and move on."
        )
    else:
        decision = "investigate"
        reasoning = (
            f"Severity={severity} with {len(rule_hits)} rule hits — "
            f"defaulting to investigation."
        )

    # One-line summary surfaced to the dashboard.
    summary = (
        f"{incident.get('title', 'incident')} — "
        f"{decision} ({len(rule_hits)} rule hits, severity {severity})"
    )

    return {
        "triage": {
            "decision": decision,
            "reasoning": reasoning,
            "rule_hit_count": len(rule_hits),
            "severity": severity,
        },
        "needs_investigation": decision == "investigate",
        "summary": summary,
    }


def decide_node(state: AgentState) -> AgentState:
    """Terminal gate — picks the final decision string for the run."""
    triage = state.get("triage") or {}
    decision = triage.get("decision", "investigate")
    return {"final_decision": decision}