"""POST /incidents/{id}/investigate — runs the agent pipeline on one incident.

Week 5 Chunk 3: Triage → Decide graph. Writes AgentTrace rows so the Trace
Viewer can render the run. Returns the final state for the operator UI to
display the summary + decision.

Future weeks: this endpoint will accept `{force: true}` to override the
auto-investigate threshold (e.g. for low-sev incidents we still want to peek).
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.graph import run_investigation
from app.db import get_session
from app.models import Incident, IncidentStatus

router = APIRouter(prefix="/incidents", tags=["investigate"])


@router.post("/{incident_id}/investigate")
async def investigate_incident(
    incident_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Run the agent graph on this incident and persist traces."""
    stmt = select(Incident).where(Incident.id == incident_id)
    result = await session.execute(stmt)
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    rule_hits = list(getattr(incident, "rule_hits", []) or [])
    final_state = await run_investigation(session, incident, rule_hits)

    # Bump status to triaging so the dashboard reflects that work has begun.
    incident.status = IncidentStatus.TRIAGING
    await session.commit()

    return {
        "incident_id": str(incident.id),
        "final_decision": final_state.get("final_decision"),
        "summary": final_state.get("summary"),
        "triage": final_state.get("triage"),
        "threat_intel": final_state.get("threat_intel"),
        "trace_ids": final_state.get("trace_ids", []),
    }