"""Helpers for writing AgentTrace rows.

The Trace Viewer (Week 11) reads from `agent_traces` to reconstruct a step-by-
step view of each incident's investigation. We write one row per agent node
per run, capturing:
  - what the node saw as input
  - what it produced as output
  - a human-readable reasoning string
  - duration in ms (for the perf chart)
"""
from __future__ import annotations

import time
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AgentName, AgentTrace, TraceStatus


async def record_trace(
    session: AsyncSession,
    *,
    incident_id: uuid.UUID,
    agent_name: AgentName,
    step: int,
    input_: dict,
    output: dict,
    reasoning: str | None,
    started_at: float,
) -> uuid.UUID:
    """Persist one AgentTrace row. Returns its id."""
    duration_ms = int((time.monotonic() - started_at) * 1000)
    trace = AgentTrace(
        id=uuid.uuid4(),
        incident_id=incident_id,
        agent_name=agent_name,
        step=step,
        input=input_,
        output=output,
        reasoning=reasoning,
        duration_ms=duration_ms,
        status=TraceStatus.SUCCESS,
    )
    session.add(trace)
    await session.flush()
    return trace.id