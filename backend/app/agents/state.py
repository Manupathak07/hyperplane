"""State carried through the LangGraph pipeline.

Every agent reads `incident` + `rule_hits` and writes its own output back into
state. The state is serialised into `agent_traces.input` / `output` so the
Trace Viewer can show what each node saw and produced.

Why a TypedDict (not a Pydantic BaseModel):
  - LangGraph state is expected to be a TypedDict — it gives us partial updates
    and proper merge semantics for free.
  - We can still validate boundaries via Pydantic models in each node if we
    need to (we do, in `_record_trace`).
"""
from __future__ import annotations

import uuid
from typing import Any, Optional, TypedDict


class AgentState(TypedDict, total=False):
    # Inputs (set by the entry point).
    incident_id: str
    incident: dict          # serialised Incident row
    rule_hits: list[dict]   # output of the rule engine

    # Populated as agents run.
    triage: dict            # TriageAgent output
    needs_investigation: bool
    summary: str            # one-line human summary for the dashboard

    # Bookkeeping.
    trace_ids: list[str]    # agent_traces row ids created during this run
    final_decision: str     # "investigate" | "dismiss"