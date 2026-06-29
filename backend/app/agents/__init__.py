"""HyperPlane 6-agent pipeline (LangGraph state graph).

Week 5 Chunk 3 scaffold:
  - Single agent wired in: TriageAgent (summarises incident + rule hits,
    decides whether the case warrants more investigation).
  - State graph topology: START → triage → decide → END
  - Each agent invocation writes one row into `agent_traces` so the Trace
    Viewer (Week 11) can replay the run.

Weeks 6-10 will slot in:
  - Supervisor (Week 6)  — replaces the simple decide() gate with an LLM call
  - Threat Intel (Week 7)
  - Enrichment   (Week 8)
  - Detection    (Week 9)
  - Response     (Week 10)

Why LangGraph:
  - Built-in state management + checkpointing (durable replays)
  - Typed state + conditional edges read like a flow chart
  - First-class observability — every node's input/output/state diff can be
    serialised for the Trace Viewer
"""
from __future__ import annotations