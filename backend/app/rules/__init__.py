"""Lightweight, declarative rule engine.

Runs synchronously on the ingestion path, BEFORE the incident is written to
Postgres (so the persisted row reflects rule output). No LLM calls — just
pure Python predicates over the incident's structured fields.

Why a rules-first layer (Week 5 Chunk 2):
  - Surfaces cheap, obvious findings immediately (severity floor, known-bad IP,
    asset risk) without an LLM round-trip.
  - Provides deterministic ground truth for the Week 6+ LangGraph agents to
    build on — Triage agent can say "rules already flagged X" instead of
    re-deriving it.
  - Auditable: every hit has rule_id + matched evidence. Operators can read
    why an incident was escalated.

Rule shape (declarative):
  {
    "rule_id":   str,        # stable id
    "rule_name": str,        # human label
    "severity":  "info|low|medium|high|critical",
    "confidence": float,     # 0.0-1.0
    "matched":   dict,       # evidence
    "description": str,
  }

Adding a rule = adding a function to one of the `*_rules.py` modules that
takes the EvalContext and yields 0+ RuleHit dicts. The engine doesn't need
to know.
"""
from __future__ import annotations

from .engine import EvalContext, evaluate, recompute_severity, severity_enum_for