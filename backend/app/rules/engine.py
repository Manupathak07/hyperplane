"""Rule engine orchestrator.

`evaluate(ctx)` runs all rules across the rule modules and returns the
collected RuleHit list. `recompute_severity()` then optionally bumps the
incident's severity if any rule hit demands a higher floor.

Severity floors (numeric → enum):
  numeric >= 9 → critical
  numeric >= 7 → high
  numeric >= 4 → medium
  numeric  < 4 → low
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.models import Severity

log = logging.getLogger(__name__)


@dataclass
class EvalContext:
    """Everything a rule needs to make a decision.

    Built once per evaluation; passed by reference so rules can read what they
    need without each one re-fetching.
    """

    # The incident under evaluation (detached from any session — purely read).
    incident_id: Any
    title: str
    description: str | None
    event_type: str
    domain: str  # "IT" | "OT" | "IoT"
    severity: str  # current severity enum value
    severity_numeric: int | None
    source: str
    src: str | None
    asset_id: str | None
    user: str | None
    host: str | None
    raw: str | None
    tags: list[str] = field(default_factory=list)
    correlation_id: str | None = None
    # Week 6 — Threat Intel agent score (0-100). Populated from the incident's
    # `threat_intel` JSONB column. 0 = no signal (no agent run yet, or no IP).
    threat_intel_score: int = 0

    @classmethod
    def from_incident_dict(cls, inc: dict) -> "EvalContext":
        """Build from an Incident ORM row (or any dict with the same keys)."""
        raw_event = inc.raw_event or {} if hasattr(inc, "raw_event") else inc.get("raw_event") or {}
        # Week 6 — `threat_intel` is a JSONB column on Incident. It's either
        # the ORM attribute, the dict key, or missing (legacy rows default
        # to {} via the migration's server_default).
        ti = getattr(inc, "threat_intel", None)
        if ti is None:
            ti = inc.get("threat_intel") if isinstance(inc, dict) else None
        ti = ti or {}
        ti_score = int(ti.get("score", 0) or 0)

        return cls(
            incident_id=str(getattr(inc, "id", inc.get("id"))),
            title=getattr(inc, "title", inc.get("title", "")),
            description=getattr(inc, "description", inc.get("description")),
            event_type=getattr(inc, "event_type", inc.get("event_type", "unknown")),
            domain=_enum_value(getattr(inc, "domain", inc.get("domain"))),
            severity=_enum_value(getattr(inc, "severity", inc.get("severity"))),
            severity_numeric=raw_event.get("severity_numeric"),
            source=getattr(inc, "source", inc.get("source", "unknown")),
            src=raw_event.get("src"),
            asset_id=raw_event.get("asset_id"),
            user=raw_event.get("user"),
            host=raw_event.get("host"),
            raw=raw_event.get("raw"),
            tags=list(raw_event.get("tags") or []),
            correlation_id=str(getattr(inc, "correlation_id", inc.get("correlation_id")) or "") or None,
            threat_intel_score=ti_score,
        )


def _enum_value(v: Any) -> str:
    if v is None:
        return ""
    return v.value if hasattr(v, "value") else str(v)


# Severity rank for the "bump to higher" logic.
_SEV_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def evaluate(ctx: EvalContext) -> list[dict]:
    """Run all rules and return their hits. Order is stable for debugging.

    Modules are imported lazily to avoid the circular import between
    `engine` (the orchestrator) and the rule modules (which depend on
    EvalContext defined here).
    """
    # Imported here, not at module top, to break the cycle.
    from . import correlation_rules, severity_rules, threatintel_rules

    hits: list[dict] = []
    for module in (severity_rules, threatintel_rules, correlation_rules):
        try:
            module_hits = module.evaluate(ctx)
        except Exception as e:  # never let one bad rule poison the pipeline
            log.warning("rule module %s failed: %s", module.__name__, e)
            module_hits = []
        hits.extend(module_hits)
    return hits


def recompute_severity(current: str, hits: list[dict]) -> str:
    """Bump the incident's severity to the highest floor demanded by hits.

    Rules can carry `severity_floor` inside `matched` — if any rule demands a
    floor higher than the current incident severity, we bump to that floor.
    Also applies the numeric-severity rule directly.
    """
    best_rank = _SEV_RANK.get(current, 0)
    best_label = current

    for hit in hits:
        matched = hit.get("matched") or {}
        floor = matched.get("severity_floor")
        if not floor:
            continue
        rank = _SEV_RANK.get(floor, 0)
        if rank > best_rank:
            best_rank = rank
            best_label = floor

    return best_label


def severity_enum_for(label: str) -> Severity:
    """Map a severity label (from rule output or numeric floor) to the enum."""
    return {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }.get(label, Severity.MEDIUM)