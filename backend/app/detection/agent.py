"""Detection agent — `detect(incident, threat_intel, enrichment)` is the entry point
used by the LangGraph `detection_node`.

Inputs:
  incident: dict from AgentState["incident"]
  threat_intel: dict from AgentState["threat_intel"] (score, sources, hits, checked_at)
  enrichment: dict from AgentState["enrichment"] (source_ip, destination_ip, geo,
                asset_id, user_id, mitre_tactics, mitre_techniques, threat_score,
                indicators)

Output:
  dict with keys:
    - detection_score: int (0-100)
    - attack_stage: str (one of the kill‑chain phases)
    - reasoning: list of strings explaining contributions
    - related_incident_ids: list of UUIDs (placeholder for future correlation)
    - detection_details: dict with per‑component scores for debugging/tracing
"""
from __future__ import annotations

from typing import Any, Dict, List

# MITRE technique weights (simplified)
_HIGH_RISK_TECHNIQUES = {
    "T1068": 2,  # Exploitation for Privilege Escalation
    "T1055": 2,  # Process Injection
    "T1021": 2,  # Remote Services
    "T1071": 2,  # Application Layer Protocol
    "T1041": 2,  # Exfiltration Over C2 Channel
    "T1486": 2,  # Data Encrypted for Impact
}
_MEDIUM_RISK_TECHNIQUES = {
    "T1046": 1,  # Network Service Scanning
    "T1078": 1,  # Valid Accounts
    "T1082": 1,  # System Information Discovery
    "T1083": 1,  # File and Directory Discovery
    "T1016": 1,  # System Network Configuration Discovery
    "T1033": 1,  # System Owner/User Discovery
    "T1087": 1,  # Account Discovery
}

_PRIVILEGED_USERS = {"admin", "administrator", "root", "sysadmin", "domain_admin"}


def _asset_score(asset_id: str | None) -> int:
    """Very simple asset criticality heuristic."""
    if not asset_id:
        return 0
    if asset_id.startswith("ASSET-10") or asset_id.startswith("ASSET-172"):
        return 10  # infrastructure / servers
    if asset_id.startswith("ASSET-192"):
        return 5   # end‑user workstations
    return 0


def _user_score(user_id: str | None) -> int:
    if not user_id:
        return 0
    return 5 if user_id.lower() in _PRIVILEGED_USERS else 0


def _mitre_score(techniques: List[str]) -> int:
    total = 0
    for t in techniques:
        w = _HIGH_RISK_TECHNIQUES.get(t)
        if w is not None:
            total += w
            continue
        w = _MEDIUM_RISK_TECHNIQUES.get(t)
        if w is not None:
            total += w
    # Cap at 10 points
    return min(total, 10)


def _attack_stage_from_score(score: int) -> str:
    if score <= 20:
        return "Reconnaissance"
    if score <= 40:
        return "Weaponization"
    if score <= 60:
        return "Delivery"
    if score <= 80:
        return "Exploitation"
    return "Actions on Objectives"


def detect(
    incident: dict[str, Any],
    threat_intel: dict[str, Any],
    enrichment: dict[str, Any],
) -> dict[str, Any]:
    """Run detection logic and return a detection envelope."""
    ti_score = threat_intel.get("score", 0) if threat_intel else 0
    enrich_score = enrichment.get("threat_score", 0) if enrichment else 0

    asset_id = enrichment.get("asset_id") if enrichment else None
    user_id = enrichment.get("user_id") if enrichment else None
    techniques = enrichment.get("mitre_techniques", []) if enrichment else []

    asset_s = _asset_score(asset_id)
    user_s = _user_score(user_id)
    mitre_s = _mitre_score(techniques)

    # Weighted sum: TI 40%, Enrich 30%, rest raw points (max ~30)
    detection_score = int(0.4 * ti_score + 0.3 * enrich_score + asset_s + user_s + mitre_s)
    detection_score = max(0, min(100, detection_score))

    attack_stage = _attack_stage_from_score(detection_score)

    reasoning = [
        f"threat_intel_score={ti_score} (wt 0.4 → {int(0.4*ti_score)})",
        f"enrichment_threat_score={enrich_score} (wt 0.3 → {int(0.3*enrich_score)})",
        f"asset_score={asset_s}",
        f"user_score={user_s}",
        f"mitre_score={mitre_s}",
        f"total={detection_score}",
    ]

    # Placeholder for correlation – could look up other incidents with same correlation_id
    related_ids: list = []

    details = {
        "threat_intel_score": ti_score,
        "enrichment_threat_score": enrich_score,
        "asset_score": asset_s,
        "user_score": user_s,
        "mitre_score": mitre_s,
        "weights": {"ti": 0.4, "enrich": 0.3},
    }

    return {
        "detection_score": detection_score,
        "attack_stage": attack_stage,
        "reasoning": reasoning,
        "related_incident_ids": related_ids,
        "detection_details": details,  # note: key typo intentional to match earlier? We'll keep as detection_details
    }


__all__ = ["detect"]
