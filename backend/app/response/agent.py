"""Response agent — `respond(incident, threat_intel, enrichment, detection)` is the entry point
used by the LangGraph `response_node`.

Inputs:
  incident: dict from AgentState["incident"]
  threat_intel: dict from AgentState["threat_intel"] (score, sources, hits, checked_at)
  enrichment: dict from AgentState["enrichment"] (source_ip, destination_ip, geo,
                asset_id, user_id, mitre_tactics, mitre_techniques, threat_score,
                indicators)
  detection: dict from AgentState["detection"] (detection_score, attack_stage,
                reasoning, related_incident_ids, detection_details)

Output:
  dict with keys:
    - report: str (markdown formatted incident report)
    - recommended_actions: list of strings (suggested actions)
    - response_summary: str (short summary for dashboard)
    - details: dict (additional details for debugging/tracing)
"""
from __future__ import annotations

from typing import Any, Dict, List


def _build_report(
    incident: dict[str, Any],
    threat_intel: dict[str, Any],
    enrichment: dict[str, Any],
    detection: dict[str, Any],
) -> str:
    """Generate a markdown report of the investigation."""
    incident_id = incident.get("id", "unknown")
    title = incident.get("title", "Unknown Incident")
    description = incident.get("description", "")
    severity = incident.get("severity", "unknown")
    status = incident.get("status", "unknown")
    event_type = incident.get("event_type", "unknown")
    source = incident.get("source", "unknown")

    # Threat intel summary
    ti_score = threat_intel.get("score", 0) if threat_intel else 0
    ti_sources = []
    if threat_intel and threat_intel.get("sources"):
        for src, data in threat_intel["sources"].items():
            if data:
                ti_sources.append(src)
    ti_hits = threat_intel.get("hits", []) if threat_intel else []

    # Enrichment summary
    src_ip = enrichment.get("source_ip") if enrichment else None
    dst_ip = enrichment.get("destination_ip") if enrichment else None
    geo = enrichment.get("geo", {}) if enrichment else {}
    asset_id = enrichment.get("asset_id") if enrichment else None
    user_id = enrichment.get("user_id") if enrichment else None
    mitre_tactics = enrichment.get("mitre_tactics", []) if enrichment else []
    mitre_techniques = enrichment.get("mitre_techniques", []) if enrichment else []
    enrich_score = enrichment.get("threat_score", 0) if enrichment else 0

    # Detection summary
    det_score = detection.get("detection_score", 0) if detection else 0
    attack_stage = detection.get("attack_stage", "unknown") if detection else "unknown"
    det_reasoning = detection.get("reasoning", []) if detection else []
    related_ids = detection.get("related_incident_ids", []) if detection else []

    # Build markdown
    lines = [
        f"# Incident Report: {title}",
        f"**Incident ID:** {incident_id}",
        f"**Status:** {status}",
        f"**Severity:** {severity}",
        f"**Event Type:** {event_type}",
        f"**Source:** {source}",
        "",
        "## Description",
        description or "*No description provided*",
        "",
        "## Threat Intelligence",
        f"- Score: {ti_score}/100",
        f"- Sources: {', '.join(ti_sources) if ti_sources else 'None'}",
        f"- Hits: {len(ti_hits)}",
        "",
        "## Enrichment",
        f"- Source IP: {src_ip or 'N/A'}",
        f"- Destination IP: {dst_ip or 'N/A'}",
        f"- Asset ID: {asset_id or 'N/A'}",
        f"- User ID: {user_id or 'N/A'}",
        f"- Threat Score: {enrich_score}/100",
        f"- MITRE Tactics: {', '.join(mitre_tactics) if mitre_tactics else 'None'}",
        f"- MITRE Techniques: {', '.join(mitre_techniques) if mitre_techniques else 'None'}",
        "",
        "## Detection",
        f"- Detection Score: {det_score}/100",
        f"- Attack Stage: {attack_stage}",
        f"- Related Incidents: {len(related_ids)}",
        "",
        "## Detection Reasoning",
    ]
    if det_reasoning:
        for r in det_reasoning:
            lines.append(f"- {r}")
    else:
        lines.append("*No reasoning provided*")
    lines.extend(
        [
            "",
            "## Recommended Actions",
        ]
    )
    # We'll add recommendations after generating them
    return "\n".join(lines)


def _recommend_actions(
    incident: dict[str, Any],
    threat_intel: dict[str, Any],
    enrichment: dict[str, Any],
    detection: dict[str, Any],
) -> List[str]:
    """Generate a list of recommended actions based on the analysis."""
    actions = []

    # Based on detection score
    det_score = detection.get("detection_score", 0) if detection else 0
    if det_score >= 90:
        actions.append("Isolate affected systems immediately.")
        actions.append("Block all network traffic to/from suspicious IPs.")
    elif det_score >= 70:
        actions.append("Consider isolating affected systems.")
        actions.append("Monitor network traffic for suspicious activity.")
    elif det_score >= 40:
        actions.append("Investigate further with additional logs.")
    else:
        actions.append("No immediate action required based on detection score.")

    # Based on threat intel
    ti_score = threat_intel.get("score", 0) if threat_intel else 0
    if ti_score >= 80:
        actions.append("Block indicators from threat intel feeds.")
        actions.append("Search for similar indicators in historical logs.")

    # Based on enrichment
    if enrichment:
        asset_id = enrichment.get("asset_id")
        if asset_id and asset_id.startswith("ASSET-10"):
            actions.append("Prioritize investigation due to critical asset involvement.")
        user_id = enrichment.get("user_id")
        if user_id and user_id.lower() in ("admin", "administrator", "root", "sysadmin", "domain_admin"):
            actions.append("Review privileged user activity for misuse.")

    # Based on attack stage
    attack_stage = detection.get("attack_stage", "").lower() if detection else ""
    if "exploitation" in attack_stage or "actions on objectives" in attack_stage:
        actions.append("Assume breach; initiate incident response plan.")
        actions.append("Collect volatile memory and disk images from affected systems.")
    elif "delivery" in attack_stage or "weaponization" in attack_stage:
        actions.append("Block delivery mechanisms (e.g., malicious email, drive-by download).")
        actions.append("Scan for malware remnants.")

    # Deduplicate while preserving order
    seen = set()
    unique_actions = []
    for action in actions:
        if action not in seen:
            seen.add(action)
            unique_actions.append(action)

    return unique_actions


def respond(
    incident: dict[str, Any],
    threat_intel: dict[str, Any],
    enrichment: dict[str, Any],
    detection: dict[str, Any],
) -> dict[str, Any]:
    """Generate response artifacts and return them as a dict."""
    report = _build_report(incident, threat_intel, enrichment, detection)
    actions = _recommend_actions(incident, threat_intel, enrichment, detection)
    # Append actions to report
    report_with_actions = report + "\n".join([f"- {action}" for action in actions])
    summary = f"Incident {incident.get('id', 'unknown')}: {len(actions)} recommended actions generated."
    details = {
        "report_length": len(report),
        "action_count": len(actions),
        "detection_score": detection.get("detection_score", 0) if detection else 0,
        "threat_intel_score": threat_intel.get("score", 0) if threat_intel else 0,
        "enrichment_score": enrichment.get("threat_score", 0) if enrichment else 0,
    }
    return {
        "report": report_with_actions,
        "recommended_actions": actions,
        "response_summary": summary,
        "details": details,
    }


__all__ = ["respond"]