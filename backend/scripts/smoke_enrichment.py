"""Smoke test for the Enrichment agent (Week 8).

Tests the enrichment functionality including:
- IP extraction from events
- GeoIP lookups (mocked)
- Asset/user enrichment
- MITRE ATT&CK mapping
- Threat score calculation
- Integration with the full investigate flow

Assertions:
  1. Enrichment agent extracts source IP correctly
  2. GeoIP lookup returns expected structure for various IP types
  3. Asset enrichment works for internal IPs
  4. User extraction from events
  5. MITRE ATT&CK mapping based on event characteristics
  6. Threat score calculation combines multiple factors
  7. End-to-end: POST /events + POST /investigate → response has enrichment data
  8. Enrichment data includes expected fields
  9. Re-investigation doesn't duplicate enrichment processing
 10. Graceful handling of missing IP data

Usage (from host):
    docker exec hyperplane-backend python -m scripts.smoke_enrichment
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone

import httpx

from app.enrichment.agent import (
    enrich,
    extract_ips_from_raw_event,
    get_asset_info,
    get_geo_info,
    map_to_mitre_techniques,
    calculate_threat_score
)
from app.enrichment.cache import get_cached_asset, get_cached_geo, clear_all_caches

API = os.environ.get("HYPERPLANE_API", "http://localhost:8000")
API_KEY = os.environ.get("EVENTS_API_KEY", "")


def _headers() -> dict:
    if API_KEY:
        return {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    return {"Content-Type": "application/json"}


def _assert(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}  {detail}")
        raise AssertionError(label)


# ---------------------------------------------------------------------------
# 1-6: Unit tests for enrichment components (no network, no DB)
# ---------------------------------------------------------------------------
async def test_ip_extraction() -> None:
    print("--- IP extraction ---")
    # Test various event formats
    event1 = {
        "raw_event": {
            "src": "192.168.1.100",
            "dst": "10.0.0.5",
            "event_type": "connection"
        }
    }
    src_ip, dst_ip = extract_ips_from_raw_event(event1["raw_event"])
    _assert("Extracts src IP", src_ip == "192.168.1.100")
    _assert("Extracts dst IP", dst_ip == "10.0.0.5")
    
    # Test with different field names
    event2 = {
        "raw_event": {
            "source_ip": "172.16.0.10",
            "destination_ip": "8.8.8.8",
            "protocol": "tcp"
        }
    }
    src_ip, dst_ip = extract_ips_from_raw_event(event2["raw_event"])
    _assert("Extracts with source_ip/destination_ip", 
            src_ip == "172.16.0.10" and dst_ip == "8.8.8.8")
    
    # Test missing IPs
    event3 = {
        "raw_event": {
            "event_type": "user_login",
            "user": "admin"
        }
    }
    src_ip, dst_ip = extract_ips_from_raw_event(event3["raw_event"])
    _assert("Handles missing IPs gracefully", src_ip is None and dst_ip is None)


async def test_geoip_lookup() -> None:
    print("--- GeoIP lookup ---")
    await clear_all_caches()  # fresh start
    
    # Test private IP
    geo = await get_geo_info("192.168.1.1")
    _assert("Private IP geo lookup", geo is not None)
    _assert("Private IP marked as internal", 
            geo.get("is_private") == True and geo.get("country") == "Private Network")
    
    # Test localhost
    geo = await get_geo_info("127.0.0.1")
    _assert("Localhost geo lookup", geo is not None)
    _assert("Localhost marked correctly", 
            geo.get("is_localhost") == True and geo.get("city") == "Localhost")
    
    # Test public IP (mocked)
    geo = await get_geo_info("8.8.8.8")
    _assert("Public IP geo lookup", geo is not None)
    _assert("Public IP has expected structure", 
            "country" in geo and "latitude" in geo)
    
    # Test None input
    geo = await get_geo_info(None)
    _assert("None IP returns None", geo is None)
    
    # Test caching
    geo1 = await get_geo_info("1.1.1.1")
    geo2 = await get_geo_info("1.1.1.1")
    _assert("GeoIP caching works", geo1 == geo2)


async def test_asset_enrichment() -> None:
    print("--- Asset enrichment ---")
    await clear_all_caches()
    
    # Test internal IP asset lookup
    asset = await get_asset_info("192.168.1.100")
    _assert("Internal IP gets asset ID", 
            asset is not None and asset.startswith("ASSET-"))
    
    asset = await get_asset_info("10.0.0.50")
    _assert("10.x.x.x IP gets asset ID", 
            asset is not None and asset.startswith("ASSET-10-"))
    
    asset = await get_asset_info("172.16.5.10")
    _assert("172.16.x.x IP gets asset ID", 
            asset is not None and asset.startswith("ASSET-172-"))
    
    # Test public IP (no asset)
    asset = await get_asset_info("8.8.8.8")
    _assert("Public IP returns no asset", asset is None)
    
    # Test None input
    asset = await get_asset_info(None)
    _assert("None IP returns None", asset is None)
    
    # Test caching
    asset1 = await get_asset_info("192.168.1.50")
    asset2 = await get_asset_info("192.168.1.50")
    _assert("Asset caching works", asset1 == asset2)


async def test_user_extraction() -> None:
    print("--- User extraction ---")
    # Test direct user field
    event1 = {"raw_event": {"user": "john.doe"}}
    user = get_user_info(event1["raw_event"])
    _assert("Extracts user from user field", user == "john.doe")
    
    # Test username field
    event2 = {"raw_event": {"username": "admin"}}
    user = get_user_info(event2["raw_event"])
    _assert("Extracts user from username field", user == "admin")
    
    # Test nested user object
    event3 = {"raw_event": {"user": {"username": "jane", "user_id": "jdoe"}}}
    user = get_user_info(event3["raw_event"])
    _assert("Extracts user from nested object", user == "jane")
    
    # Test empty/invalid values
    event4 = {"raw_event": {"user": "", "username": "-"}}
    user = get_user_info(event4["raw_event"])
    _assert("Returns None for empty user values", user is None)
    
    # Test missing user
    event5 = {"raw_event": {"event_type": "connection"}}
    user = get_user_info(event5["raw_event"])
    _assert("Returns None when no user present", user is None)


async def test_mitre_mapping() -> None:
    print("--- MITRE ATT&CK mapping ---")
    # Test brute force attack
    event1 = {
        "raw_event": {
            "event_type": "auth.login_failed",
            "description": "brute force attempt",
            "src": "198.51.100.10"
        }
    }
    tactics, techniques = map_to_mitre_techniques(event1["raw_event"], {})
    _assert("Brute force maps to credential access", 
            "credential-access" in tactics)
    _assert("Brute force includes brute force technique", 
            any(t.startswith("T1110") for t in techniques))
    
    # Test malware
    event2 = {
        "raw_event": {
            "event_type": "malware.detected",
            "description": "trojan found",
            "src": "10.0.0.5"
        }
    }
    tactics, techniques = map_to_mitre_techniques(event2["raw_event"], {})
    _assert("Malware maps to execution", 
            "execution" in tactics)
    
    # Test network scan
    event3 = {
        "raw_event": {
            "event_type": "network.scan",
            "description": "port sweep detected",
            "dst": "192.168.1.0/24"
        }
    }
    tactics, techniques = map_to_mitre_techniques(event3["raw_event"], {})
    _assert("Network scan maps to discovery", 
            "discovery" in tactics)
    _assert("Network scan includes scanning technique", 
            any(t.startswith("T1046") for t in techniques))
    
    # Test with high threat intel score boosting to command & control
    event4 = {
        "raw_event": {
            "event_type": "connection",
            "description": "outbound connection",
            "dst": "203.0.113.100"
        }
    }
    threat_intel = {"score": 85}  # High score
    tactics, techniques = map_to_mitre_techniques(event4["raw_event"], threat_intel)
    _assert("High TI score adds command and control", 
            "command-and-control" in tactics)


async def test_threat_score_calculation() -> None:
    print("--- Threat score calculation ---")
    incident = {
        "raw_event": {
            "event_type": "auth.login_failed",
            "description": "brute force attempt",
            "src": "198.51.100.10",
            "user": "admin"
        }
    }
    threat_intel = {"score": 90}  # High threat intel
    
    # Enrichment data (what would come from enrichment step)
    enrichment_data = {
        "geo": {
            "source": {"country": "United States", "is_private": False},
            "destination": None
        },
        "asset_id": "ASSET-10-0-10",
        "user_id": "admin",
        "mitre_tactics": ["credential-access", "lateral-movement"],
        "mitre_techniques": ["T1078", "T1021.002"],
        "threat_score": 0  # Will be calculated
    }
    
    score = calculate_threat_score(incident, threat_intel, enrichment_data)
    _assert("Threat score is integer", isinstance(score, int))
    _assert("Threat score in valid range", 0 <= score <= 100)
    _assert("High threat scenario gets elevated score", score > 50)
    
    # Test low threat scenario
    incident2 = {
        "raw_event": {
            "event_type": "info.startup",
            "description": "service started",
            "src": "10.0.0.5"
        }
    }
    threat_intel2 = {"score": 10}  # Low threat intel
    
    enrichment_data2 = {
        "geo": {
            "source": {"country": "Private Network", "is_private": True},
            "destination": None
        },
        "asset_id": "ASSET-10-0-5",
        "user_id": None,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "threat_score": 0
    }
    
    score2 = calculate_threat_score(incident2, threat_intel2, enrichment_data2)
    _assert("Low threat scenario gets lower score", score2 < score)
    _assert("Low threat score still valid", 0 <= score2 <= 100)


# ---------------------------------------------------------------------------
# 7-10: End-to-end tests through the API
# ---------------------------------------------------------------------------
def _sample_event(src_ip: str, eid: uuid.UUID, event_type: str = "auth.login_failed") -> dict:
    return {
        "event_id": str(eid),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "domain": "it",
        "event_type": event_type,
        "severity": 3,
        "confidence": 0.9,
        "src": src_ip,
        "user": "testuser",
        "host": "test-host",
        "raw": f"enrichment test from {src_ip}",
        "parser": "syslog",
        "vendor": "linux",
        "tags": ["smoke-enrich"],
        "labels": {"test": "enrichment"},
    }


async def test_investigate_e2e() -> None:
    print("--- e2e investigate with enrichment ---")
    async with httpx.AsyncClient(timeout=15) as client:
        # Use an RFC5737 src for predictable threat intel + enrichment
        eid = uuid.uuid4()
        ev = _sample_event("198.51.100.50", eid)
        
        # Clear caches to ensure fresh lookups
        await clear_all_caches()
        
        # Post event
        r = await client.post(f"{API}/events/", json=ev, headers=_headers())
        _assert("POST /events accepted", 
                r.status_code == 200, f"got {r.status_code}: {r.text}")
        results = r.json().get("results", [])
        _assert("Event created", 
                len(results) == 1 and results[0]["status"] == "created")
        incident_id = results[0]["id"]
        
        # Run investigate
        r2 = await client.post(f"{API}/incidents/{incident_id}/investigate", 
                               headers=_headers())
        _assert("POST /investigate returns 200", 
                r2.status_code == 200, f"got {r2.status_code}: {r2.text}")
        body = r2.json()
        
        # Check that enrichment data is present
        enrichment = body.get("enrichment") or {}
        _assert("Response includes enrichment data", 
                isinstance(enrichment, dict) and len(enrichment) > 0)
        
        # Check key enrichment fields
        _assert("Enrichment includes source_ip", 
                "source_ip" in enrichment and enrichment["source_ip"] == "198.51.100.50")
        _assert("Enrichment includes geo data", 
                "geo" in enrichment and isinstance(enrichment["geo"], dict))
        _assert("Enrichment includes asset_id", 
                "asset_id" in enrichment)
        _assert("Enrichment includes user_id", 
                "user_id" in enrichment)
        _assert("Enrichment includes MITRE tactics", 
                "mitre_tactics" in enrichment and isinstance(enrichment["mitre_tactics"], list))
        _assert("Enrichment includes MITRE techniques", 
                "mitre_techniques" in enrichment and isinstance(enrichment["mitre_techniques"], list))
        _assert("Enrichment includes threat_score", 
                "threat_score" in enrichment and isinstance(enrichment["threat_score"], int))
        _assert("Threat score in valid range", 
                0 <= enrichment["threat_score"] <= 100)
        
        # Check trace includes enrichment step
        trace_ids = body.get("trace_ids", [])
        _assert("Has 4 trace entries (triage + threat_intel + enrichment + decide)", 
                len(trace_ids) == 4, f"got {len(trace_ids)} trace_ids")
        
        print(f"  [info] enrichment keys: {list(enrichment.keys())}")
        print(f"  [info] threat_score: {enrichment.get('threat_score')}")
        print(f"  [info] mitre_tactics: {enrichment.get('mitre_tactics')}")
        print(f"  [info] mitre_techniques: {enrichment.get('mitre_techniques')}")


async def test_reinvestigate_idempotency() -> None:
    print("--- re-investigate idempotency ---")
    async with httpx.AsyncClient(timeout=15) as client:
        eid = uuid.uuid4()
        ev = _sample_event("203.0.113.25", eid, "malware.detected")
        
        await clear_all_caches()
        
        # First investigation
        r = await client.post(f"{API}/events/", json=ev, headers=_headers())
        r.raise_for_status()
        results = r.json().get("results", [])
        incident_id = results[0]["id"]
        
        r1 = await client.post(f"{API}/incidents/{incident_id}/investigate", 
                               headers=_headers())
        r1.raise_for_status()
        body1 = r1.json()
        enrichment1 = body1.get("enrichment") or {}
        
        # Second investigation (re-investigate)
        r2 = await client.post(f"{API}/incidents/{incident_id}/investigate", 
                               headers=_headers())
        r2.raise_for_status()
        body2 = r2.json()
        enrichment2 = body2.get("enrichment") or {}
        
        # Core enrichment data should be identical (cached lookups)
        _assert("Re-investigation preserves source_ip", 
                enrichment1.get("source_ip") == enrichment2.get("source_ip"))
        _assert("Re-investigation preserves asset_id", 
                enrichment1.get("asset_id") == enrichment2.get("asset_id"))
        _assert("Re-investigation preserves user_id", 
                enrichment1.get("user_id") == enrichment2.get("user_id"))
        _assert("Re-investigation preserves MITRE data", 
                enrichment1.get("mitre_tactics") == enrichment2.get("mitre_tactics") and
                enrichment1.get("mitre_techniques") == enrichment2.get("mitre_techniques"))
        
        # Threat score might vary slightly due to timing but should be close
        ts1 = enrichment1.get("threat_score", 0)
        ts2 = enrichment2.get("threat_score", 0)
        _assert("Re-investigation threat score reasonably consistent", 
                abs(ts1 - ts2) <= 5)  # Allow small variance


async def test_no_ip_handling() -> None:
    print("--- graceful handling of missing IPs ---")
    async with httpx.AsyncClient(timeout=15) as client:
        eid = uuid.uuid4()
        # Event with no IP addresses
        ev = _sample_event("", eid, "user.login")
        ev["src"] = ""  # Explicitly empty
        
        await clear_all_caches()
        
        # Post event
        r = await client.post(f"{API}/events/", json=ev, headers=_headers())
        _assert("Event with no IP accepted", 
                r.status_code == 200, f"got {r.status_code}: {r.text}")
        results = r.json().get("results", [])
        _assert("Event created", 
                len(results) == 1 and results[0]["status"] == "created")
        incident_id = results[0]["id"]
        
        # Investigate should still work
        r2 = await client.post(f"{API}/incidents/{incident_id}/investigate", 
                               headers=_headers())
        _assert("Investigate succeeds with no IP", 
                r2.status_code == 200, f"got {r2.status_code}: {r2.text}")
        body = r2.json()
        
        enrichment = body.get("enrichment") or {}
        _assert("Enrichment present even with no IP", 
                isinstance(enrichment, dict))
        _assert("Source IP is None when not provided", 
                enrichment.get("source_ip") is None)
        _assert("Geo is None when no IP", 
                enrichment.get("geo") is None or enrichment.get("geo") == {})


async def main() -> None:
    print("=== Enrichment smoke test ===")
    await test_ip_extraction()
    await test_geoip_lookup()
    await test_asset_enrichment()
    await test_user_extraction()
    await test_mitre_mapping()
    await test_threat_score_calculation()
    await test_investigate_e2e()
    await test_reinvestigate_idempotency()
    await test_no_ip_handling()
    print("=== ALL PASSED ===")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except AssertionError:
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
