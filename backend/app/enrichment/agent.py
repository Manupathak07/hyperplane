"""Enrichment agent — `enrich(incident, threat_intel)` is the entry point used by the
LangGraph `enrichment_node`.

Flow:
  1. Extract IP addresses from incident.raw_event
  2. Perform GeoIP lookup on IPs (cached)
  3. Enrich with asset information from CMDB/inventory (cached)
  4. Map observed behaviors to MITRE ATT&CK techniques 
  5. Calculate composite threat score
  6. Return enrichment envelope matching NormalizedIncident fields

The `envelope` shape matches what gets stored in NormalizedIncident:
  {
    "source_ip": str,
    "destination_ip": str | None,
    "geo": {"source": {...}, "destination": {...}} | None,
    "asset_id": str | None,
    "user_id": str | None,
    "mitre_tactics": list[str],
    "mitre_techniques": list[str],
    "threat_score": int (0-100),
    "indicators": dict
  }
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any, Dict, List, Optional, Tuple

from app.config import settings
from app.enrichment.cache import get_cached_asset, get_cached_geo, set_cached_asset, set_cached_geo

log = logging.getLogger(__name__)


def extract_ips_from_raw_event(raw_event: dict) -> tuple[Optional[str], Optional[str]]:
    """Extract source and destination IP addresses from raw event data."""
    src_ip = None
    dst_ip = None
    
    # Common field names for source/destination IPs
    src_fields = ['src', 'source_ip', 'src_ip', 'source']
    dst_fields = ['dst', 'destination_ip', 'dest_ip', 'destination']
    
    # Try direct field access
    for field in src_fields:
        if field in raw_event and isinstance(raw_event[field], str):
            try:
                ipaddress.ip_address(raw_event[field])  # Validate IP
                src_ip = raw_event[field]
                break
            except ValueError:
                pass
    
    for field in dst_fields:
        if field in raw_event and isinstance(raw_event[field], str):
            try:
                ipaddress.ip_address(raw_event[field])  # Validate IP
                dst_ip = raw_event[field]
                break
            except ValueError:
                pass
    
    # If not found in direct fields, try nested structures
    if not src_ip or not dst_ip:
        # Try common nested structures
        if 'network' in raw_event and isinstance(raw_event['network'], dict):
            net = raw_event['network']
            if not src_ip and 'src' in net:
                try:
                    ipaddress.ip_address(net['src'])
                    src_ip = net['src']
                except ValueError:
                    pass
            if not dst_ip and 'dst' in net:
                try:
                    ipaddress.ip_address(net['dst'])
                    dst_ip = net['dst']
                except ValueError:
                    pass
    
    return src_ip, dst_ip


async def get_geo_info(ip: Optional[str]) -> Optional[Dict[str, Any]]:
    """Get geographical information for an IP address with caching."""
    if not ip:
        return None
    
    try:
        ipaddress.ip_address(ip)  # Validate
    except ValueError:
        return None
    
    # Check cache first
    cached = await get_cached_geo(ip)
    if cached is not None:
        return cached
    
    # Mock GeoIP data - replace with real service in production
    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.'):
        # Private IP ranges
        result = {
            "country": "Private Network",
            "region": "Internal",
            "city": "Local",
            "latitude": 0.0,
            "longitude": 0.0,
            "is_private": True
        }
    elif ip == '127.0.0.1':
        result = {
            "country": "Localhost",
            "region": "Local",
            "city": "Localhost",
            "latitude": 0.0,
            "longitude": 0.0,
            "is_localhost": True
        }
    else:
        # Mock public IP data
        # In reality, this would call a GeoIP service like MaxMind or IPinfo.io
        result = {
            "country": "Unknown",
            "region": "Unknown", 
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "is_private": False,
            "is_bogon": ip in ['0.0.0.0', '255.255.255.255']
        }
    
    # Cache the result
    await set_cached_geo(ip, result)
    return result


async def get_asset_info(ip: Optional[str]) -> Optional[str]:
    """Look up asset information for an IP address with caching."""
    if not ip:
        return None
    
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    
    # Check cache first
    cached = await get_cached_asset(ip)
    if cached is not None:
        return cached
    
    # Placeholder asset lookup
    if ip.startswith('192.168.1.'):
        result = f"ASSET-{ip.split('.')[-1]:03d}"
    elif ip.startswith('10.0.'):
        result = f"ASSET-10-{ip.split('.')[-2]}-{ip.split('.')[-1]}"
    elif ip.startswith('172.16.'):
        result = f"ASSET-172-{int(ip.split('.')[2]):02d}-{ip.split('.')[-1]}"
    else:
        # For public IPs, might indicate external asset or threat actor
        # Could be tagged as "EXTERNAL" or left as None
        result = None
    
    # Cache the result
    await set_cached_asset(ip, result)
    return result


def get_user_info(raw_event: dict) -> Optional[str]:
    """Extract user information from the event."""
    user_fields = ['user', 'username', 'user_id', 'src_user', 'dst_user', 'account']
    
    for field in user_fields:
        if field in raw_event and isinstance(raw_event[field], str):
            user_val = raw_event[field].strip()
            if user_val and user_val not in ['', '-', 'N/A', 'NULL', 'null']:
                return user_val
    
    # Check nested structures
    if 'user' in raw_event and isinstance(raw_event['user'], dict):
        user_obj = raw_event['user']
        for field in ['username', 'user_id', 'name']:
            if field in user_obj and isinstance(user_obj[field], str):
                user_val = user_obj[field].strip()
                if user_val and user_val not in ['', '-', 'N/A', 'NULL', 'null']:
                    return user_val
    
    return None


def map_to_mitre_techniques(raw_event: dict, threat_intel: dict) -> tuple[List[str], List[str]]:
    """Map observed behaviors to MITRE ATT&CK tactics and techniques."""
    tactics = []
    techniques = []
    
    # Extract useful information from the event
    event_type = raw_event.get('event_type', '').lower()
    description = raw_event.get('description', '').lower()
    raw_str = str(raw_event).lower()
    
    # Technique mapping based on event characteristics
    
    # Initial Access techniques
    if any(pattern in event_type or pattern in description for pattern in 
           ['ssh', 'brute', 'bruteforce', 'password_spray', 'credential_stuffing']):
        tactics.append("initial-access")
        techniques.extend(["T1078", "T1110"])  # Valid Accounts, Brute Force
    
    if any(pattern in event_type or pattern in description for pattern in 
           ['phishing', 'spearphishing', 'malicious_link']):
        tactics.append("initial-access")
        techniques.append("T1566")  # Phishing
    
    if any(pattern in event_type or pattern in description for pattern in 
           ['exploit', 'vulnerability', 'cve-']):
        tactics.append("initial-access")
        techniques.append("T1190")  # Exploit Public-Facing Application
    
    # Persistence techniques
    if any(pattern in event_type or pattern in description for pattern in 
           ['registry', 'startup', 'scheduled_task', 'cron', 'service']):
        tactics.append("persistence")
        techniques.extend(["T1547", "T1053"])  # Boot/Logon Autostart, Scheduled Task
    
    # Privilege Escalation
    if any(pattern in event_type or pattern in description for pattern in 
           ['privilege', 'escalation', 'sudo', 'su ', 'uac', 'bypass']):
        tactics.append("privilege-escalation")
        techniques.append("T1068")  # Exploitation for Privilege Escalation
    
    # Defense Evasion
    if any(pattern in event_type or pattern in description for pattern in 
           ['obfuscation', 'encoding', 'encryption', 'packed', 'hidden']):
        tactics.append("defense-evasion")
        techniques.append("T1027")  # Obfuscated/Stored Files
    
    if any(pattern in event_type or pattern in description for pattern in 
           ['process_injection', 'dll_injection', 'process_hollowing']):
        tactics.append("defense-evasion", "privilege-escalation")
        techniques.append("T1055")  # Process Injection
    
    # Credential Access
    if any(pattern in event_type or pattern in description for pattern in 
           ['keylog', 'credential', 'password', 'hash', 'token']):
        tactics.append("credential-access")
        techniques.append("T1003")  # OS Credential Dumping
    
    # Discovery
    if any(pattern in event_type or pattern in description for pattern in 
           ['scan', 'enumerate', 'discovery', 'probe', 'query']):
        tactics.append("discovery")
        techniques.append("T1087")  # Account Discovery
    
    if any(pattern in event_type or pattern in description for pattern in 
           ['port_scan', 'network_scan', 'sweep']):
        tactics.append("discovery")
        techniques.append("T1046")  # Network Service Scanning
    
    # Lateral Movement
    if any(pattern in event_type or pattern in description for pattern in 
           ['lateral', 'psexec', 'wmi', 'smb', 'remote_services']):
        tactics.append("lateral-movement")
        techniques.append("T1021")  # Remote Services
    
    # Collection
    if any(pattern in event_type or pattern in description for pattern in 
           ['clipboard', 'screenshot', 'audio_capture', 'webcam']):
        tactics.append("collection")
        techniques.append("T1115")  # Clipboard Data
    
    # Command and Control
    if any(pattern in event_type or pattern in description for pattern in 
           ['beacon', 'callback', 'c2', 'command_and_control']):
        tactics.append("command-and-control")
        techniques.append("T1071")  # Application Layer Protocol
    
    if any(pattern in event_type or pattern in description for pattern in 
           ['dns_tunnel', 'dns_query']):
        tactics.append("command-and-control")
        techniques.append("T1071.004")  # DNS
    
    # Exfiltration
    if any(pattern in event_type or pattern in description for pattern in 
           ['exfil', 'exfiltration', 'data_transfer', 'upload']):
        tactics.append("exfiltration")
        techniques.append("T1041")  # Exfiltration Over C2 Channel
    
    # Impact
    if any(pattern in event_type or pattern in description for pattern in 
           ['ransom', 'encrypt', 'delete', 'wipe', 'destroy']):
        tactics.append("impact")
        techniques.append("T1486")  # Data Encrypted for Impact
    
    # If threat intel indicates malicious IP, add command and control
    ti_score = threat_intel.get('score', 0)
    if ti_score >= 70:  # High threat score
        if "command-and-control" not in tactics:
            tactics.append("command-and-control")
        if "T1071" not in techniques:
            techniques.append("T1071")
    
    # Deduplicate while preserving order
    def deduplicate_list(seq):
        seen = set()
        result = []
        for item in seq:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result
    
    tactics = deduplicate_list(tactics)
    techniques = deduplicate_list(techniques)
    
    return tactics, techniques


def calculate_threat_score(
    raw_event: dict, 
    threat_intel: dict, 
    enrichment_data: dict
) -> int:
    """Calculate a composite threat score (0-100)."""
    score = 0
    
    # Base score from threat intel (0-40 points)
    ti_score = threat_intel.get('score', 0)
    score += min(ti_score * 0.4, 40)  # Max 40 points from TI
    
    # Geographic risk (0-15 points)
    geo_risk = 0
    src_geo = enrichment_data.get('geo', {}).get('source')
    dst_geo = enrichment_data.get('geo', {}).get('destination')
    
    # Higher risk for certain countries or unknown locations
    high_risk_countries = {'XX', 'UNKNOWN', 'UNKNOWN'}  # Would be real country codes
    
    for geo in [src_geo, dst_geo]:
        if geo:
            country = geo.get('country', '').upper()
            if country in high_risk_countries or country == 'UNKNOWN':
                geo_risk += 7
            elif geo.get('is_private') is False and not geo.get('is_localhost'):
                geo_risk += 3  # Some risk for public IPs
    
    score += min(geo_risk, 15)
    
    # Asset criticality (0-15 points)
    asset_risk = 0
    asset_id = enrichment_data.get('asset_id')
    user_id = enrichment_data.get('user_id')
    
    # Critical assets get higher scores
    if asset_id:
        if asset_id.startswith('ASSET-10') or asset_id.startswith('ASSET-172'):
            # Internal infrastructure
            asset_risk += 10
        elif asset_id.startswith('ASSET-192'):
            # End-user devices
            asset_risk += 5
    
    # Privileged users increase risk
    if user_id:
        priv_users = {'admin', 'administrator', 'root', 'sysadmin', 'domain_admin'}
        if any(user in user_id.lower() for user in priv_users):
            asset_risk += 5
    
    score += min(asset_risk, 15)
    
    # MITRE technique risk (0-20 points)
    mitre_risk = 0
    techniques = enrichment_data.get('mitre_techniques', [])
    tactics = enrichment_data.get('mitre_tactics', [])
    
    # High-risk techniques
    high_risk_tech = {
        'T1003', 'T1055', 'T1021', 'T1071', 'T1041', 'T1486', 'T1566.001'
    }
    high_risk_tactics = {'credential-access', 'privilege-escalation', 'lateral-movement', 
                        'command-and-control', 'exfiltration', 'impact'}
    
    for tech in techniques:
        if tech in high_risk_tech:
            mitre_risk += 4
    
    for tac in tactics:
        if tac in high_risk_tactics:
            mitre_risk += 3
    
    score += min(mitre_risk, 20)
    
    # Event type risk (0-10 points)
    event_risk = 0
    event_type = raw_event.get('event_type', '').lower()
    
    high_risk_events = {
        'malware', 'ransomware', 'exploit', 'intrusion', 'data_exfil',
        'privilege_escalation', 'lateral_movement', 'command_control'
    }
    
    if any(risk in event_type for risk in high_risk_events):
        event_risk += 10
    elif 'failed_login' in event_type or 'brute_force' in event_type:
        event_risk += 5
    elif 'scan' in event_type or 'probe' in event_type:
        event_risk += 3
    
    score += min(event_risk, 10)
    
    return min(int(score), 100)


async def enrich(incident: dict, threat_intel: dict) -> dict:
    """Enrich incident with contextual information."""
    raw_event = incident.get('raw_event', {})
    
    # Extract IP addresses
    src_ip, dst_ip = extract_ips_from_raw_event(raw_event)
    
    # Get geo information (with caching)
    src_geo_task = get_geo_info(src_ip)
    dst_geo_task = get_geo_info(dst_ip)
    src_geo, dst_geo = await asyncio.gather(src_geo_task, dst_geo_task)
    
    # Get asset information (with caching)
    asset_task = get_asset_info(src_ip)  # Usually check source asset
    asset_id = await asset_task
    
    # Get user information
    user_id = get_user_info(raw_event)
    
    # Map to MITRE ATT&CK
    mitre_tactics, mitre_techniques = map_to_mitre_techniques(raw_event, threat_intel)
    
    # Prepare enrichment data for threat score calculation
    enrichment_data = {
        'geo': {
            'source': src_geo,
            'destination': dst_geo
        },
        'asset_id': asset_id,
        'user_id': user_id,
        'mitre_tactics': mitre_tactics,
        'mitre_techniques': mitre_techniques
    }
    
    # Calculate threat score
    threat_score = calculate_threat_score(incident, threat_intel, enrichment_data)
    
    # Prepare indicators (additional context)
    indicators = {
        'enrichment_timestamp': __import__('datetime').datetime.now().isoformat(),
        'enrichment_version': '1.0',
        'sources_used': {
            'geoip': bool(src_geo or dst_geo),
            'asset_db': bool(asset_id),
            'user_lookup': bool(user_id),
            'mitre_mapping': bool(mitre_tactics or mitre_techniques)
        }
    }
    
    # Build the final envelope matching NormalizedIncident structure
    envelope = {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "geo": {
            "source": src_geo,
            "destination": dst_geo
        } if (src_geo or dst_geo) else None,
        "asset_id": asset_id,
        "user_id": user_id,
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "threat_score": threat_score,
        "indicators": indicators
    }
    
    return envelope


__all__ = ["enrich"]
