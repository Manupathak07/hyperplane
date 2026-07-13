"""FastAPI app entrypoint.

Wires:
  - lifespan that disposes the SQLAlchemy engine cleanly on shutdown
  - CORS (open for dev — narrow before any deploy)
  - /docs (Swagger UI) + /redoc
  - /health and /incidents routers
  - WebSocket endpoints for live updates
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db import engine
from app.routes import events, health, incidents, investigate, search
from app.search import close_es, ensure_index
from app.websocket import manager, websocket_endpoint, trace_websocket_endpoint


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure the ES index exists. Idempotent — logs and moves on if ES
    # is unreachable so the rest of the API still works.
    await ensure_index()
    yield
    # Shutdown: dispose the engine and close the ES client cleanly.
    await engine.dispose()
    await close_es()


app = FastAPI(
    title="HyperPlane API",
    description=(
        "Agentic SIEM backend — 6-agent incident investigation pipeline "
        "(Supervisor → Triage → Threat Intel → Enrichment → Detection → Response)."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — open for local dev. Lock down for any real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(incidents.router)
app.include_router(events.router)
app.include_router(search.router)
app.include_router(investigate.router)


# WebSocket endpoints
@app.websocket("/ws/events/")
async def websocket_endpoint_route(websocket: WebSocket):
    """WebSocket endpoint for live event streaming."""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo back or handle client messages if needed
            await websocket.send_text(f"Echo: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.websocket("/ws/trace/{incident_id}")
async def trace_websocket_endpoint_route(websocket: WebSocket, incident_id: str):
    """WebSocket endpoint for streaming trace data for a specific incident."""
    await manager.connect_to_trace(websocket, incident_id)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo back or handle client messages if needed
            await websocket.send_text(f"Trace echo: {data}")
    except WebSocketDisconnect:
        manager.disconnect_from_trace(websocket, incident_id)


@app.get("/", tags=["meta"])
async def root() -> dict:
    return {
        "service": "HyperPlane",
        "environment": settings.environment,
        "docs": "/docs",
    }
