"""FastAPI app entrypoint.

Wires:
  - lifespan that disposes the SQLAlchemy engine cleanly on shutdown
  - CORS (open for dev — narrow before any deploy)
  - /docs (Swagger UI) + /redoc
  - /health and /incidents routers
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db import engine
from app.routes import events, health, incidents, search
from app.search import close_es, ensure_index


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


@app.get("/", tags=["meta"])
async def root() -> dict:
    return {
        "service": "HyperPlane",
        "environment": settings.environment,
        "docs": "/docs",
    }
