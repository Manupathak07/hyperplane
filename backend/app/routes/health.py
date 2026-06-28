"""Healthcheck endpoint — pings Postgres so the dashboard can show green."""
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session

router = APIRouter(tags=["health"])


@router.get("/health")
async def health(session: AsyncSession = Depends(get_session)) -> dict:
    db_status = "down"
    try:
        result = await session.execute(text("SELECT 1"))
        if result.scalar() == 1:
            db_status = "up"
    except Exception:
        pass

    overall = "ok" if db_status == "up" else "degraded"
    return {
        "status": overall,
        "service": "hyperplane-backend",
        "database": db_status,
    }
