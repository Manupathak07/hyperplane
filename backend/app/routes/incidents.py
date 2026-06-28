"""Incident CRUD endpoints — used by the React dashboard and external ingesters."""
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db import get_session
from app.models import Incident
from app.schemas import IncidentCreate, IncidentDetail, IncidentRead

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.post("/", response_model=IncidentRead, status_code=201)
async def create_incident(
    payload: IncidentCreate,
    session: AsyncSession = Depends(get_session),
) -> Incident:
    incident = Incident(**payload.model_dump())
    session.add(incident)
    await session.commit()
    await session.refresh(incident)
    return incident


@router.get("/", response_model=list[IncidentRead])
async def list_incidents(
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
) -> list[Incident]:
    stmt = (
        select(Incident)
        .order_by(Incident.created_at.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> Incident:
    stmt = (
        select(Incident)
        .where(Incident.id == incident_id)
        .options(
            selectinload(Incident.traces),
            selectinload(Incident.normalized),
        )
    )
    result = await session.execute(stmt)
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
