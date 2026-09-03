from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, delete

from ..database import get_session
from ..models import Action, AuditEvent, Event, Finding, Incident, ReplayRun
from ..schemas import ReplayResponse, ScenarioSummary
from ..services import pipeline, scenario_engine

router = APIRouter(prefix="/api", tags=["scenarios"])


@router.get("/scenarios", response_model=list[ScenarioSummary])
def list_scenarios() -> list[ScenarioSummary]:
    return [ScenarioSummary(**s) for s in scenario_engine.list_scenarios()]


@router.post("/scenarios/{scenario_id}/replay", response_model=ReplayResponse)
def replay(scenario_id: str, session: Session = Depends(get_session)) -> ReplayResponse:
    try:
        events = scenario_engine.build_events(scenario_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown scenario {scenario_id}")

    run_id = f"RUN-{uuid.uuid4().hex[:10]}"
    if scenario_engine.is_campaign(scenario_id):
        res = pipeline.correlate_campaign(session, events, scenario_id)
    else:
        res = pipeline.ingest_events(session, events, scenario_id=scenario_id, source="live")

    session.add(ReplayRun(
        run_id=run_id, scenario_id=scenario_id,
        status="queued" if res.get("queued") else "completed",
        queued=res.get("queued", False), replayed=True,
        event_count=res.get("ingested", 0), duplicate_count=res.get("duplicates", 0),
    ))
    session.commit()

    return ReplayResponse(
        run_id=run_id, scenario_id=scenario_id,
        status="queued" if res.get("queued") else "started",
        events_ingested=res.get("ingested", 0),
        duplicates_skipped=res.get("duplicates", 0),
        incident_id=res.get("incident_id"),
        queued=res.get("queued", False),
    )


@router.post("/scenarios/link/down")
def link_down() -> dict:
    pipeline.set_link_down()
    return pipeline.link_status()


@router.post("/scenarios/link/restore")
def link_restore(session: Session = Depends(get_session)) -> dict:
    return pipeline.restore_link(session)


@router.get("/scenarios/link/status")
def link_status() -> dict:
    return pipeline.link_status()


@router.post("/scenarios/clear")
def clear_demo(session: Session = Depends(get_session)) -> dict:
    for model in (Action, Incident, Finding, Event, ReplayRun, AuditEvent):
        session.exec(delete(model))
    session.commit()
    return {"status": "cleared"}
