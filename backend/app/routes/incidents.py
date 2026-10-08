from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, desc, select

from ..database import get_session
from ..models import Incident
from ..schemas import IncidentDetail, IncidentSummary

router = APIRouter(prefix="/api", tags=["incidents"])


def _summary(inc: Incident) -> IncidentSummary:
    return IncidentSummary(
        incident_id=inc.incident_id, title=inc.title, status=inc.status,
        risk_score=inc.risk_score, confidence=inc.confidence,
        mission_impact=inc.mission_impact, scenario_id=inc.scenario_id,
        finding_count=len(inc.finding_ids_json or []), created_at=inc.created_at,
        source=getattr(inc, "source", "demo"),
    )


@router.get("/incidents", response_model=list[IncidentSummary])
def list_incidents(session: Session = Depends(get_session)) -> list[IncidentSummary]:
    rows = session.exec(select(Incident).order_by(desc(Incident.risk_score))).all()
    return [_summary(r) for r in rows]


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: str, session: Session = Depends(get_session)) -> IncidentDetail:
    inc = session.exec(select(Incident).where(Incident.incident_id == incident_id)).first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")
    return IncidentDetail(
        **_summary(inc).model_dump(),
        entity_ids=inc.entity_ids_json or [],
        finding_ids=inc.finding_ids_json or [],
        timeline=inc.timeline_json or [],
        evidence_refs=inc.evidence_refs_json or [],
        recommended_actions=inc.recommended_actions_json or [],
        graph=inc.graph_json or {},
        analysis=inc.analysis_json or {},
    )
