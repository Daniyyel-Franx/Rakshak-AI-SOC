from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from ..database import get_session
from ..models import Incident
from ..schemas import GraphEdge, GraphNode, GraphResponse

router = APIRouter(prefix="/api", tags=["graph"])


@router.get("/incidents/{incident_id}/graph", response_model=GraphResponse)
def incident_graph(incident_id: str, session: Session = Depends(get_session)) -> GraphResponse:
    inc = session.exec(select(Incident).where(Incident.incident_id == incident_id)).first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")
    graph = inc.graph_json or {"nodes": [], "edges": []}
    return GraphResponse(
        incident_id=incident_id,
        nodes=[GraphNode(**n) for n in graph.get("nodes", [])],
        edges=[GraphEdge(**e) for e in graph.get("edges", [])],
    )
