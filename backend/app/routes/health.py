from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from ..config import settings
from ..database import get_session
from ..models import Event
from ..schemas import HealthResponse
from ..services import ollama_client, retrieval

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health(session: Session = Depends(get_session)) -> HealthResponse:
    db_ok = "ok"
    try:
        session.exec(select(Event.id).limit(1)).first()
    except Exception:
        db_ok = "error"

    ollama = await ollama_client.health()
    faiss_ok = retrieval.faiss_available()
    return HealthResponse(
        status="ok",
        ollama_available=ollama["available"],
        ollama_model=settings.ollama_model,
        database=db_ok,
        ocsf_schema_version=settings.ocsf_schema_version,
        faiss_available=faiss_ok,
        retrieval_mode="faiss" if faiss_ok else "keyword",
    )
