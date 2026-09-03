from __future__ import annotations

import asyncio
import json
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlmodel import Session, desc, select

from ..database import get_session
from ..models import Event
from ..schemas import TelemetryEvent, TelemetryPage
from ..services.normalizer import to_telemetry_dict

router = APIRouter(prefix="/api", tags=["telemetry"])


@router.get("/telemetry", response_model=TelemetryPage)
def telemetry(
    limit: int = Query(100, ge=1, le=500),
    cursor: Optional[int] = Query(None, description="return events with id < cursor"),
    session: Session = Depends(get_session),
) -> TelemetryPage:
    stmt = select(Event).order_by(desc(Event.id))
    if cursor is not None:
        stmt = stmt.where(Event.id < cursor)
    rows = session.exec(stmt.limit(limit)).all()
    total = session.exec(select(Event.id)).all()
    items = [TelemetryEvent(**to_telemetry_dict(r)) for r in rows]
    next_cursor = str(rows[-1].id) if len(rows) == limit and rows else None
    return TelemetryPage(items=items, next_cursor=next_cursor, total=len(total))


@router.get("/stream/telemetry")
async def stream_telemetry(session: Session = Depends(get_session)) -> StreamingResponse:
    """Server-Sent Events stream. Each message is valid JSON.

    Sends the most recent events, then polls for newer ones. Clients dedupe by
    event_id on reconnect (each message carries a stable SSE id).
    """
    async def event_gen():
        last_id = 0
        # initial backlog (most recent 25, chronological)
        with Session(session.bind) as s:
            rows = list(reversed(s.exec(select(Event).order_by(desc(Event.id)).limit(25)).all()))
        for r in rows:
            last_id = max(last_id, r.id or 0)
            payload = json.dumps(to_telemetry_dict(r))
            yield f"id: {r.event_id}\nevent: telemetry\ndata: {payload}\n\n"
        # live tail
        for _ in range(600):  # ~5 min at 0.5s cadence, then client reconnects
            await asyncio.sleep(0.5)
            with Session(session.bind) as s:
                new_rows = s.exec(
                    select(Event).where(Event.id > last_id).order_by(Event.id).limit(50)
                ).all()
            for r in new_rows:
                last_id = max(last_id, r.id or 0)
                payload = json.dumps(to_telemetry_dict(r))
                yield f"id: {r.event_id}\nevent: telemetry\ndata: {payload}\n\n"
            yield ": keep-alive\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
