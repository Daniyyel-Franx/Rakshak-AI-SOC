"""Deduplication for ingestion and replay.

Two guards:
  1. event_id uniqueness (idempotent replay).
  2. content fingerprint uniqueness (collapses re-emitted identical events).

Used both for direct ingest and for replaying queued offline events without
creating duplicates.
"""
from __future__ import annotations

from sqlmodel import Session, select

from ..models import Event


def existing_ids(session: Session, event_ids: list[str], source: str) -> set[str]:
    if not event_ids:
        return set()
    rows = session.exec(select(Event.event_id).where(Event.event_id.in_(event_ids), Event.source == source)).all()
    return set(rows)


def existing_fingerprints(session: Session, fingerprints: list[str], source: str) -> set[str]:
    if not fingerprints:
        return set()
    rows = session.exec(select(Event.fingerprint).where(Event.fingerprint.in_(fingerprints), Event.source == source)).all()
    return set(rows)


def is_duplicate(session: Session, event_id: str, fingerprint: str, source: str) -> bool:
    hit = session.exec(
        select(Event.id).where(
            ((Event.event_id == event_id) | (Event.fingerprint == fingerprint)) & 
            (Event.source == source)
        )
    ).first()
    return hit is not None
