"""Tamper-evident audit log (hash-chained).

Each audit record stores the hash of the previous record, forming a chain.
signature_placeholder documents that real cryptographic signing is future
production-hardening work, not implemented in this prototype.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlmodel import Session, desc, select

from ..models import AuditEvent


def _hash(previous_hash: str, payload: dict[str, Any], event_type: str, actor: str) -> str:
    blob = json.dumps(
        {"prev": previous_hash, "type": event_type, "actor": actor, "payload": payload},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode()).hexdigest()


def record(session: Session, event_type: str, payload: dict[str, Any], actor: str = "system") -> AuditEvent:
    last = session.exec(select(AuditEvent).order_by(desc(AuditEvent.id))).first()
    previous_hash = last.event_hash if last else "GENESIS"
    event_hash = _hash(previous_hash, payload, event_type, actor)
    entry = AuditEvent(
        audit_id=f"AUD-{uuid.uuid4().hex[:10]}",
        event_type=event_type,
        actor=actor,
        payload_json=payload,
        previous_hash=previous_hash,
        event_hash=event_hash,
        signature_placeholder="unsigned-prototype",
    )
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry


def verify_chain(session: Session) -> bool:
    rows = session.exec(select(AuditEvent).order_by(AuditEvent.id)).all()
    previous = "GENESIS"
    for r in rows:
        expected = _hash(previous, r.payload_json, r.event_type, r.actor)
        if expected != r.event_hash or r.previous_hash != previous:
            return False
        previous = r.event_hash
    return True
