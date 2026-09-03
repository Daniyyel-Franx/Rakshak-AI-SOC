"""Deterministic normalisation of OCSF-compatible events into DB rows.

Given the same input event, this always produces the same Event row and the
same fingerprint. No randomness, no wall-clock reads for identity fields.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from ..models import Event
from . import ocsf


def _severity_priority(severity_id: int) -> int:
    # OCSF severity_id 1..6 -> priority 1..5
    return max(1, min(5, severity_id))


def compute_fingerprint(ev: dict[str, Any]) -> str:
    """Stable content fingerprint used for deduplication.

    Uses class + time + core identity fields, NOT event_id, so that the same
    logical event replayed twice collapses to one row.
    """
    key = {
        "class": ev.get("event_class") or ocsf.CLASS_NAME.get(ev.get("class_uid", 0), "unknown"),
        "time": ev.get("time") or ev.get("event_time"),
        "user": (ev.get("user") or {}).get("name"),
        "src": (ev.get("src_endpoint") or {}).get("ip") or (ev.get("src_endpoint") or {}).get("hostname"),
        "dst": (ev.get("dst_endpoint") or {}).get("ip") or (ev.get("dst_endpoint") or {}).get("hostname")
               or (ev.get("device") or {}).get("hostname"),
        "proc": (ev.get("process") or {}).get("cmd_line"),
        "file": (ev.get("file") or {}).get("path"),
        "type_uid": ev.get("type_uid"),
        "site": ev.get("site_id") or (ev.get("unmapped") or {}).get("site_id"),
    }
    blob = json.dumps(key, sort_keys=True, separators=(",", ":"))
    return "fp_" + hashlib.sha256(blob.encode()).hexdigest()[:24]


def normalize(ev: dict[str, Any], received_time: str | None = None) -> Event:
    """Convert an OCSF-compatible dict into an Event ORM object."""
    unmapped = dict(ev.get("unmapped") or {})
    event_class = ev.get("event_class") or ocsf.CLASS_NAME.get(ev.get("class_uid", 0), "unknown")
    site_id = ev.get("site_id") or unmapped.get("site_id") or "site-unknown"
    event_time = ev.get("time") or ev.get("event_time")
    if not event_time:
        raise ValueError("event missing time")

    recv = received_time or datetime.now(timezone.utc).isoformat()
    severity_id = int(ev.get("severity_id", 1))

    return Event(
        event_id=ev["event_id"],
        event_time=event_time,
        received_time=recv,
        site_id=site_id,
        event_class=event_class,
        activity_id=int(ev.get("activity_id", 0)),
        type_uid=int(ev.get("type_uid", 0)),
        severity_id=severity_id,
        status_id=int(ev.get("status_id", 1)),
        action=ev.get("action", "observed"),
        source_json=ev.get("src_endpoint") or {},
        destination_json=ev.get("dst_endpoint") or {},
        user_json=ev.get("user") or {},
        device_json=ev.get("device") or {},
        process_json=ev.get("process") or {},
        unmapped_json=unmapped,
        classification=unmapped.get("classification", "unclassified"),
        fingerprint=compute_fingerprint(ev),
        priority=_severity_priority(severity_id),
    )


def to_telemetry_dict(row: Event) -> dict[str, Any]:
    """Serialise an Event row for the API telemetry response."""
    return {
        "event_id": row.event_id,
        "event_time": row.event_time,
        "received_time": row.received_time,
        "site_id": row.site_id,
        "event_class": row.event_class,
        "activity_id": row.activity_id,
        "type_uid": row.type_uid,
        "severity_id": row.severity_id,
        "status_id": row.status_id,
        "action": row.action,
        "source": row.source_json,
        "destination": row.destination_json,
        "user": row.user_json,
        "device": row.device_json,
        "process": row.process_json,
        "unmapped": row.unmapped_json,
        "classification": row.classification,
        "priority": row.priority,
        "message": row.unmapped_json.get("message", "") if isinstance(row.unmapped_json, dict) else "",
    }
