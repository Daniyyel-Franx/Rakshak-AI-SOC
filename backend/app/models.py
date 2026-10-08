"""SQLModel ORM table definitions for the Rakshak-AI prototype.

JSON-typed columns store structured OCSF sub-objects and prototype extensions.
All timestamps are stored as ISO-8601 strings for deterministic replay.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import Column
from sqlalchemy.types import JSON
from sqlmodel import Field, SQLModel


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Event(SQLModel, table=True):
    __tablename__ = "events"

    id: Optional[int] = Field(default=None, primary_key=True)
    event_id: str = Field(index=True, unique=True)
    event_time: str = Field(index=True)
    received_time: str = Field(index=True)
    site_id: str = Field(index=True)
    event_class: str = Field(index=True)   # e.g. authentication, network_activity
    activity_id: int = 0
    type_uid: int = 0
    severity_id: int = 1
    status_id: int = 1
    action: str = "observed"
    source_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    destination_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    user_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    device_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    process_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    unmapped_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    classification: str = "unclassified"
    fingerprint: str = Field(index=True)
    priority: int = 1
    source: str = Field(default="demo", index=True)
    created_at: str = Field(default_factory=_now)


class Feature(SQLModel, table=True):
    __tablename__ = "features"

    id: Optional[int] = Field(default=None, primary_key=True)
    identity: str = Field(index=True)
    identity_type: str = "user"
    window_start: str = ""
    window_end: str = ""
    feature_version: str = "1.0"
    features_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    source_event_ids_json: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: str = Field(default_factory=_now)


class Finding(SQLModel, table=True):
    __tablename__ = "findings"

    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: str = Field(index=True, unique=True)
    rule_id: str = Field(index=True)
    title: str = ""
    severity: str = "low"
    attack_techniques_json: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    evidence_event_ids_json: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    anomaly_score: float = 0.0
    sequence_score: float = 0.0
    graph_score: float = 0.0
    deception_score: float = 0.0
    created_at: str = Field(default_factory=_now)


class Incident(SQLModel, table=True):
    __tablename__ = "incidents"

    id: Optional[int] = Field(default=None, primary_key=True)
    incident_id: str = Field(index=True, unique=True)
    title: str = ""
    status: str = "open"
    risk_score: float = 0.0
    confidence: float = 0.0
    mission_impact: str = "unknown"
    entity_ids_json: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    finding_ids_json: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    graph_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    timeline_json: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    evidence_refs_json: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    recommended_actions_json: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    analysis_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    scenario_id: str = Field(default="", index=True)
    source: str = Field(default="demo", index=True)
    created_at: str = Field(default_factory=_now)
    updated_at: str = Field(default_factory=_now)


class Action(SQLModel, table=True):
    __tablename__ = "actions"

    id: Optional[int] = Field(default=None, primary_key=True)
    action_id: str = Field(index=True, unique=True)
    incident_id: str = Field(index=True)
    action_type: str = ""
    target: str = ""
    approval_state: str = "pending"
    approved_by: str = ""
    result: str = ""
    rollback_data_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: str = Field(default_factory=_now)


class AuditEvent(SQLModel, table=True):
    __tablename__ = "audit_events"

    id: Optional[int] = Field(default=None, primary_key=True)
    audit_id: str = Field(index=True, unique=True)
    event_type: str = ""
    actor: str = "system"
    payload_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    previous_hash: str = ""
    event_hash: str = ""
    signature_placeholder: str = "unsigned-prototype"
    created_at: str = Field(default_factory=_now)


class ReplayRun(SQLModel, table=True):
    """Tracks scenario replay runs for offline queueing / dedup accounting."""
    __tablename__ = "replay_runs"

    id: Optional[int] = Field(default=None, primary_key=True)
    run_id: str = Field(index=True, unique=True)
    scenario_id: str = Field(index=True)
    status: str = "started"
    queued: bool = False   # produced while link was down
    replayed: bool = False
    event_count: int = 0
    duplicate_count: int = 0
    created_at: str = Field(default_factory=_now)
