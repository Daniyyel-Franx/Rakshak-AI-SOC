"""Pydantic v2 response/request models for the API contract."""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

RiskClass = Literal["R0", "R1", "R2", "R3"]


# ----------------------------- Health -----------------------------
class HealthResponse(BaseModel):
    status: str = "ok"
    ollama_available: bool = False
    ollama_model: str
    database: str = "ok"
    ocsf_schema_version: str
    faiss_available: bool = False
    retrieval_mode: str = "keyword"


# ----------------------------- Telemetry -----------------------------
class TelemetryEvent(BaseModel):
    event_id: str
    event_time: str
    received_time: str
    site_id: str
    event_class: str
    activity_id: int
    type_uid: int
    severity_id: int
    status_id: int
    action: str
    source: dict[str, Any] = Field(default_factory=dict)
    destination: dict[str, Any] = Field(default_factory=dict)
    user: dict[str, Any] = Field(default_factory=dict)
    device: dict[str, Any] = Field(default_factory=dict)
    process: dict[str, Any] = Field(default_factory=dict)
    unmapped: dict[str, Any] = Field(default_factory=dict)
    classification: str
    priority: int
    message: str = ""


class TelemetryPage(BaseModel):
    items: list[TelemetryEvent]
    next_cursor: Optional[str] = None
    total: int


# ----------------------------- Scenarios -----------------------------
class ScenarioSummary(BaseModel):
    scenario_id: str
    name: str
    description: str
    severity: str
    ground_truth_nodes: int
    ground_truth_edges: int
    benign: bool = False


class ReplayResponse(BaseModel):
    run_id: str
    scenario_id: str
    status: str
    events_ingested: int = 0
    duplicates_skipped: int = 0
    incident_id: Optional[str] = None
    queued: bool = False


# ----------------------------- Graph -----------------------------
class GraphNode(BaseModel):
    id: str
    type: str
    data: dict[str, Any]
    position: dict[str, float] = Field(default_factory=lambda: {"x": 0.0, "y": 0.0})


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str = ""
    timestamp: str = ""
    technique_id: str = ""
    technique_name: str = ""
    evidence_event_ids: list[str] = Field(default_factory=list)
    severity: str = "low"
    animated: bool = False
    # Sigma match evidence: field-path -> matched-value dict populated when
    # technique_id originates from SigmaEngine (absent for hardcoded edges).
    evidence: dict[str, Any] = Field(default_factory=dict)


class GraphResponse(BaseModel):
    incident_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]


# ----------------------------- Incidents -----------------------------
class IncidentSummary(BaseModel):
    incident_id: str
    title: str
    status: str
    risk_score: float
    confidence: float
    mission_impact: str
    scenario_id: str
    finding_count: int
    created_at: str


class IncidentDetail(IncidentSummary):
    entity_ids: list[str]
    finding_ids: list[str]
    timeline: list[dict[str, Any]]
    evidence_refs: list[str]
    recommended_actions: list[dict[str, Any]]
    graph: dict[str, Any]
    analysis: dict[str, Any]


# ----------------------------- Metrics -----------------------------
class MetricsSummary(BaseModel):
    total_events: int
    active_incidents: int
    critical_incidents: int
    average_risk: float
    events_per_minute: float
    queued_offline_events: int
    severity_counts: dict[str, int]
    events_by_class: dict[str, int]
    techniques: dict[str, int]
    risk_distribution: list[dict[str, Any]]
    event_rate_timeseries: list[dict[str, Any]]
    top_entities: list[dict[str, Any]]
    incident_status: dict[str, int]
    cross_site_campaigns: list[dict[str, Any]]


# ----------------------------- AI Analysis -----------------------------
class AttackTechnique(BaseModel):
    id: str
    name: str
    tactic: str
    confidence: float
    evidence_refs: list[str]


class RecommendedStep(BaseModel):
    action: str
    risk_class: RiskClass
    requires_approval: bool


class AnalysisResult(BaseModel):
    incident_id: str
    assessment: str
    threat_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_refs: list[str]
    attack_techniques: list[AttackTechnique]
    attack_path_summary: str
    recommended_next_steps: list[RecommendedStep]
    missing_evidence: list[str]
    safety_notice: str
    analysis_source: str = "ollama"  # or rule_engine_fallback


# ----------------------------- Actions -----------------------------
ALLOWED_ACTIONS = [
    "simulate_isolate_endpoint",
    "simulate_revoke_session",
    "activate_decoy",
    "collect_mock_evidence",
    "create_case",
]


class SimulateActionRequest(BaseModel):
    incident_id: str
    action_type: str
    target: str = ""
    approved_by: str = "analyst"


class SimulateActionResponse(BaseModel):
    action_id: str
    incident_id: str
    action_type: str
    target: str
    policy_risk_class: RiskClass
    approval_state: str
    result: str
    rollback_data: dict[str, Any]
    simulation_only: bool = True
