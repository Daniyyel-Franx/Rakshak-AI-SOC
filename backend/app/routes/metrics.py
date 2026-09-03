from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from ..database import get_session
from ..models import Event, Finding, Incident
from ..schemas import MetricsSummary
from ..services import pipeline

router = APIRouter(prefix="/api", tags=["metrics"])

SEV_NAME = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical"}


@router.get("/metrics/summary", response_model=MetricsSummary)
def summary(session: Session = Depends(get_session)) -> MetricsSummary:
    events = session.exec(select(Event)).all()
    incidents = session.exec(select(Incident)).all()
    findings = session.exec(select(Finding)).all()

    severity_counts: Counter = Counter()
    events_by_class: Counter = Counter()
    rate_buckets: dict[str, int] = defaultdict(int)
    entity_risk: dict[str, float] = defaultdict(float)

    for e in events:
        severity_counts[SEV_NAME.get(e.severity_id, "low")] += 1
        events_by_class[e.event_class] += 1
        # per-minute bucket
        try:
            dt = datetime.fromisoformat(e.event_time.replace("Z", "+00:00"))
            rate_buckets[dt.strftime("%Y-%m-%dT%H:%M")] += 1
        except Exception:
            pass
        user = (e.user_json or {}).get("name")
        if user:
            entity_risk[f"user:{user}"] += e.severity_id
        src_ip = (e.source_json or {}).get("ip")
        if src_ip:
            entity_risk[f"ip:{src_ip}"] += e.severity_id

    techniques: Counter = Counter()
    for f in findings:
        for t in (f.attack_techniques_json or []):
            techniques[t.get("id", "?")] += 1

    active = [i for i in incidents if i.status == "open"]
    critical = [i for i in incidents if i.risk_score >= 85 or i.mission_impact == "high"]
    avg_risk = round(sum(i.risk_score for i in incidents) / len(incidents), 1) if incidents else 0.0

    # risk histogram buckets
    hist = Counter()
    for i in incidents:
        bucket = min(90, int(i.risk_score // 10) * 10)
        hist[bucket] += 1
    risk_distribution = [{"bucket": f"{b}-{b+10}", "count": hist[b]} for b in range(0, 100, 10)]

    event_rate = [{"minute": k, "count": v} for k, v in sorted(rate_buckets.items())]
    epm = round(len(events) / max(1, len(rate_buckets)), 2) if rate_buckets else 0.0

    top_entities = sorted(
        ({"entity": k, "risk": round(v, 1)} for k, v in entity_risk.items()),
        key=lambda x: -x["risk"],
    )[:8]

    incident_status: Counter = Counter(i.status for i in incidents)

    campaigns = [
        {"incident_id": i.incident_id, "title": i.title, "risk_score": i.risk_score,
         "sites": sorted({eid.split(":")[1] for eid in (i.entity_ids_json or []) if eid.startswith("site:")})}
        for i in incidents if i.scenario_id == "SCENARIO_3_COORDINATED_CAMPAIGN"
    ]

    return MetricsSummary(
        total_events=len(events),
        active_incidents=len(active),
        critical_incidents=len(critical),
        average_risk=avg_risk,
        events_per_minute=epm,
        queued_offline_events=pipeline.queue_count(),
        severity_counts=dict(severity_counts),
        events_by_class=dict(events_by_class),
        techniques=dict(techniques),
        risk_distribution=risk_distribution,
        event_rate_timeseries=event_rate,
        top_entities=top_entities,
        incident_status=dict(incident_status),
        cross_site_campaigns=campaigns,
    )
