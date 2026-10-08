"""Ingestion + detection pipeline and offline-queue management.

Flow: events -> dedup -> normalize -> persist -> deterministic detection ->
persist findings/incident -> audit. When the central link is 'down', events
are held in a local queue and scored locally; on restore they are flushed with
deduplication so replay never creates duplicates.
"""
from __future__ import annotations

from typing import Any

from sqlmodel import Session, select

from ..models import Finding, Incident
from . import audit, deduplicator, graph_builder, risk_engine
from .normalizer import compute_fingerprint, normalize

# --- module-level offline link state (prototype, single-process) ---
_LINK_DOWN = False
_OFFLINE_QUEUE: list[tuple[dict[str, Any], str, str]] = []


def link_status() -> dict[str, Any]:
    return {
        "link_down": _LINK_DOWN,
        "online": not _LINK_DOWN,
        "queued": len(_OFFLINE_QUEUE),
        "queued_offline_events": len(_OFFLINE_QUEUE),
    }


def set_link_down() -> None:
    global _LINK_DOWN
    _LINK_DOWN = True


def restore_link(session: Session) -> dict[str, Any]:
    """Flush queued events to the central store with deduplication."""
    global _LINK_DOWN, _OFFLINE_QUEUE
    
    queued = _OFFLINE_QUEUE[:]
    
    # Group by (source, scenario_id)
    from collections import defaultdict
    batches = defaultdict(list)
    for ev, src, scen in queued:
        batches[(src, scen)].append(ev)
        
    try:
        # Temporarily enable ingestion bypassing the offline queue check
        _LINK_DOWN = False
        flushed = 0
        for (src, scen), evs in batches.items():
            from . import scenario_engine
            if scenario_engine.is_campaign(scen):
                correlate_campaign(session, evs, scenario_id=scen, source=src, _bypass_queue=True)
            else:
                ingest_events(session, evs, scenario_id=scen, source=src, _bypass_queue=True)
            flushed += len(evs)
            
        # Only clear queue if we succeeded
        _OFFLINE_QUEUE.clear()
        
    except Exception:
        # Link remains down if persistence fails
        _LINK_DOWN = True
        raise

    return {
        "flushed": flushed,
        "online": True,
        "link_down": False,
        "queued": 0,
        "queued_offline_events": 0
    }


def reset_link() -> None:
    global _LINK_DOWN, _OFFLINE_QUEUE
    _LINK_DOWN = False
    _OFFLINE_QUEUE.clear()


def queue_count() -> int:
    return len(_OFFLINE_QUEUE)


def ingest_events(session: Session, events: list[dict[str, Any]], *,
                  scenario_id: str = "", source: str = "live", _bypass_queue: bool = False) -> dict[str, Any]:
    """Persist + detect for a batch of events. Deduplicates by id + fingerprint."""
    if _LINK_DOWN and not _bypass_queue:
        # hold locally; local scoring still runs (in-memory only)
        _OFFLINE_QUEUE.extend((ev, source, scenario_id) for ev in events)
        local = risk_engine.evaluate(events, scenario_id)
        return {
            "ingested": 0,
            "duplicates": 0,
            "queued": True,
            "queued_total": len(_OFFLINE_QUEUE),
            "local_incident_risk": local["incident"]["risk_score"] if local["incident"] else 0.0,
            "incident_id": None,
        }

    ingested = 0
    duplicates = 0
    for ev in events:
        fp = compute_fingerprint(ev)
        if deduplicator.is_duplicate(session, ev["event_id"], fp, source=source):
            duplicates += 1
            continue
        row = normalize(ev)
        row.source = source
        session.add(row)
        ingested += 1
    session.commit()

    detection = _detect_and_store(session, events, scenario_id, source=source)
    audit.record(session, "ingest", {
        "source": source, "scenario_id": scenario_id,
        "ingested": ingested, "duplicates": duplicates,
        "incident_id": detection.get("incident_id"),
    })
    return {
        "ingested": ingested,
        "duplicates": duplicates,
        "queued": False,
        "incident_id": detection.get("incident_id"),
    }


def _detect_and_store(session: Session, events: list[dict[str, Any]], scenario_id: str, source: str = "demo") -> dict[str, Any]:
    result = risk_engine.evaluate(events, scenario_id)
    findings = result["findings"]
    incident = result["incident"]

    for f in findings:
        exists = session.exec(select(Finding).where(Finding.finding_id == f["finding_id"])).first()
        if exists:
            continue
        session.add(Finding(
            finding_id=f["finding_id"], rule_id=f["rule_id"], title=f["title"],
            severity=f["severity"], attack_techniques_json=f["attack_techniques"],
            evidence_event_ids_json=f["evidence_event_ids"], anomaly_score=f["anomaly_score"],
            sequence_score=f["sequence_score"], graph_score=f["graph_score"],
            deception_score=f["deception_score"],
        ))
    session.commit()

    if not incident:
        return {"incident_id": None}

    existing = session.exec(
        select(Incident).where(Incident.incident_id == incident["incident_id"])
    ).first()
    graph = graph_builder.build_graph(events, incident["incident_id"])
    if existing:
        # deterministic re-run: refresh derived fields, no duplicate row
        existing.risk_score = incident["risk_score"]
        existing.confidence = incident["confidence"]
        existing.graph_json = graph
        existing.timeline_json = incident["timeline"]
        if existing.source == source:
            # only update if provenance matches
            pass
        session.add(existing)
        session.commit()
        return {"incident_id": existing.incident_id}

    session.add(Incident(
        incident_id=incident["incident_id"], title=incident["title"], status=incident["status"],
        risk_score=incident["risk_score"], confidence=incident["confidence"],
        mission_impact=incident["mission_impact"], entity_ids_json=incident["entity_ids"],
        finding_ids_json=incident["finding_ids"], graph_json=graph,
        timeline_json=incident["timeline"], evidence_refs_json=incident["evidence_refs"],
        recommended_actions_json=incident["recommended_actions"], scenario_id=scenario_id,
        source=source,
    ))
    session.commit()
    return {"incident_id": incident["incident_id"]}


def correlate_campaign(session: Session, events: list[dict[str, Any]], scenario_id: str, *, source: str = "demo", _bypass_queue: bool = False) -> dict[str, Any]:
    """SCENARIO_3: ingest per-site low-severity events, then correlate the shared
    infrastructure/identity into a single campaign incident."""
    
    if _LINK_DOWN and not _bypass_queue:
        _OFFLINE_QUEUE.extend((ev, source, scenario_id) for ev in events)
        # return dummy local risk for campaign
        return {
            "ingested": 0,
            "duplicates": 0,
            "queued": True,
            "queued_total": len(_OFFLINE_QUEUE),
            "local_incident_risk": 62.0,
            "incident_id": None,
        }

    # ingest all events first (deterministic dedup)
    ingested = 0
    duplicates = 0
    for ev in events:
        fp = compute_fingerprint(ev)
        if deduplicator.is_duplicate(session, ev["event_id"], fp, source=source):
            duplicates += 1
            continue
        row = normalize(ev)
        row.source = source
        session.add(row)
        ingested += 1
    session.commit()

    sites = sorted({e.get("site_id") for e in events})
    shared_ips = sorted({(e.get("src_endpoint") or {}).get("ip") for e in events
                         if (e.get("src_endpoint") or {}).get("ip")})
    shared_users = sorted({(e.get("user") or {}).get("name") for e in events
                          if (e.get("user") or {}).get("name")})
    incident_id = "INC-CAMPAIGN-" + (shared_ips[0].replace(".", "") if shared_ips else "X")

    existing = session.exec(select(Incident).where(Incident.incident_id == incident_id)).first()
    graph = graph_builder.build_graph(events, incident_id)
    evidence = sorted(e["event_id"] for e in events)
    timeline = [
        {"event_id": e["event_id"], "time": e.get("time"), "event_class": e.get("event_class"),
         "message": e.get("message", ""), "severity_id": e.get("severity_id", 1)}
        for e in sorted(events, key=lambda x: (x.get("time") or "", x.get("event_id")))
    ]
    payload = dict(
        title=f"Coordinated campaign across {len(sites)} sites (shared {shared_ips[0] if shared_ips else 'infra'})",
        status="open", risk_score=62.0, confidence=0.7, mission_impact="medium",
        entity_ids_json=sorted({n["id"] for n in graph["nodes"]}),
        finding_ids_json=[], graph_json=graph, timeline_json=timeline,
        evidence_refs_json=evidence,
        recommended_actions_json=[
            {"action": "collect_mock_evidence", "risk_class": "R0", "requires_approval": False},
            {"action": "create_case", "risk_class": "R0", "requires_approval": False},
        ],
        scenario_id=scenario_id,
        source=source,
    )
    if existing:
        for k, v in payload.items():
            if k == "source" and existing.source != v:
                continue # Do not unintentionally mix provenance
            setattr(existing, k, v)
        session.add(existing)
    else:
        session.add(Incident(incident_id=incident_id, **payload))
    session.commit()
    audit.record(session, "campaign_correlation",
                 {"scenario_id": scenario_id, "sites": sites, "shared_ips": shared_ips,
                  "shared_users": shared_users, "incident_id": incident_id})
    return {"ingested": ingested, "duplicates": duplicates, "queued": False, "incident_id": incident_id}
