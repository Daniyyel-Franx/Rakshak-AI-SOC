"""Database seeding + artifact generation.

Seeds a small benign background of telemetry (so charts are non-empty before
any scenario runs) and writes deterministic artifacts:
  * data/seed_events.jsonl
  * data/sample_io.json  (full scenario input + expected deterministic output)
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, delete

from .config import DATA_DIR
from .database import engine, init_db
from .models import Action, AuditEvent, Event, Finding, Incident, ReplayRun
from .services import graph_builder, ocsf, response_validator, risk_engine, scenario_engine
from .services.normalizer import normalize


def _benign_background() -> list[dict]:
    base = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
    events = []
    users = [("alice", "admin-ws-01"), ("bob", "eng-ws-02"), ("carol", "eng-ws-03")]
    for i in range(9):
        u, host = users[i % len(users)]
        t = (base + timedelta(minutes=i * 3)).isoformat()
        events.append(ocsf.build_authentication(
            event_id=f"BG-AUTH-{i}", time=t, user=u, src_ip=f"10.0.0.{20+i}", src_host=host,
            dst_host="corp-app-01", success=True, severity_id=1, site_id="site-01",
            scenario_id="", asset_criticality="low", network_zone="corp"))
        if i % 3 == 0:
            events.append(ocsf.build_network_activity(
                event_id=f"BG-NET-{i}", time=t, src_ip=f"10.0.0.{20+i}", dst_ip="10.0.1.10",
                dst_port=443, protocol="tcp", bytes_out=2048, bytes_in=8192, duration_ms=80,
                severity_id=1, site_id="site-01", scenario_id="", network_zone="corp"))
    return events


def write_seed_events_file() -> None:
    events = _benign_background()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(DATA_DIR / "seed_events.jsonl", "w") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")


def write_sample_io() -> None:
    events = scenario_engine.build_events("SCENARIO_1_SSH_COMPROMISE")
    result = risk_engine.evaluate(events, "SCENARIO_1_SSH_COMPROMISE")
    incident = result["incident"]
    graph = graph_builder.build_graph(events, incident["incident_id"] if incident else "")
    analysis = response_validator.fallback_analysis(incident, result["findings"])
    sample = {
        "_note": "Synthetic OCSF-compatible input and deterministic expected output. SIMULATION ONLY.",
        "input_events": events,
        "expected_output": {
            "incident_id": incident["incident_id"],
            "threat_score": analysis["threat_score"],
            "confidence": analysis["confidence"],
            "evidence_refs": analysis["evidence_refs"],
            "attack_techniques": analysis["attack_techniques"],
            "graph_node_ids": sorted(n["id"] for n in graph["nodes"]),
            "graph_edge_ids": sorted(e["id"] for e in graph["edges"]),
            "recommended_next_steps": analysis["recommended_next_steps"],
            "missing_evidence": analysis["missing_evidence"],
            "safety_notice": analysis["safety_notice"],
        },
    }
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(DATA_DIR / "sample_io.json", "w") as fh:
        json.dump(sample, fh, indent=2)


def seed_database(with_background: bool = True) -> dict:
    init_db()
    count = 0
    with Session(engine) as session:
        # Re-seeding is intentionally safe and deterministic for local demos.
        # Delete dependent rows before events to satisfy SQLite foreign keys.
        for model in (Action, Incident, Finding, Event, ReplayRun, AuditEvent):
            session.exec(delete(model))
        session.commit()
        if with_background:
            for ev in _benign_background():
                session.add(normalize(ev))
                count += 1
            session.commit()
    return {"seeded_events": count}


def main() -> None:
    init_db()
    write_seed_events_file()
    write_sample_io()
    res = seed_database()
    print(json.dumps({"status": "seeded", **res}, indent=2))


if __name__ == "__main__":
    main()
