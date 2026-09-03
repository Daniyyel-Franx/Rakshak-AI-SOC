def test_replay_dedup(client):
    client.post("/api/scenarios/clear")
    r1 = client.post("/api/scenarios/SCENARIO_1_SSH_COMPROMISE/replay").json()
    assert r1["events_ingested"] > 0
    assert r1["duplicates_skipped"] == 0

    r2 = client.post("/api/scenarios/SCENARIO_1_SSH_COMPROMISE/replay").json()
    assert r2["events_ingested"] == 0
    assert r2["duplicates_skipped"] == r1["events_ingested"]


def test_no_duplicate_events_in_telemetry(client):
    client.post("/api/scenarios/clear")
    client.post("/api/scenarios/SCENARIO_1_SSH_COMPROMISE/replay")
    client.post("/api/scenarios/SCENARIO_1_SSH_COMPROMISE/replay")
    items = client.get("/api/telemetry?limit=500").json()["items"]
    ids = [e["event_id"] for e in items]
    assert len(ids) == len(set(ids))  # no duplicate SSE/telemetry ids


def test_offline_queue_and_restore(client):
    client.post("/api/scenarios/clear")
    client.post("/api/scenarios/link/down")
    r = client.post("/api/scenarios/SCENARIO_5_DISCONNECTED_OPERATION/replay").json()
    assert r["queued"] is True
    status = client.get("/api/scenarios/link/status").json()
    assert status["link_down"] is True
    assert status["queued_offline_events"] > 0

    restore = client.post("/api/scenarios/link/restore").json()
    assert restore["flushed"] > 0
    # replaying the flushed events again must not duplicate
    after = client.get("/api/scenarios/link/status").json()
    assert after["link_down"] is False
    assert after["queued_offline_events"] == 0
