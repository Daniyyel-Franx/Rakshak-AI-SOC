def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert "ollama_available" in body
    assert body["ocsf_schema_version"]


def test_root_safety_banner(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "SIMULATION ONLY" in r.json()["safety"]
