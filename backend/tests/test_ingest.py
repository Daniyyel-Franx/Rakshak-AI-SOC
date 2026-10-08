from __future__ import annotations

import io
from fastapi.testclient import TestClient


def test_ingest_sysmon_raw(client: TestClient):
    sysmon_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <EventRecordID>9901</EventRecordID>
    <TimeCreated SystemTime="2026-01-15T02:15:30.123456Z"/>
    <Computer>win-srv-01</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-01-15 02:15:30.123</Data>
    <Data Name="ProcessId">1024</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="User">CORP\\secops</Data>
    <Data Name="ParentProcessId">512</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
  </EventData>
</Event>"""

    payload = {
        "source_type": "sysmon",
        "records": [sysmon_xml],
        "site_id": "site-live-01",
    }
    r = client.post("/api/ingest/raw", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["source_type"] == "sysmon"
    assert data["ingested"] == 1
    assert data["status"] == "success"


def test_ingest_auditd_execve_raw(client: TestClient):
    execve_record = {
        "type": "EXECVE",
        "msg": "audit(1705284000.123:7701)",
        "argc": "3",
        "a0": "/bin/bash",
        "a1": "-c",
        "a2": "id",
        "exe": "/bin/bash",
        "auid": "1000",
        "uid": "1000",
        "host": "linux-prod-01",
    }
    payload = {
        "source_type": "auditd_execve",
        "records": [execve_record],
        "site_id": "site-live-02",
    }
    r = client.post("/api/ingest/raw", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["source_type"] == "auditd_execve"
    assert data["ingested"] == 1
    assert data["status"] == "success"


def test_ingest_auditd_file_raw(client: TestClient):
    file_record = {
        "type": "PATH",
        "msg": "audit(1705284000.456:7702)",
        "name": "/etc/shadow",
        "nametype": "NORMAL",
        "cwd": "/root",
        "exe": "/bin/cat",
        "uid": "0",
        "host": "linux-prod-01",
    }
    payload = {
        "source_type": "auditd_file",
        "records": [file_record],
        "site_id": "site-live-02",
    }
    r = client.post("/api/ingest/raw", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["source_type"] == "auditd_file"
    assert data["ingested"] == 1
    assert data["status"] == "success"


def test_ingest_ssh_auth_raw(client: TestClient):
    line = "Jan 15 02:00:20 edge-fw-01 sshd[1234]: Accepted publickey for analyst from 198.51.100.22 port 52123 ssh2"
    payload = {
        "source_type": "ssh_auth",
        "records": [line],
        "site_id": "site-live-03",
    }
    r = client.post("/api/ingest/raw", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["source_type"] == "ssh_auth"
    assert data["ingested"] == 1
    assert data["status"] == "success"


def test_ingest_zeek_conn_raw(client: TestClient):
    conn_record = {
        "ts": "1705284000.789",
        "uid": "Cabc123456",
        "id.orig_h": "192.168.1.50",
        "id.orig_p": 49152,
        "id.resp_h": "203.0.113.10",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "conn_state": "SF",
        "orig_bytes": 1200,
        "resp_bytes": 4800,
        "host": "router-01",
    }
    payload = {
        "source_type": "zeek_conn",
        "records": [conn_record],
        "site_id": "site-live-04",
    }
    r = client.post("/api/ingest/raw", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["source_type"] == "zeek_conn"
    assert data["ingested"] == 1
    assert data["status"] == "success"


def test_ingest_file_upload(client: TestClient):
    auth_lines = (
        "Jan 15 03:00:10 srv-01 sshd[2001]: Failed password for invalid user admin from 198.51.100.99 port 41234 ssh2\n"
        "Jan 15 03:00:15 srv-01 sshd[2002]: Accepted password for deployer from 198.51.100.99 port 41236 ssh2\n"
    )
    file_bytes = io.BytesIO(auth_lines.encode("utf-8"))

    r = client.post(
        "/api/ingest/file",
        files={"file": ("auth.log", file_bytes, "text/plain")},
        data={"source_type": "ssh_auth", "site_id": "site-live-05"},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["source_type"] == "ssh_auth"
    assert data["ingested"] == 2
    assert data["status"] == "success"


def test_demo_preservation_across_clear(client: TestClient):
    # 1. Clear any prior state
    client.post("/api/scenarios/clear")

    # 2. Ingest live event
    line = "Jan 15 04:00:20 bastion sshd[3001]: Accepted password for secadmin from 198.51.100.50 port 50000 ssh2"
    live_res = client.post(
        "/api/ingest/raw",
        json={"source_type": "ssh_auth", "records": [line], "site_id": "site-live"},
    ).json()
    assert live_res["ingested"] == 1

    # 3. Replay demo scenario
    demo_res = client.post("/api/scenarios/SCENARIO_1_SSH_COMPROMISE/replay").json()
    assert demo_res["incident_id"]

    # 4. Check incidents list has both demo and live data
    incidents_before = client.get("/api/incidents").json()
    assert any(i["source"] == "demo" for i in incidents_before)

    # 5. Clear demo data
    clear_res = client.post("/api/scenarios/clear").json()
    assert clear_res["status"] == "cleared"

    # 6. Verify demo incidents were removed, but live telemetry events remain
    incidents_after = client.get("/api/incidents").json()
    assert not any(i["source"] == "demo" for i in incidents_after)

    telemetry = client.get("/api/telemetry?limit=50").json()
    live_events = [e for e in telemetry["items"] if e.get("site_id") == "site-live"]
    assert len(live_events) >= 1
