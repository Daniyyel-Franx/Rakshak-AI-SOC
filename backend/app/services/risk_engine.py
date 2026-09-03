"""Deterministic rule + risk engine.

Detection is deterministic (rules + behavioural score + graph correlation +
deception). The LLM is NOT a detector. Given the same events, the same
findings and the same incident are produced.

Each rule cites the exact evidence event_ids that triggered it.
"""
from __future__ import annotations

import hashlib
from typing import Any

from . import anomaly, feature_engine, graph_builder

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _stable_id(prefix: str, *parts: str) -> str:
    blob = "|".join(parts)
    return f"{prefix}-" + hashlib.sha256(blob.encode()).hexdigest()[:10].upper()


def _acting_user(events: list[dict[str, Any]]) -> str:
    for ev in events:
        u = (ev.get("user") or {}).get("name")
        if u:
            return u
    return "unknown"


def _mission_impact(events: list[dict[str, Any]]) -> str:
    order = ["low", "medium", "high", "critical"]
    crit = "low"
    mission = "steady"
    for ev in events:
        um = ev.get("unmapped") or {}
        c = um.get("asset_criticality", "low")
        if c in order and order.index(c) > order.index(crit):
            crit = c
        mission = um.get("mission_state", mission)
    if crit in ("critical", "high") and mission in ("elevated", "operation"):
        return "high"
    if crit in ("critical", "high"):
        return "medium"
    return "low"


# ------------------------- individual rules -------------------------
def _rule_ssh_brute(events, site, scenario) -> dict | None:
    auth = [e for e in events if e.get("event_class") == "authentication"]
    failed = [e for e in auth if int(e.get("status_id", 1)) == 2]
    success = [e for e in auth if int(e.get("status_id", 1)) == 1]
    if len(failed) >= 2 and success:
        evidence = [e["event_id"] for e in failed] + [success[0]["event_id"]]
        return {
            "rule_id": "R-SSH-BRUTE",
            "title": "SSH brute-force followed by successful authentication",
            "severity": "high",
            "attack_techniques": [
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
                {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
            ],
            "evidence_event_ids": evidence,
        }
    return None


def _rule_payload(events, site, scenario) -> dict | None:
    hits = []
    for e in events:
        if e.get("event_class") == "process_activity":
            cmd = ((e.get("process") or {}).get("cmd_line") or "").lower()
            if any(s in cmd for s in ("curl", "wget", "http://", "https://")):
                hits.append(e["event_id"])
        if e.get("event_class") == "network_activity" and (e.get("url") or {}).get("url_string"):
            hits.append(e["event_id"])
    if hits:
        return {
            "rule_id": "R-PAYLOAD-RETRIEVAL",
            "title": "Synthetic payload retrieval on target host",
            "severity": "high",
            "attack_techniques": [
                {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
                {"id": "T1059.004", "name": "Unix Shell", "tactic": "Execution"},
            ],
            "evidence_event_ids": hits,
        }
    return None


def _rule_canary(events, site, scenario) -> dict | None:
    hits = [e["event_id"] for e in events
            if e.get("event_class") == "file_activity" and (e.get("unmapped") or {}).get("is_canary")]
    hits += [e["event_id"] for e in events if (e.get("unmapped") or {}).get("decoy_interaction")]
    if hits:
        return {
            "rule_id": "R-CANARY-ACCESS",
            "title": "Interaction with synthetic canary/decoy asset",
            "severity": "critical",
            "attack_techniques": [
                {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
            ],
            "evidence_event_ids": list(dict.fromkeys(hits)),
        }
    return None


def _rule_insider_offhours(events, site, scenario) -> dict | None:
    hits = []
    unassigned = False
    for e in events:
        um = e.get("unmapped") or {}
        if um.get("outside_maintenance_window"):
            hits.append(e["event_id"])
        if um.get("unassigned_asset"):
            unassigned = True
            hits.append(e["event_id"])
    if hits:
        techniques = [{"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"}]
        if unassigned:
            techniques.append({"id": "T1530", "name": "Data from Cloud/Restricted Asset",
                               "tactic": "Collection"})
        return {
            "rule_id": "R-INSIDER-OFFHOURS",
            "title": "Maintenance identity active outside window / restricted asset",
            "severity": "high",
            "attack_techniques": techniques,
            "evidence_event_ids": list(dict.fromkeys(hits)),
        }
    return None


def _rule_privilege(events, site, scenario) -> dict | None:
    hits = []
    for e in events:
        if e.get("event_class") == "process_activity":
            cmd = ((e.get("process") or {}).get("cmd_line") or "").lower()
            if any(k in cmd for k in ("sudo", "useradd", "passwd", "chown root", "systemctl")):
                hits.append(e["event_id"])
    if hits:
        return {
            "rule_id": "R-PRIV-ACTION",
            "title": "Privileged action executed",
            "severity": "medium",
            "attack_techniques": [
                {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
            ],
            "evidence_event_ids": hits,
        }
    return None


RULES = [_rule_ssh_brute, _rule_payload, _rule_canary, _rule_insider_offhours, _rule_privilege]


def _is_authorized_benign(events: list[dict[str, Any]]) -> bool:
    """SCENARIO_4 context: approved maintenance downgrades anomaly."""
    if not events:
        return False
    authorized = all((e.get("unmapped") or {}).get("authorized_activity") for e in events)
    in_window = any((e.get("unmapped") or {}).get("maintenance_window") for e in events)
    no_canary = not any((e.get("unmapped") or {}).get("is_canary") for e in events)
    return authorized and in_window and no_canary


def evaluate(events: list[dict[str, Any]], scenario_id: str = "") -> dict[str, Any]:
    """Return findings + incident (deterministic) for a batch of events."""
    if not events:
        return {"findings": [], "incident": None, "features": {}, "anomaly_score": 0.0}

    site = events[0].get("site_id") or (events[0].get("unmapped") or {}).get("site_id", "site-unknown")
    user = _acting_user(events)

    # behavioural score
    features = feature_engine.compute_features(user, events)
    anomaly_score = anomaly.score_features(features)

    # authorized-activity downgrade
    authorized = _is_authorized_benign(events)
    if authorized:
        anomaly_score = round(anomaly_score * 0.25, 4)

    # deterministic rules
    findings: list[dict[str, Any]] = []
    for rule in RULES:
        res = rule(events, site, scenario_id)
        if not res:
            continue
        if authorized and res["rule_id"] in ("R-INSIDER-OFFHOURS", "R-PRIV-ACTION"):
            continue  # authorized context suppresses these
        deception_score = 1.0 if res["rule_id"] == "R-CANARY-ACCESS" else 0.0
        finding = {
            "finding_id": _stable_id("FND", scenario_id, res["rule_id"], site,
                                     ",".join(res["evidence_event_ids"])),
            "rule_id": res["rule_id"],
            "title": res["title"],
            "severity": res["severity"],
            "attack_techniques": res["attack_techniques"],
            "evidence_event_ids": res["evidence_event_ids"],
            "anomaly_score": anomaly_score,
            "sequence_score": 0.0,
            "graph_score": 0.0,
            "deception_score": deception_score,
        }
        findings.append(finding)

    # graph correlation contributes graph_score
    graph = graph_builder.build_graph(events)
    graph_score = round(min(1.0, len(graph["edges"]) / 8.0), 4)
    for f in findings:
        f["graph_score"] = graph_score

    incident = _build_incident(events, findings, features, anomaly_score, graph_score,
                               scenario_id, site, authorized)
    return {
        "findings": findings,
        "incident": incident,
        "features": features,
        "anomaly_score": anomaly_score,
        "graph": graph,
    }


def _build_incident(events, findings, features, anomaly_score, graph_score,
                    scenario_id, site, authorized) -> dict[str, Any] | None:
    if not findings and anomaly_score < 0.3:
        # No incident for clearly benign activity.
        if authorized:
            return None
    max_sev = "low"
    for f in findings:
        if SEV_RANK.get(f["severity"], 1) > SEV_RANK.get(max_sev, 1):
            max_sev = f["severity"]

    deception = 1.0 if any(f["deception_score"] > 0 for f in findings) else 0.0
    rule_boost = min(1.0, 0.2 * len(findings))
    # combined risk 0..100
    risk = (0.45 * anomaly_score + 0.20 * graph_score + 0.20 * deception + 0.15 * rule_boost) * 100
    sev_floor = {"low": 15, "medium": 45, "high": 70, "critical": 85}
    risk = max(risk, sev_floor.get(max_sev, 0) if findings else 0)
    risk = round(min(100.0, risk), 1)

    if not findings and risk < 25:
        return None

    confidence = round(min(0.99, 0.4 + 0.1 * len(findings) + 0.2 * graph_score + 0.2 * deception), 2)
    entity_ids = sorted({n["id"] for n in graph_builder.build_graph(events)["nodes"]})
    evidence_refs = sorted({eid for f in findings for eid in f["evidence_event_ids"]}) or \
        [e["event_id"] for e in events]

    timeline = [
        {
            "event_id": e["event_id"],
            "time": e.get("event_time") or e.get("time"),
            "event_class": e.get("event_class"),
            "message": e.get("message") or (e.get("unmapped") or {}).get("message", ""),
            "severity_id": e.get("severity_id", 1),
        }
        for e in sorted(events, key=lambda x: (x.get("event_time") or "", x.get("event_id") or ""))
    ]

    mission_impact = _mission_impact(events)
    title = findings[0]["title"] if findings else "Behavioural anomaly detected"
    incident_id = _stable_id("INC", scenario_id, site, findings[0]["rule_id"] if findings else "anomaly",
                             evidence_refs[0] if evidence_refs else "")

    recommended = _recommend_actions(findings, mission_impact)

    return {
        "incident_id": incident_id,
        "title": title,
        "status": "open",
        "risk_score": risk,
        "confidence": confidence,
        "mission_impact": mission_impact,
        "scenario_id": scenario_id,
        "entity_ids": entity_ids,
        "finding_ids": [f["finding_id"] for f in findings],
        "evidence_refs": evidence_refs,
        "timeline": timeline,
        "recommended_actions": recommended,
        "site_id": site,
    }


def _recommend_actions(findings, mission_impact) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    rule_ids = {f["rule_id"] for f in findings}
    if {"R-SSH-BRUTE", "R-PAYLOAD-RETRIEVAL"} & rule_ids:
        actions.append({"action": "simulate_isolate_endpoint", "risk_class": "R2", "requires_approval": True})
        actions.append({"action": "simulate_revoke_session", "risk_class": "R1", "requires_approval": True})
    if "R-CANARY-ACCESS" in rule_ids:
        actions.append({"action": "activate_decoy", "risk_class": "R1", "requires_approval": False})
    actions.append({"action": "collect_mock_evidence", "risk_class": "R0", "requires_approval": False})
    actions.append({"action": "create_case", "risk_class": "R0", "requires_approval": False})
    # de-dup preserving order
    seen = set()
    out = []
    for a in actions:
        if a["action"] not in seen:
            seen.add(a["action"])
            out.append(a)
    return out
