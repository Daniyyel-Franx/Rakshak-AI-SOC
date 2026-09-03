from app.services import response_validator as rv


VALID_IDS = {"EVT-1", "EVT-2", "EVT-3"}
KNOWN = {"T1021.004", "T1105", "T1110"}


def _good():
    return {
        "incident_id": "INC-1",
        "assessment": "suspicious",
        "threat_score": 80,
        "confidence": 0.8,
        "evidence_refs": ["EVT-1", "EVT-2"],
        "attack_techniques": [
            {"id": "T1021.004", "name": "SSH", "tactic": "Lateral Movement",
             "confidence": 0.8, "evidence_refs": ["EVT-1"]}
        ],
        "attack_path_summary": "ssh then payload",
        "recommended_next_steps": [
            {"action": "simulate_isolate_endpoint", "risk_class": "R2", "requires_approval": True}
        ],
        "missing_evidence": [],
        "safety_notice": "SIMULATION ONLY",
    }


def test_schema_valid():
    ok, errors = rv.validate_schema(_good())
    assert ok, errors


def test_grounding_drops_hallucinated_refs():
    data = _good()
    data["evidence_refs"] = ["EVT-1", "EVT-999", "FAKE"]
    ok, issues, cleaned = rv.ground(data, VALID_IDS, KNOWN)
    assert ok
    assert cleaned["evidence_refs"] == ["EVT-1"]
    assert any("hallucinated" in i for i in issues)


def test_grounding_drops_unknown_technique():
    data = _good()
    data["attack_techniques"].append(
        {"id": "T9999", "name": "fake", "tactic": "x", "confidence": 0.9, "evidence_refs": ["EVT-1"]})
    ok, issues, cleaned = rv.ground(data, VALID_IDS, KNOWN)
    ids = {t["id"] for t in cleaned["attack_techniques"]}
    assert "T9999" not in ids


def test_grounding_rejects_when_no_valid_evidence():
    data = _good()
    data["evidence_refs"] = ["NOPE"]
    ok, issues, cleaned = rv.ground(data, VALID_IDS, KNOWN)
    assert ok is False


def test_non_allowed_action_dropped():
    data = _good()
    data["recommended_next_steps"].append(
        {"action": "rm -rf /", "risk_class": "R3", "requires_approval": True})
    ok, issues, cleaned = rv.ground(data, VALID_IDS, KNOWN)
    actions = {s["action"] for s in cleaned["recommended_next_steps"]}
    assert "rm -rf /" not in actions


def test_score_clamping():
    data = _good()
    data["threat_score"] = 999
    data["confidence"] = 5.0
    ok, issues, cleaned = rv.ground(data, VALID_IDS, KNOWN)
    assert cleaned["threat_score"] == 100
    assert cleaned["confidence"] == 1.0


def test_fallback_analysis_is_grounded():
    incident = {"incident_id": "INC-1", "title": "t", "risk_score": 70, "confidence": 0.7,
                "entity_ids": ["a"], "evidence_refs": ["EVT-1"], "recommended_actions": []}
    findings = [{"rule_id": "R", "title": "t", "severity": "high",
                 "attack_techniques": [{"id": "T1021.004", "name": "SSH", "tactic": "LM"}],
                 "evidence_event_ids": ["EVT-1"]}]
    out = rv.fallback_analysis(incident, findings)
    assert out["analysis_source"] == "rule_engine_fallback"
    assert out["evidence_refs"] == ["EVT-1"]
