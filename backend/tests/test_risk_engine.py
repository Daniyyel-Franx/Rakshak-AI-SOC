from app.services import anomaly, risk_engine, scenario_engine


def test_anomaly_weights_sum_to_one():
    assert round(sum(anomaly.WEIGHTS.values()), 6) == 1.0


def test_deterministic_score_bounds():
    feats = {k: 1.0 for k in anomaly.WEIGHTS}
    feats["privilege_action_count"] = 5.0
    s = anomaly.deterministic_score(feats)
    assert 0.0 <= s <= 1.0


def test_decoy_dominates_score():
    base = {k: 0.0 for k in anomaly.WEIGHTS}
    decoy = dict(base, decoy_interaction=1.0)
    assert anomaly.deterministic_score(decoy) >= 0.20


def test_ssh_scenario_produces_high_incident():
    ev = scenario_engine.build_events("SCENARIO_1_SSH_COMPROMISE")
    res = risk_engine.evaluate(ev, "SCENARIO_1_SSH_COMPROMISE")
    assert res["incident"] is not None
    assert res["incident"]["risk_score"] >= 60
    rule_ids = {f["rule_id"] for f in res["findings"]}
    assert "R-SSH-BRUTE" in rule_ids


def test_insider_scenario_is_elevated():
    ev = scenario_engine.build_events("SCENARIO_2_INSIDER_MISUSE")
    res = risk_engine.evaluate(ev, "SCENARIO_2_INSIDER_MISUSE")
    assert res["incident"]["risk_score"] >= 80
    assert any(f["rule_id"] == "R-CANARY-ACCESS" for f in res["findings"])


def test_benign_scenario_downgraded():
    ev = scenario_engine.build_events("SCENARIO_4_BENIGN_MAINTENANCE")
    res = risk_engine.evaluate(ev, "SCENARIO_4_BENIGN_MAINTENANCE")
    # authorised maintenance => low anomaly, no incident
    assert res["anomaly_score"] < 0.3
    assert res["incident"] is None


def test_findings_cite_evidence():
    ev = scenario_engine.build_events("SCENARIO_1_SSH_COMPROMISE")
    res = risk_engine.evaluate(ev, "SCENARIO_1_SSH_COMPROMISE")
    valid_ids = {e["event_id"] for e in ev}
    for f in res["findings"]:
        assert f["evidence_event_ids"]
        assert all(eid in valid_ids for eid in f["evidence_event_ids"])
