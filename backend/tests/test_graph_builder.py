from app.services import graph_builder, scenario_engine


def test_graph_min_size():
    ev = scenario_engine.build_events("SCENARIO_1_SSH_COMPROMISE")
    g = graph_builder.build_graph(ev, "INC-TEST")
    assert len(g["nodes"]) >= 5
    assert len(g["edges"]) >= 4


def test_graph_determinism():
    ev = scenario_engine.build_events("SCENARIO_1_SSH_COMPROMISE")
    g1 = graph_builder.build_graph(ev, "INC-TEST")
    g2 = graph_builder.build_graph(ev, "INC-TEST")
    assert graph_builder.graph_signature(g1) == graph_builder.graph_signature(g2)
    # positions deterministic too
    assert [n["position"] for n in g1["nodes"]] == [n["position"] for n in g2["nodes"]]


def test_expected_pathway_nodes():
    ev = scenario_engine.build_events("SCENARIO_1_SSH_COMPROMISE")
    g = graph_builder.build_graph(ev)
    types = {n["type"] for n in g["nodes"]}
    # source IP -> user -> source host -> target host -> process -> payload
    for expected in ("attacker_ip", "user", "source_host", "target_host", "process", "payload"):
        assert expected in types, f"missing {expected}"


def test_attack_technique_labels_grounded():
    ev = scenario_engine.build_events("SCENARIO_1_SSH_COMPROMISE")
    g = graph_builder.build_graph(ev)
    techniques = {e["technique_id"] for e in g["edges"] if e["technique_id"]}
    assert "T1021.004" in techniques  # SSH lateral movement
    assert "T1105" in techniques      # payload transfer
    # every technique edge must cite evidence
    for e in g["edges"]:
        if e["technique_id"]:
            assert e["evidence_event_ids"], f"technique edge {e['id']} lacks evidence"


def test_canary_creates_decoy_node():
    ev = scenario_engine.build_events("SCENARIO_2_INSIDER_MISUSE")
    g = graph_builder.build_graph(ev)
    assert any(n["type"] == "decoy" for n in g["nodes"])
