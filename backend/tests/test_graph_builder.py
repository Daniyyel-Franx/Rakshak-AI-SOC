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


def test_lsass_edge_from_sigma():
    """LSASS process event -> technique_id T1003.001 sourced from Sigma, not hardcoded.

    This technique has no prior hardcoded equivalent in graph_builder.py, so its
    presence on the edge proves the result genuinely came from SigmaEngine.
    The evidence dict (field->value) must trace back to the actual Sigma match.
    """
    lsass_ev = {
        "event_id": "EVT-LSASS-001",
        "event_class": "process_activity",
        "event_time": "2026-01-15T03:00:00Z",
        "severity_id": 4,
        "site_id": "site-01",
        "user": {"name": "SYSTEM"},
        "device": {"hostname": "win-dc-01"},
        "process": {
            "name": "lsass.exe",
            "cmd_line": "C:\\Windows\\System32\\lsass.exe",
            "file": {"path": "C:\\Windows\\System32\\lsass.exe"},
        },
    }

    g = graph_builder.build_graph([lsass_ev])

    # Must produce exactly one technique-tagged edge
    tech_edges = [e for e in g["edges"] if e.get("technique_id")]
    assert len(tech_edges) == 1, f"expected 1 technique edge, got {len(tech_edges)}"

    edge = tech_edges[0]

    # Technique ID must be T1003.001 (from the LSASS Sigma rule)
    assert edge["technique_id"] == "T1003.001", (
        f"expected T1003.001 from Sigma, got {edge['technique_id']!r}"
    )

    # Evidence must cite the actual Sigma-matched field/value, not a hardcoded string
    assert "process.file.path" in edge["evidence"], (
        "evidence missing 'process.file.path' — technique_id may be hardcoded, not Sigma-sourced"
    )
    assert edge["evidence"]["process.file.path"].lower().endswith("lsass.exe"), (
        f"evidence value unexpected: {edge['evidence']['process.file.path']!r}"
    )

    # The edge must reference the event ID
    assert "EVT-LSASS-001" in edge["evidence_event_ids"]

