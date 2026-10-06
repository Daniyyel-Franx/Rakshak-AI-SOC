"""Tests for blast_radius.py — formula correctness and edge cases.

The worked example is taken verbatim from:
  .agents/skills/blast-radius-formula/SKILL.md

  3 reachable nodes:
    DB-Server    (w=5, d=2) → 5 * 1/(1+2) = 1.6667
    File-Server  (w=3, d=1) → 3 * 1/(1+1) = 1.5000
    Print-Server (w=1, d=3) → 1 * 1/(1+3) = 0.2500
  Total = 3.4167  (SKILL.md rounds to 3.42)
"""
from __future__ import annotations

import networkx as nx
import pytest

from app.services.blast_radius import BlastRadiusError, compute_blast_radius


# ---------------------------------------------------------------------------
# Shared fixture: exact topology from the SKILL.md worked example
# ---------------------------------------------------------------------------
@pytest.fixture
def skill_topology() -> nx.Graph:
    """Fixed 4-node topology matching the SKILL.md hand-computed example."""
    G = nx.Graph()
    G.add_node("Compromised-Host", weight=4)
    G.add_node("File-Server", weight=3)    # d=1 from Compromised-Host
    G.add_node("DB-Server", weight=5)      # d=2 from Compromised-Host
    G.add_node("Print-Server", weight=1)   # d=3 from Compromised-Host
    G.add_edge("Compromised-Host", "File-Server")
    G.add_edge("File-Server", "DB-Server")
    G.add_edge("DB-Server", "Print-Server")
    return G


# ---------------------------------------------------------------------------
# [1] Exact worked example from SKILL.md — most important test
# ---------------------------------------------------------------------------
def test_skill_worked_example_exact_score(skill_topology):
    """Total blast radius must match SKILL.md hand-computed 3.4167 (rounds to 3.42)."""
    result = compute_blast_radius("Compromised-Host", topology=skill_topology)

    assert result["host"] == "Compromised-Host"

    # Exact score check (rounded to 4 decimal places as the implementation returns)
    assert result["score"] == pytest.approx(3.4167, abs=1e-3), (
        f"Expected 3.4167 from SKILL.md worked example, got {result['score']}"
    )

    # Verify per-node contributions match the hand-computed values
    by_node = {n["node"]: n for n in result["contributing_nodes"]}

    assert "DB-Server" in by_node
    assert by_node["DB-Server"]["weight"] == 5
    assert by_node["DB-Server"]["distance"] == 2
    assert by_node["DB-Server"]["contribution"] == pytest.approx(5 / 3, abs=1e-3)  # 1.6667

    assert "File-Server" in by_node
    assert by_node["File-Server"]["weight"] == 3
    assert by_node["File-Server"]["distance"] == 1
    assert by_node["File-Server"]["contribution"] == pytest.approx(1.5, abs=1e-4)  # 1.5000

    assert "Print-Server" in by_node
    assert by_node["Print-Server"]["weight"] == 1
    assert by_node["Print-Server"]["distance"] == 3
    assert by_node["Print-Server"]["contribution"] == pytest.approx(0.25, abs=1e-4)  # 0.2500

    # Must be exactly 3 contributing nodes (host itself excluded)
    assert len(result["contributing_nodes"]) == 3


def test_skill_worked_example_host_itself_excluded(skill_topology):
    """The compromised host itself must NOT appear in contributing_nodes."""
    result = compute_blast_radius("Compromised-Host", topology=skill_topology)
    node_names = {n["node"] for n in result["contributing_nodes"]}
    assert "Compromised-Host" not in node_names


# ---------------------------------------------------------------------------
# [2] Host with zero reachable nodes -> score 0, not an error
# ---------------------------------------------------------------------------
def test_isolated_host_returns_zero_score():
    """An isolated host (no edges) has score 0 and empty contributing_nodes."""
    G = nx.Graph()
    G.add_node("isolated-host", weight=3)
    G.add_node("other-host", weight=5)
    # No edges — isolated-host cannot reach anything

    result = compute_blast_radius("isolated-host", topology=G)

    assert result["score"] == 0.0
    assert result["contributing_nodes"] == []
    assert result["host"] == "isolated-host"


# ---------------------------------------------------------------------------
# [3] Host not in topology graph -> raises BlastRadiusError (typed)
# ---------------------------------------------------------------------------
def test_unknown_host_raises_typed_error(skill_topology):
    """Requesting blast radius for a host not in the graph must raise BlastRadiusError."""
    with pytest.raises(BlastRadiusError, match="not in the topology graph"):
        compute_blast_radius("nonexistent-host-xyz", topology=skill_topology)


def test_unknown_host_error_is_value_error_subclass(skill_topology):
    """BlastRadiusError must be a ValueError subclass (typed, not generic)."""
    with pytest.raises(ValueError):
        compute_blast_radius("nonexistent-host-xyz", topology=skill_topology)


# ---------------------------------------------------------------------------
# [4] Real topology smoke test
# ---------------------------------------------------------------------------
def test_real_topology_target_web_01_has_nonzero_score():
    """target-web-01 in the real topology has reachable nodes -> score > 0."""
    from app.services.blast_radius import compute_blast_radius as cbr
    result = cbr("target-web-01")
    assert result["score"] > 0
    assert len(result["contributing_nodes"]) > 0


def test_real_topology_cutoff_4_respected():
    """No contributing node should have distance > 4 (cutoff enforcement)."""
    from app.services.blast_radius import compute_blast_radius as cbr
    result = cbr("target-web-01")
    for n in result["contributing_nodes"]:
        assert n["distance"] <= 4, (
            f"Node {n['node']} at distance {n['distance']} exceeds cutoff=4"
        )
