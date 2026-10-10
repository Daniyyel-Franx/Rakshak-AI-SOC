import pytest
import networkx as nx
from app.services.blast_radius import compute_blast_radius

def test_topology_edges_use_canonical_ids():
    """Verify that topology_edges correctly use canonical IDs and match contributing nodes, avoiding unmatched endpoints."""
    # Build a small custom graph to test alias mapping edge cases
    G = nx.Graph()
    # 'target-web-01' is the canonical host for 'target-linux-01'
    G.add_node("target-web-01", weight=5)
    G.add_node("site-01-app", weight=3)
    G.add_edge("target-web-01", "site-01-app", trust_type="ssh")
    
    result = compute_blast_radius("target-linux-01", topology=G)
    
    # 1. The root ID for UI rendering MUST be the canonical host
    root_id = result.get("canonical_host", result["host"])
    assert root_id == "target-web-01"
    
    # 2. Extract all nodes present in the incident result
    contributing_node_ids = {n["node"] for n in result["contributing_nodes"]}
    all_node_ids = {root_id} | contributing_node_ids
    
    # 3. Ensure EVERY topology edge maps perfectly to these node IDs
    edges = result.get("topology_edges", [])
    assert len(edges) == 1
    for e in edges:
        assert e["source"] in all_node_ids, f"Unmatched edge endpoint: {e['source']}"
        assert e["target"] in all_node_ids, f"Unmatched edge endpoint: {e['target']}"
        
    # 4. Verify canonical ID is actually used in the edge
    assert edges[0]["source"] == "target-web-01" or edges[0]["target"] == "target-web-01"
