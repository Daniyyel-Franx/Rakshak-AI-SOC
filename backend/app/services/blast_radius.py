"""Blast radius computation for a confirmed-compromised host.

Formula (from .agents/skills/blast-radius-formula/SKILL.md):

    BlastRadius(h) = Σ  w(n) · 1/(1 + d_min(h, n))
                    n ∈ Reachable(h)

- h           : confirmed-compromised host (must exist in topology graph)
- Reachable(h): nodes reachable within cutoff=4 hops via the SEPARATE
                topology/trust graph (SSH keys, AD groups, SMB shares)
- w(n)        : criticality weight 1-5 from the topology node attribute
- d_min(h, n) : shortest-path hop distance, computed in one call via
                nx.single_source_shortest_path_length(G, h, cutoff=4)

Out-of-scope (future work): path-multiplicity weighting.
"""
from __future__ import annotations

from typing import Any

import networkx as nx

from .topology import canonicalize_host, get_topology_graph


class BlastRadiusError(ValueError):
    """Raised when the host is not in the topology graph."""
    pass


def compute_blast_radius(
    host: str,
    topology: nx.Graph | None = None,
) -> dict[str, Any]:
    """Compute blast radius for a confirmed-compromised host.

    Args:
        host:     Hostname that is confirmed compromised (must exist in G or resolve via alias).
        topology: Optional topology graph override (default: live topology).

    Returns:
        {
          "host":               str,
          "canonical_host":     str,
          "score":              float,           # total blast radius
          "contributing_nodes": [               # per-node breakdown
            {
              "node":         str,
              "weight":       int,   # criticality weight 1-5
              "distance":     int,   # hop distance from host
              "contribution": float, # w(n) * 1/(1+d)
            }, ...
          ]
        }

    Raises:
        BlastRadiusError: if host is not in the topology graph.
    """
    G = topology if topology is not None else get_topology_graph()

    lookup_host = host
    if lookup_host not in G:
        canon = canonicalize_host(lookup_host)
        if canon in G:
            lookup_host = canon
        else:
            raise BlastRadiusError(
                f"Host '{host}' is not in the topology graph. "
                f"Known hosts: {sorted(G.nodes())}"
            )

    # One call yields {node: distance} for all reachable nodes within 4 hops.
    # This includes lookup_host itself at distance 0 — we exclude it (d=0 -> double count).
    reachable: dict[str, int] = nx.single_source_shortest_path_length(G, lookup_host, cutoff=4)

    contributing: list[dict[str, Any]] = []
    total_score: float = 0.0

    for node, distance in reachable.items():
        if node == lookup_host:
            continue  # exclude the compromised host itself
        weight: int = G.nodes[node].get("weight", 1)
        contribution: float = weight * (1.0 / (1 + distance))
        total_score += contribution
        contributing.append({
            "node": node,
            "weight": weight,
            "distance": distance,
            "contribution": round(contribution, 4),
        })

    # Sort by contribution descending for readability
    contributing.sort(key=lambda x: x["contribution"], reverse=True)

    # Extract actual topology edges connecting all nodes in the reachable subgraph
    subgraph_nodes = set(reachable.keys())
    subG = G.subgraph(subgraph_nodes)
    topology_edges: list[dict[str, Any]] = []
    for u, v, data in subG.edges(data=True):
        topology_edges.append({
            "source": u,
            "target": v,
            "trust_type": data.get("trust_type", "trust"),
        })

    return {
        "host": host,
        "canonical_host": lookup_host,
        "score": round(total_score, 4),
        "contributing_nodes": contributing,
        "topology_edges": topology_edges,
    }
