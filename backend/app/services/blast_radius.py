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

from .topology import get_topology_graph


class BlastRadiusError(ValueError):
    """Raised when the host is not in the topology graph."""
    pass


def compute_blast_radius(
    host: str,
    topology: nx.Graph | None = None,
) -> dict[str, Any]:
    """Compute blast radius for a confirmed-compromised host.

    Args:
        host:     Hostname that is confirmed compromised (must exist in G).
        topology: Optional topology graph override (default: live topology).

    Returns:
        {
          "host":               str,
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

    if host not in G:
        raise BlastRadiusError(
            f"Host '{host}' is not in the topology graph. "
            f"Known hosts: {sorted(G.nodes())}"
        )

    # One call yields {node: distance} for all reachable nodes within 4 hops.
    # This includes h itself at distance 0 — we exclude it (d=0 → contribution
    # w(h)·1/1 = w(h) would double-count the compromised host itself).
    reachable: dict[str, int] = nx.single_source_shortest_path_length(G, host, cutoff=4)

    contributing: list[dict[str, Any]] = []
    total_score: float = 0.0

    for node, distance in reachable.items():
        if node == host:
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

    return {
        "host": host,
        "score": round(total_score, 4),
        "contributing_nodes": contributing,
    }
