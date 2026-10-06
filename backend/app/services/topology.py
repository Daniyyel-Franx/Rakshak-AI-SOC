"""Lab trust/asset topology graph.

This is a SEPARATE graph from the causal incident graph. It models static
network trust relationships (SSH keys, AD group membership, SMB shares)
that exist in the environment, used to compute blast radius when a host
is confirmed compromised.

Node weights (criticality 1-5):
  5 = crown jewel (DB, SCADA historian, CA server)
  4 = high-value (production app server, jump server)
  3 = medium (internal service, relay node)
  2 = low-medium (maintenance laptop, edge node)
  1 = low (test/print server, benign aux)

Hostnames reuse demo scenario names for narrative consistency.
"""
from __future__ import annotations

from functools import lru_cache

import networkx as nx

# ---------------------------------------------------------------------------
# Node catalogue: (hostname, criticality_weight)
# ---------------------------------------------------------------------------
_NODES: list[tuple[str, int]] = [
    # Crown jewels
    ("scada-hist-01", 5),      # SCADA historian — critical OT data store
    ("db-server-01", 5),       # Corporate DB server — crown jewel
    # High value
    ("target-web-01", 4),      # Primary web/SSH target (Scenario 1)
    ("site-01-app-01", 4),     # Site-01 app server (Scenario 3)
    ("maint-jump-01", 4),      # Maintenance jump server
    # Medium value
    ("site-02-app-01", 3),     # Site-02 app server (Scenario 3)
    ("site-03-app-01", 3),     # Site-03 app server (Scenario 3)
    ("sync-relay", 3),         # Cross-site sync relay (Scenario 3)
    # Low-medium
    ("edge-node-03", 2),       # Edge node (Scenario 5)
    ("maint-laptop", 2),       # Maintenance laptop (Scenario 2)
    # Low value
    ("print-server-01", 1),    # Print server — low value aux
]

# ---------------------------------------------------------------------------
# Edge catalogue: (src, dst, trust_type)
# trust_type ∈ {"ssh_key", "ad_group", "smb_share"}
# Edges are undirected (trust is bidirectional for reachability purposes)
# ---------------------------------------------------------------------------
_EDGES: list[tuple[str, str, str]] = [
    # Web target → historian via SSH key (attacker's first pivot path)
    ("target-web-01", "scada-hist-01", "ssh_key"),
    # Web target → DB via AD group membership
    ("target-web-01", "db-server-01", "ad_group"),
    # Historian → DB (SMB share for backup exports)
    ("scada-hist-01", "db-server-01", "smb_share"),
    # Jump server → historian (admin SSH key)
    ("maint-jump-01", "scada-hist-01", "ssh_key"),
    # Jump server → web target (ops SSH key)
    ("maint-jump-01", "target-web-01", "ssh_key"),
    # Maintenance laptop → jump server (AD group)
    ("maint-laptop", "maint-jump-01", "ad_group"),
    # Site app servers → sync relay (AD group, cross-site sync)
    ("site-01-app-01", "sync-relay", "ad_group"),
    ("site-02-app-01", "sync-relay", "ad_group"),
    ("site-03-app-01", "sync-relay", "ad_group"),
    # Edge node → site-03 app (SSH key, field ops)
    ("edge-node-03", "site-03-app-01", "ssh_key"),
    # Site-01 app → web target (SMB share for log aggregation)
    ("site-01-app-01", "target-web-01", "smb_share"),
    # Print server → site-01 app (SMB share for print queues)
    ("print-server-01", "site-01-app-01", "smb_share"),
]


@lru_cache(maxsize=1)
def get_topology_graph() -> nx.Graph:
    """Return the singleton lab trust topology NetworkX graph.

    Cached — this graph is static and constructed once per process.
    Edges are undirected: trust relationships are bidirectional for
    reachability purposes (if A can SSH to B, an attacker on A can
    reach B, and vice versa via key exposure).
    """
    G = nx.Graph()

    for hostname, weight in _NODES:
        G.add_node(hostname, weight=weight)

    for src, dst, trust_type in _EDGES:
        G.add_edge(src, dst, trust_type=trust_type)

    return G
