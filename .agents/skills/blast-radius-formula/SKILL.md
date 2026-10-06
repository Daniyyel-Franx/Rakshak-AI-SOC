---
name: blast-radius-formula
description: Use when implementing, modifying, or testing blast_radius.py.
---

Formula (NetworkX-based, not Neo4j):
BlastRadius(h) = Σ w(n) · 1/(1+d_min(h,n)) for n in Reachable(h)

- h: confirmed-compromised host from the causal incident graph
- Reachable(h): nodes connected via the SEPARATE topology/trust graph
  (SSH keys, AD groups, SMB shares) — not the incident graph itself
- w(n): manually-assigned criticality weight, 1-5, from the topology dataset
- d_min(h,n): nx.single_source_shortest_path_length(topology_graph, h, cutoff=4)

Worked example to validate against (hand-computed, use as a test case):
3 reachable nodes — DB-Server (w=5, d=2) → 1.67; File-Server (w=3, d=1) → 1.50;
Print-Server (w=1, d=3) → 0.25. Total = 3.42.

Do not implement path-multiplicity weighting — explicitly out of scope
(documented as future work), keep to hop-distance + criticality only.