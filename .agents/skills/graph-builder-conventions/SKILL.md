---
name: graph-builder-conventions
description: Use when modifying backend/app/services/graph_builder.py.
---

KEEP unchanged: the _GraphState class, node/edge dedup logic, severity
escalation, deterministic layered layout, to_networkx() conversion.

REPLACE: the hardcoded keyword-matching blocks (e.g. checks like
"bash"/"curl" in cmd.lower()) — these must be swapped for calls into
sigma_engine.py's match output. The add_edge(...) call signature stays
the same; only the source of technique_id/technique_name changes from
string-matching to real Sigma match results.

Do not touch components/AttackPathGraph.tsx — it already renders
animated edges correctly from this module's output shape.