---
name: demo-data-preservation
description: Use when touching models.py, any ingestion endpoint, or the scenario /clear endpoint.
---

Incident model has a source: Literal["demo","live"] field.
- scenario_engine.py / /api/scenarios/*/replay always writes source="demo" —
  do not change this file.
- New raw-log ingestion writes source="live".
- /api/scenarios/clear must only delete rows where source=="demo" —
  never touch source=="live" rows.
- Frontend should be able to filter/show both; never silently merge or
  overwrite one with the other.