# DFIR Capstone — Project Rules

## Stack
Python 3.11 (FastAPI, SQLModel, NetworkX, pySigma) backend.
React + React Flow (@xyflow/react) frontend. SQLite, no external DB — no Neo4j.
Local-only project, no cloud deployment, no CI/CD needed.

## Non-negotiable conventions
- Every new module ships with its test file in the same task — a module
  is not done until its tests pass. Follow the existing deterministic-testing
  pattern in backend/tests/conftest.py.
- Before writing any parser, detection, or graph code, check whether a
  relevant Skill exists in .agents/skills/ and read it first — don't
  guess field names or formulas from general knowledge when a Skill
  defines the exact contract.
- Never modify these files without being explicitly asked to in the task:
  components/AttackPathGraph.tsx (already correct — animated edges work)
  backend/app/services/normalizer.py (correct as-is)
  backend/app/services/audit.py (correct as-is)
- backend/app/services/ocsf.py defines the target event schema shape —
  all new parsers must emit dicts matching its existing field structure
  exactly, not a redesigned schema.
- Demo data (source="demo") and live ingested data (source="live") must
  never be mixed or overwritten by each other — see the
  demo-data-preservation skill before touching models.py or any
  ingestion/clear endpoint.

## Architecture summary
Raw logs → parsers (new) → normalizer.py (existing, unchanged) →
sigma_engine (new) → graph_builder.py (existing skeleton, new detection
input) → blast_radius.py (new, NetworkX-based) → API → frontend (existing,
unchanged except new blast-radius overlay).