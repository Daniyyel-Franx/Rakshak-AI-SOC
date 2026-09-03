"""Validation and grounding of LLM analysis output + deterministic fallback.

Every model response is validated against the JSON Schema, then grounded:
  * every cited evidence_ref must exist in the incident's real event IDs
  * every ATT&CK technique id must match the allowed pattern and be known
  * recommended actions must be within the allowed simulated action set
  * threat_score in 0..100, confidence in 0..1

If validation fails or Ollama is unavailable, a deterministic
rule_engine_fallback analysis is returned instead.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..config import POLICY_DIR
from ..schemas import ALLOWED_ACTIONS

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

_SCHEMA_CACHE: dict[str, Any] | None = None


def load_schema() -> dict[str, Any]:
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is None:
        path = POLICY_DIR / "llm_output_schema.json"
        _SCHEMA_CACHE = json.loads(Path(path).read_text())
    return _SCHEMA_CACHE


def validate_schema(data: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate against JSON Schema; fall back to structural checks if jsonschema absent."""
    errors: list[str] = []
    try:
        import jsonschema
        try:
            jsonschema.validate(instance=data, schema=load_schema())
        except jsonschema.ValidationError as e:  # type: ignore
            errors.append(f"schema: {e.message}")
    except Exception:
        # Minimal structural validation fallback.
        required = ["incident_id", "assessment", "threat_score", "confidence",
                    "evidence_refs", "attack_techniques", "attack_path_summary",
                    "recommended_next_steps", "missing_evidence", "safety_notice"]
        for key in required:
            if key not in data:
                errors.append(f"missing field: {key}")
    return (len(errors) == 0, errors)


def ground(data: dict[str, Any], valid_event_ids: set[str],
           known_techniques: set[str]) -> tuple[bool, list[str], dict[str, Any]]:
    """Enforce evidence grounding and safety. Returns (ok, issues, cleaned)."""
    issues: list[str] = []
    cleaned = dict(data)

    # score bounds
    try:
        cleaned["threat_score"] = max(0, min(100, int(round(float(data.get("threat_score", 0))))))
    except Exception:
        cleaned["threat_score"] = 0
        issues.append("threat_score not numeric")
    try:
        cleaned["confidence"] = max(0.0, min(1.0, float(data.get("confidence", 0.0))))
    except Exception:
        cleaned["confidence"] = 0.0
        issues.append("confidence not numeric")

    # evidence refs must exist
    refs = [r for r in data.get("evidence_refs", []) if isinstance(r, str)]
    valid_refs = [r for r in refs if r in valid_event_ids]
    hallucinated = [r for r in refs if r not in valid_event_ids]
    if hallucinated:
        issues.append(f"hallucinated evidence refs dropped: {hallucinated}")
    cleaned["evidence_refs"] = valid_refs

    # techniques: pattern + evidence grounding
    techs = []
    for t in data.get("attack_techniques", []):
        tid = str(t.get("id", ""))
        if not TECHNIQUE_RE.match(tid):
            issues.append(f"invalid technique id dropped: {tid}")
            continue
        if known_techniques and tid not in known_techniques:
            issues.append(f"unsupported technique id dropped: {tid}")
            continue
        t_refs = [r for r in t.get("evidence_refs", []) if r in valid_event_ids]
        if not t_refs:
            issues.append(f"technique {tid} lacked valid evidence; dropped")
            continue
        techs.append({
            "id": tid,
            "name": str(t.get("name", "")),
            "tactic": str(t.get("tactic", "")),
            "confidence": max(0.0, min(1.0, float(t.get("confidence", 0.0)) if _is_num(t.get("confidence")) else 0.0)),
            "evidence_refs": t_refs,
        })
    cleaned["attack_techniques"] = techs

    # recommended actions must be within allowed set
    steps = []
    for s in data.get("recommended_next_steps", []):
        act = str(s.get("action", ""))
        if act not in ALLOWED_ACTIONS:
            issues.append(f"non-allowed action dropped: {act}")
            continue
        rc = s.get("risk_class", "R0")
        if rc not in ("R0", "R1", "R2", "R3"):
            rc = "R0"
        steps.append({"action": act, "risk_class": rc,
                      "requires_approval": bool(s.get("requires_approval", True))})
    cleaned["recommended_next_steps"] = steps

    cleaned.setdefault("missing_evidence", data.get("missing_evidence", []))
    cleaned.setdefault("assessment", data.get("assessment", ""))
    cleaned.setdefault("attack_path_summary", data.get("attack_path_summary", ""))
    cleaned["safety_notice"] = "SIMULATION ONLY — synthetic cyber-range. No real actions performed."

    ok = len(valid_refs) > 0  # must be grounded in at least one real event
    if not ok:
        issues.append("no valid evidence references — analysis rejected")
    return ok, issues, cleaned


def _is_num(v: Any) -> bool:
    try:
        float(v)
        return True
    except Exception:
        return False


def fallback_analysis(incident: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Deterministic analysis used when Ollama is unavailable or output invalid."""
    evidence = incident.get("evidence_refs", [])
    techniques: list[dict[str, Any]] = []
    seen = set()
    for f in findings:
        for t in f.get("attack_techniques", []):
            if t["id"] in seen:
                continue
            seen.add(t["id"])
            techniques.append({
                "id": t["id"],
                "name": t["name"],
                "tactic": t.get("tactic", ""),
                "confidence": round(min(0.9, 0.5 + 0.1 * len(f.get("evidence_event_ids", []))), 2),
                "evidence_refs": f.get("evidence_event_ids", [])[:5],
            })
    assessment = (
        f"Deterministic rule-engine assessment for {incident['incident_id']}: "
        f"{incident.get('title', 'anomalous activity')}. "
        f"{len(findings)} finding(s) correlated across {len(incident.get('entity_ids', []))} entities. "
        "Evidence supports suspicion; treat as under investigation, not confirmed."
    )
    return {
        "incident_id": incident["incident_id"],
        "assessment": assessment,
        "threat_score": int(round(incident.get("risk_score", 0))),
        "confidence": round(float(incident.get("confidence", 0.5)), 2),
        "evidence_refs": evidence,
        "attack_techniques": techniques,
        "attack_path_summary": incident.get("title", ""),
        "recommended_next_steps": incident.get("recommended_actions", []),
        "missing_evidence": [
            "Endpoint EDR process tree corroboration",
            "Network capture of synthetic payload transfer",
        ],
        "safety_notice": "SIMULATION ONLY — synthetic cyber-range. No real actions performed.",
        "analysis_source": "rule_engine_fallback",
    }
