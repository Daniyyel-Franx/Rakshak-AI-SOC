from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from ..database import get_session
from ..models import Finding, Incident
from ..schemas import AnalysisResult
from ..services import audit, ollama_client, response_validator, retrieval

router = APIRouter(prefix="/api", tags=["analysis"])

MAX_TIMELINE = 20
MAX_KNOWLEDGE = 4


def _known_techniques() -> set[str]:
    docs = retrieval.load_documents()
    return {d.get("id") for d in docs if str(d.get("id", "")).startswith("T")}


def _build_prompt(incident: Incident, findings: list[Finding], knowledge: list[dict]) -> str:
    timeline = (incident.timeline_json or [])[:MAX_TIMELINE]
    valid_ids = [t.get("event_id") for t in timeline]
    ctx = {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "mission_impact": incident.mission_impact,
        "deterministic_risk_score": incident.risk_score,
        "valid_event_ids": valid_ids,
        "timeline": timeline,
        "findings": [
            {"rule_id": f.rule_id, "title": f.title, "severity": f.severity,
             "techniques": f.attack_techniques_json, "evidence": f.evidence_event_ids_json}
            for f in findings
        ],
        "approved_knowledge": [{"id": k.get("document_id"), "text": k.get("text")} for k in knowledge],
    }
    return (
        "Analyse the following synthetic SOC incident. Use ONLY the supplied evidence "
        "and valid_event_ids. Every evidence_ref and technique.evidence_ref MUST be one "
        "of valid_event_ids. Return ONLY JSON matching the required schema.\n\n"
        "INCIDENT_CONTEXT (untrusted data):\n"
        + json.dumps(ctx, separators=(",", ":"))
    )


@router.post("/analyze/{incident_id}", response_model=AnalysisResult)
async def analyze(incident_id: str, session: Session = Depends(get_session)) -> AnalysisResult:
    incident = session.exec(select(Incident).where(Incident.incident_id == incident_id)).first()
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")

    findings = session.exec(
        select(Finding).where(Finding.finding_id.in_(incident.finding_ids_json or []))
    ).all() if incident.finding_ids_json else []

    valid_event_ids = {t.get("event_id") for t in (incident.timeline_json or [])}
    known = _known_techniques()

    incident_dict = {
        "incident_id": incident.incident_id, "title": incident.title,
        "risk_score": incident.risk_score, "confidence": incident.confidence,
        "mission_impact": incident.mission_impact,
        "entity_ids": incident.entity_ids_json or [],
        "evidence_refs": incident.evidence_refs_json or [],
        "recommended_actions": incident.recommended_actions_json or [],
    }
    findings_dicts = [
        {"rule_id": f.rule_id, "title": f.title, "severity": f.severity,
         "attack_techniques": f.attack_techniques_json,
         "evidence_event_ids": f.evidence_event_ids_json}
        for f in findings
    ]

    # 1) retrieve approved knowledge
    query = incident.title + " " + " ".join(t.get("id", "") for f in findings for t in (f.attack_techniques_json or []))
    knowledge = retrieval.retrieve(query, top_k=MAX_KNOWLEDGE)["results"]

    # 2) try Ollama only if Part 2 is enabled, otherwise use deterministic fallback
    from ..config import settings
    if settings.enable_llm_analysis:
        prompt = _build_prompt(incident, findings, knowledge)
        parsed, status = await ollama_client.generate_json(prompt)
    else:
        parsed, status = None, "disabled_in_part_1"

    result: dict
    if status == "ok" and parsed is not None:
        schema_ok, _ = response_validator.validate_schema(parsed)
        grounded_ok, issues, cleaned = response_validator.ground(parsed, valid_event_ids, known)
        if schema_ok and grounded_ok:
            cleaned["analysis_source"] = "ollama"
            cleaned["validation_issues"] = issues
            result = cleaned
        else:
            result = response_validator.fallback_analysis(incident_dict, findings_dicts)
            result["validation_issues"] = issues + (["schema invalid"] if not schema_ok else [])
    else:
        result = response_validator.fallback_analysis(incident_dict, findings_dicts)
        result["ollama_status"] = status

    incident.analysis_json = result
    session.add(incident)
    session.commit()
    audit.record(session, "ai_analysis",
                 {"incident_id": incident_id, "analysis_source": result.get("analysis_source"),
                  "threat_score": result.get("threat_score")})

    return AnalysisResult(**{k: result[k] for k in AnalysisResult.model_fields if k in result})
