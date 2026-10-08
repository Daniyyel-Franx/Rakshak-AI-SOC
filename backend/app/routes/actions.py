from __future__ import annotations

import json
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from ..config import POLICY_DIR
from ..database import get_session
from ..models import Action, Incident
from ..schemas import ALLOWED_ACTIONS, SimulateActionRequest, SimulateActionResponse
from ..services import audit, deception

router = APIRouter(prefix="/api", tags=["actions"])

_POLICY = json.loads((Path(POLICY_DIR) / "response_policy.json").read_text())


@router.post("/actions/simulate", response_model=SimulateActionResponse)
def simulate(req: SimulateActionRequest, session: Session = Depends(get_session)) -> SimulateActionResponse:
    if req.action_type not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=400, detail=f"action not allowed: {req.action_type}")

    incident = session.exec(select(Incident).where(Incident.incident_id == req.incident_id)).first()
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")

    policy = _POLICY["actions"][req.action_type]
    risk_class = policy["risk_class"]
    requires_approval = policy["requires_approval"]

    approval_state = "approved" if (not requires_approval or req.approved_by) else "pending"

    # ---- SIMULATION ONLY. No real command is ever executed. ----
    rollback_data: dict = {"reversible": policy["reversible"], "simulated": True}
    if req.action_type == "activate_decoy":
        analysis_techs = (incident.analysis_json or {}).get("attack_techniques", [])
        decoy = deception.activate_decoy(req.incident_id, analysis_techs)
        result = f"Simulated decoy deployed: {decoy['name']} on {decoy['network_segment']}"
        rollback_data["decoy"] = decoy
    elif req.action_type == "simulate_isolate_endpoint":
        result = f"Simulated network isolation of endpoint '{req.target or 'target host'}' (no real change)"
        rollback_data["restore"] = "re-enable simulated network interface"
    elif req.action_type == "simulate_revoke_session":
        result = f"Simulated revocation of session for '{req.target or 'user'}' (no real change)"
        rollback_data["restore"] = "reissue simulated session token"
    elif req.action_type == "collect_mock_evidence":
        result = f"Collected synthetic evidence bundle ({len(incident.evidence_refs_json or [])} refs)"
        rollback_data["evidence_refs"] = incident.evidence_refs_json or []
    else:  # create_case
        result = f"Synthetic case opened for {req.incident_id}"
        rollback_data["case_id"] = f"CASE-{uuid.uuid4().hex[:8]}"

    action = Action(
        action_id=f"ACT-{uuid.uuid4().hex[:10]}", incident_id=req.incident_id,
        action_type=req.action_type, target=req.target, approval_state=approval_state,
        approved_by=req.approved_by if approval_state == "approved" else "",
        result=result if approval_state == "approved" else "awaiting approval",
        rollback_data_json=rollback_data,
    )
    session.add(action)
    session.commit()
    session.refresh(action)
    audit.record(session, "simulated_action",
                 {"action_id": action.action_id, "incident_id": req.incident_id,
                  "action_type": req.action_type, "approval_state": approval_state},
                 actor=req.approved_by or "analyst")

    return SimulateActionResponse(
        action_id=action.action_id, incident_id=req.incident_id, action_type=req.action_type,
        target=req.target, policy_risk_class=risk_class, approval_state=approval_state,
        approved_by=action.approved_by,
        result=action.result, rollback_data=rollback_data, simulation_only=True,
    )


@router.get("/actions/{incident_id}")
def list_actions(incident_id: str, session: Session = Depends(get_session)) -> list[dict]:
    rows = session.exec(select(Action).where(Action.incident_id == incident_id)).all()
    return [
        {"action_id": a.action_id, "action_type": a.action_type, "target": a.target,
         "approval_state": a.approval_state, "result": a.result,
         "rollback_data": a.rollback_data_json, "simulation_only": True}
        for a in rows
    ]
