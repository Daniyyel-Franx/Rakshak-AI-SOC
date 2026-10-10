"""Blast radius route.

GET /api/incidents/{incident_id}/blast-radius

Host-identification decision:
  An incident's graph may implicate MULTIPLE target hosts (e.g. pivot from
  web server to DB server). We extract all nodes whose type is "target_host"
  from the stored graph_json, compute blast radius for each that exists in
  the topology graph, and return all results as a list.

  Rationale: returning only the first host would silently miss multi-pivot
  scenarios. The frontend overlay can display per-host scores or highlight
  the maximum. The caller can also take max(r["score"] for r in hosts).

  Fallback: if no target_host node is in the topology graph (e.g. the host
  name is not seeded there), we still return a valid response with that host
  and score=0 rather than 404, so the caller always gets a structured result.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from ..database import get_session
from ..models import Incident
from ..schemas import BlastRadiusResponse
from ..services.blast_radius import BlastRadiusError, compute_blast_radius

router = APIRouter(prefix="/api", tags=["blast-radius"])


def _extract_target_hosts(graph_json: dict) -> list[str]:
    """Return hostnames of all target_host nodes in the incident graph."""
    nodes = graph_json.get("nodes", [])
    hosts = []
    for node in nodes:
        if node.get("type") == "target_host":
            label = node.get("data", {}).get("label") or node.get("id", "")
            if label:
                hosts.append(label)
    return hosts


@router.get("/incidents/{incident_id}/blast-radius", response_model=BlastRadiusResponse)
def get_blast_radius(
    incident_id: str,
    session: Session = Depends(get_session),
) -> BlastRadiusResponse:
    """Compute blast radius for all target hosts in the incident's attack graph.

    Returns one entry per identified target host. For each host present in the
    topology graph, the full per-node contribution breakdown is included.
    If a host is not in the topology graph (unknown asset), score is 0.
    """
    inc = session.exec(
        select(Incident).where(Incident.incident_id == incident_id)
    ).first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")

    graph_json = inc.graph_json or {}
    target_hosts = _extract_target_hosts(graph_json)

    if not target_hosts:
        # No target_host nodes found — return an empty but valid response
        return BlastRadiusResponse(incident_id=incident_id, hosts=[])

    results = []
    for host in target_hosts:
        try:
            result = compute_blast_radius(host)
            if len(result.get("contributing_nodes", [])) == 0:
                result["error"] = "Target exists in topology but has no evidence-backed reachable nodes."
        except BlastRadiusError:
            # Host not in topology — return zero-score entry, not a 404
            result = {
                "host": host,
                "score": 0.0,
                "contributing_nodes": [],
                "topology_edges": [],
                "error": "Target host is not mapped to the configured topology.",
            }
        except Exception as exc:
            result = {
                "host": host,
                "score": 0.0,
                "contributing_nodes": [],
                "topology_edges": [],
                "error": f"Blast-radius calculation failed at runtime: {exc}",
            }
        results.append(result)

    return BlastRadiusResponse(incident_id=incident_id, hosts=results)
