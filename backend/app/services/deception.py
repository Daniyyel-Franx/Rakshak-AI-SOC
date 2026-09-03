"""Adaptive but ISOLATED deception simulation.

Decoys are entirely synthetic. Nothing here touches real hosts, files, network
or accounts. "Adaptive" means the chosen decoy type is selected from the
incident's observed techniques, but deployment is simulated only.
"""
from __future__ import annotations

import uuid
from typing import Any

DECOY_CATALOG = {
    "T1021.004": {"type": "ssh_honeypot", "name": "Synthetic SSH honeypot",
                  "description": "Fake SSH service emitting synthetic banners on an isolated decoy segment."},
    "T1105": {"type": "canary_file", "name": "Synthetic canary payload sink",
              "description": "Decoy download endpoint that records access without serving real data."},
    "T1005": {"type": "canary_document", "name": "Synthetic canary document",
              "description": "Beaconless canary file whose access raises a synthetic alert."},
    "default": {"type": "network_decoy", "name": "Synthetic network decoy",
                "description": "Isolated decoy host advertising fake services."},
}


def select_decoy(techniques: list[dict[str, Any]]) -> dict[str, Any]:
    for t in techniques:
        if t.get("id") in DECOY_CATALOG:
            return DECOY_CATALOG[t["id"]]
    return DECOY_CATALOG["default"]


def activate_decoy(incident_id: str, techniques: list[dict[str, Any]]) -> dict[str, Any]:
    decoy = select_decoy(techniques)
    return {
        "decoy_id": f"DECOY-{uuid.uuid4().hex[:8]}",
        "incident_id": incident_id,
        "decoy_type": decoy["type"],
        "name": decoy["name"],
        "description": decoy["description"],
        "network_segment": "isolated-decoy-vlan-999 (synthetic)",
        "status": "simulated_active",
        "isolation": "fully_isolated",
        "simulation_only": True,
    }
