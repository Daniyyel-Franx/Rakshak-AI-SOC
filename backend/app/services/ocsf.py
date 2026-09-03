"""OCSF-compatible event builders.

This prototype targets OCSF schema version 1.3.0 and is OCSF-COMPATIBLE, not
OCSF-certified. We implement class-specific structures rather than one generic
event type.

OCSF core fields used here:
    time, activity_id, category_uid, class_uid, type_uid, metadata,
    severity_id, status_id, message, plus class-specific objects
    (src_endpoint, dst_endpoint, actor/user, process, file).

Prototype DEFENCE EXTENSIONS live under `unmapped` and are NOT OCSF core:
    site_id, asset_criticality, user_role, mission_state, network_zone,
    clock_uncertainty_ms, sensor_confidence, classification, scenario_id.
"""
from __future__ import annotations

from typing import Any

OCSF_VERSION = "1.3.0"

# class_uid -> human name (subset used by the prototype)
CLASS_AUTHENTICATION = 3002
CLASS_NETWORK_ACTIVITY = 4001
CLASS_PROCESS_ACTIVITY = 1007
CLASS_FILE_ACTIVITY = 1001
CLASS_SECURITY_FINDING = 2001

CLASS_NAME = {
    CLASS_AUTHENTICATION: "authentication",
    CLASS_NETWORK_ACTIVITY: "network_activity",
    CLASS_PROCESS_ACTIVITY: "process_activity",
    CLASS_FILE_ACTIVITY: "file_activity",
    CLASS_SECURITY_FINDING: "finding",
}

CATEGORY_UID = {
    CLASS_AUTHENTICATION: 3,   # Identity & Access Management
    CLASS_NETWORK_ACTIVITY: 4,  # Network Activity
    CLASS_PROCESS_ACTIVITY: 1,  # System Activity
    CLASS_FILE_ACTIVITY: 1,     # System Activity
    CLASS_SECURITY_FINDING: 2,  # Findings
}


def _metadata(scenario_id: str) -> dict[str, Any]:
    return {
        "version": OCSF_VERSION,
        "product": {"name": "Rakshak-AI Sensor", "vendor_name": "Rakshak-AI (prototype)"},
        "logged_time": None,
        "labels": ["synthetic", "cyber-range", scenario_id] if scenario_id else ["synthetic"],
    }


def _extensions(*, site_id: str, scenario_id: str, extra: dict[str, Any] | None = None,
                **overrides: Any) -> dict[str, Any]:
    """Build the `unmapped` defence-extension block.

    Known extension fields have defaults; any additional keyword (e.g.
    outside_maintenance_window, authorized_activity, unassigned_asset,
    campaign_feature) is merged in as an extra extension field.
    """
    unmapped: dict[str, Any] = {
        "site_id": site_id,
        "asset_criticality": "medium",
        "user_role": "user",
        "mission_state": "steady",
        "network_zone": "corp",
        "clock_uncertainty_ms": 25,
        "sensor_confidence": 0.9,
        "classification": "unclassified",
        "scenario_id": scenario_id,
    }
    unmapped.update(overrides)
    if extra:
        unmapped.update(extra)
    return unmapped


def _base(class_uid: int, activity_id: int, event_id: str, time: str,
          severity_id: int, status_id: int, message: str,
          site_id: str, scenario_id: str, ext: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "time": time,
        "event_time": time,
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID[class_uid],
        "class_uid": class_uid,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": severity_id,
        "status_id": status_id,
        "message": message,
        "metadata": _metadata(scenario_id),
        "event_class": CLASS_NAME[class_uid],
        "site_id": site_id,
        "unmapped": ext,
    }


def build_authentication(
    *, event_id: str, time: str, user: str, src_ip: str, src_host: str,
    dst_host: str, success: bool, auth_protocol: str = "ssh",
    site_id: str, scenario_id: str, severity_id: int = 2, **ext_kwargs: Any,
) -> dict[str, Any]:
    activity_id = 1 if success else 2  # 1=Logon success, 2=Logoff/failure per prototype mapping
    status_id = 1 if success else 2
    ext = _extensions(site_id=site_id, scenario_id=scenario_id, **ext_kwargs)
    ev = _base(CLASS_AUTHENTICATION, activity_id, event_id, time, severity_id,
               status_id, f"{'Successful' if success else 'Failed'} {auth_protocol} auth for {user}",
               site_id, scenario_id, ext)
    ev["user"] = {"name": user, "type": "User"}
    ev["src_endpoint"] = {"ip": src_ip, "hostname": src_host}
    ev["dst_endpoint"] = {"hostname": dst_host}
    ev["auth_protocol"] = auth_protocol
    ev["is_success"] = success
    return ev


def build_network_activity(
    *, event_id: str, time: str, src_ip: str, dst_ip: str, dst_port: int,
    protocol: str, bytes_out: int, bytes_in: int, duration_ms: int, url: str = "",
    site_id: str, scenario_id: str, severity_id: int = 2, **ext_kwargs: Any,
) -> dict[str, Any]:
    ext = _extensions(site_id=site_id, scenario_id=scenario_id, **ext_kwargs)
    ev = _base(CLASS_NETWORK_ACTIVITY, 6, event_id, time, severity_id, 1,
               f"Network flow {src_ip} -> {dst_ip}:{dst_port}", site_id, scenario_id, ext)
    ev["src_endpoint"] = {"ip": src_ip}
    ev["dst_endpoint"] = {"ip": dst_ip, "port": dst_port}
    ev["connection_info"] = {"protocol_ver": protocol, "direction": "Outbound"}
    ev["traffic"] = {"bytes_out": bytes_out, "bytes_in": bytes_in, "duration_ms": duration_ms}
    if url:
        ev["url"] = {"url_string": url}
    return ev


def build_process_activity(
    *, event_id: str, time: str, user: str, host: str, process_name: str,
    cmd_line: str, parent_name: str = "", site_id: str, scenario_id: str,
    severity_id: int = 3, **ext_kwargs: Any,
) -> dict[str, Any]:
    ext = _extensions(site_id=site_id, scenario_id=scenario_id, **ext_kwargs)
    ev = _base(CLASS_PROCESS_ACTIVITY, 1, event_id, time, severity_id, 1,
               f"Process {process_name} launched on {host}", site_id, scenario_id, ext)
    ev["user"] = {"name": user, "type": "User"}
    ev["device"] = {"hostname": host}
    ev["process"] = {
        "name": process_name,
        "cmd_line": cmd_line,
        "parent_process": {"name": parent_name} if parent_name else {},
    }
    return ev


def build_file_activity(
    *, event_id: str, time: str, user: str, host: str, file_path: str,
    file_name: str, is_canary: bool = False, site_id: str, scenario_id: str,
    severity_id: int = 3, **ext_kwargs: Any,
) -> dict[str, Any]:
    ext = _extensions(site_id=site_id, scenario_id=scenario_id,
                      extra={"is_canary": is_canary}, **ext_kwargs)
    ev = _base(CLASS_FILE_ACTIVITY, 1, event_id, time, severity_id, 1,
               f"File access {file_path} by {user}", site_id, scenario_id, ext)
    ev["user"] = {"name": user, "type": "User"}
    ev["device"] = {"hostname": host}
    ev["file"] = {"name": file_name, "path": file_path, "type": "Regular File"}
    return ev


def build_finding(
    *, event_id: str, time: str, title: str, technique_id: str, technique_name: str,
    evidence_ids: list[str], site_id: str, scenario_id: str, severity_id: int = 4,
    **ext_kwargs: Any,
) -> dict[str, Any]:
    ext = _extensions(site_id=site_id, scenario_id=scenario_id,
                      extra={"evidence_event_ids": evidence_ids}, **ext_kwargs)
    ev = _base(CLASS_SECURITY_FINDING, 1, event_id, time, severity_id, 1,
               title, site_id, scenario_id, ext)
    ev["finding_info"] = {
        "title": title,
        "attacks": [{"technique": {"uid": technique_id, "name": technique_name}}],
    }
    return ev
