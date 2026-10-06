"""Windows Sysmon Event ID 1 (Process Creation) to OCSF parser.

Target schema: OCSF v1.3.0 Process Activity (class_uid 1007).
Emits dicts matching ocsf.py's build_process_activity output exactly.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from .. import ocsf


class SysmonParseError(ValueError):
    """Raised when a Sysmon record is malformed, truncated, or missing required fields."""
    pass


def _extract_process_name(path_or_name: str) -> str:
    """Extract the executable image name from a file path or command string."""
    if not path_or_name:
        return ""
    clean = path_or_name.strip().strip('"').strip("'")
    if not clean:
        return ""
    # Normalize path separators
    normalized = clean.replace("/", "\\")
    return normalized.split("\\")[-1]


def _normalize_timestamp(ts: str) -> str:
    """Normalize Sysmon UtcTime/TimeCreated into standard ISO-8601 UTC string."""
    if not ts or not isinstance(ts, str) or not ts.strip():
        raise SysmonParseError("Missing or empty timestamp")
    clean = ts.strip()
    try:
        # Sysmon native format: "2026-01-15 02:15:30.123"
        if " " in clean and "T" not in clean:
            dt = datetime.fromisoformat(clean.replace(" ", "T"))
        elif clean.endswith("Z"):
            dt = datetime.fromisoformat(clean[:-1] + "+00:00")
        else:
            dt = datetime.fromisoformat(clean)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception as e:
        raise SysmonParseError(f"Invalid timestamp format '{clean}': {e}") from e


def _parse_xml_record(xml_input: str | bytes | ET.Element) -> dict[str, Any]:
    """Parse Sysmon XML string, bytes, or Element into a flat field dictionary."""
    if isinstance(xml_input, (str, bytes)):
        text = xml_input.decode("utf-8", errors="replace") if isinstance(xml_input, bytes) else xml_input
        if not text.strip():
            raise SysmonParseError("Sysmon XML record is empty")
        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            raise SysmonParseError(f"Malformed or truncated Sysmon XML: {e}") from e
    elif ET.iselement(xml_input):
        root = xml_input
    else:
        raise SysmonParseError(f"Unsupported XML record type: {type(xml_input).__name__}")

    data: dict[str, Any] = {}

    def local_tag(elem: ET.Element) -> str:
        return elem.tag.split("}")[-1]

    root_tag = local_tag(root)
    if root_tag != "Event":
        raise SysmonParseError(f"Expected root tag 'Event', got '{root_tag}'")

    for child in root:
        ltag = local_tag(child)
        if ltag == "System":
            for sc in child:
                stag = local_tag(sc)
                if stag == "EventID":
                    data["EventID"] = (sc.text or "").strip()
                elif stag == "EventRecordID":
                    data["EventRecordID"] = (sc.text or "").strip()
                elif stag == "Computer":
                    data["Computer"] = (sc.text or "").strip()
                elif stag == "TimeCreated":
                    st = sc.attrib.get("SystemTime")
                    if st:
                        data["TimeCreated"] = st.strip()
        elif ltag == "EventData":
            for dc in child:
                dtag = local_tag(dc)
                if dtag == "Data":
                    name = dc.attrib.get("Name")
                    if name:
                        data[name] = (dc.text or "").strip()

    return data


def _extract_dict_record(rec: dict[str, Any]) -> dict[str, Any]:
    """Normalize a pre-extracted Sysmon dict into a flat field dictionary."""
    flat: dict[str, Any] = {}

    # Handle EVTX-to-dict wrapper if present: {"Event": ...}
    if "Event" in rec and isinstance(rec["Event"], dict):
        rec = rec["Event"]

    # System block
    system = rec.get("System")
    if isinstance(system, dict):
        for k, v in system.items():
            if k == "TimeCreated" and isinstance(v, dict):
                st = v.get("@SystemTime") or v.get("SystemTime")
                if st:
                    flat["TimeCreated"] = str(st).strip()
            elif isinstance(v, (str, int, float)):
                flat[k] = str(v).strip()

    # EventData block
    event_data = rec.get("EventData")
    if isinstance(event_data, dict):
        for k, v in event_data.items():
            if isinstance(v, (str, int, float)):
                flat[k] = str(v).strip()
            elif isinstance(v, dict) and "text" in v:
                flat[k] = str(v["text"]).strip()
    elif isinstance(event_data, list):
        for item in event_data:
            if isinstance(item, dict):
                name = item.get("@Name") or item.get("Name")
                val = item.get("#text") or item.get("text") or item.get("Value") or item.get("@Value")
                if name and val is not None:
                    flat[name] = str(val).strip()

    # Top-level keys override/merge
    for k, v in rec.items():
        if k not in ("System", "EventData", "Event") and isinstance(v, (str, int, float)):
            flat[k] = str(v).strip()

    return flat


def parse_sysmon_eid1(
    record: str | bytes | dict[str, Any] | ET.Element | Any,
    *,
    site_id: str = "site-01",
    scenario_id: str = "T1566.001",
    event_id: str | None = None,
    severity_id: int = 3,
    **ext_kwargs: Any,
) -> dict[str, Any]:
    """Parse a Sysmon Event ID 1 (Process Creation) record into an OCSF-compatible event dict.

    Target schema: OCSF Class 1007 (Process Activity), matching ocsf.py's
    build_process_activity structure exactly.

    Parameters:
        record: A Sysmon EID 1 event as an XML string/bytes, python-evtx Record,
                ElementTree Element, or pre-extracted dict.
        site_id: Deployment site ID (default "site-01").
        scenario_id: Scenario or ATT&CK scenario tag (default "T1566.001").
        event_id: Optional explicit event ID override.
        severity_id: OCSF severity ID (default 3: Medium).
        **ext_kwargs: Additional defence extensions merged into `unmapped`.

    Returns:
        OCSF-compatible dict with class_uid 1007.

    Raises:
        SysmonParseError: When record is malformed, truncated, wrong event type,
                          or missing mandatory fields.
    """
    if record is None:
        raise SysmonParseError("Sysmon record cannot be None")

    if isinstance(record, (str, bytes)):
        clean_str = record.decode("utf-8", errors="replace").strip() if isinstance(record, bytes) else record.strip()
        if not clean_str:
            raise SysmonParseError("Sysmon record string is empty")
        if clean_str.startswith("{"):
            try:
                parsed_json = json.loads(clean_str)
                if not isinstance(parsed_json, dict):
                    raise SysmonParseError("JSON record must be an object")
                flat = _extract_dict_record(parsed_json)
            except json.JSONDecodeError as e:
                raise SysmonParseError(f"Malformed JSON Sysmon record: {e}") from e
        else:
            flat = _parse_xml_record(record)
    elif ET.iselement(record):
        flat = _parse_xml_record(record)
    elif isinstance(record, dict):
        if not record:
            raise SysmonParseError("Sysmon record dictionary is empty")
        flat = _extract_dict_record(record)
    elif hasattr(record, "xml") and callable(record.xml):
        # Support python-evtx Record objects
        try:
            xml_text = record.xml()
        except Exception as e:
            raise SysmonParseError(f"Failed to read XML from EVTX record: {e}") from e
        flat = _parse_xml_record(xml_text)
    else:
        raise SysmonParseError(f"Unsupported record type: {type(record).__name__}")

    # Validate Event ID: must be 1 if present
    eid = flat.get("EventID")
    if eid is not None and str(eid).strip() and str(eid).strip() != "1":
        raise SysmonParseError(f"Expected Sysmon Event ID 1 (Process Creation), got {eid}")

    # Validate required Image field
    image = flat.get("Image") or flat.get("image")
    if not image or not str(image).strip():
        raise SysmonParseError("Sysmon EID 1 record missing required 'Image' field")
    image = str(image).strip()

    process_name = _extract_process_name(image)
    if not process_name:
        raise SysmonParseError("Failed to extract valid process name from 'Image' field")

    # Validate required CommandLine field
    if "CommandLine" not in flat and "command_line" not in flat and "cmd_line" not in flat:
        raise SysmonParseError("Sysmon EID 1 record missing required 'CommandLine' field")
    cmd_line = flat.get("CommandLine")
    if cmd_line is None:
        cmd_line = flat.get("command_line", flat.get("cmd_line", ""))
    cmd_line = str(cmd_line).strip()

    # Validate required User field
    user = flat.get("User") or flat.get("user")
    if not user or not str(user).strip():
        raise SysmonParseError("Sysmon EID 1 record missing required 'User' field")
    user = str(user).strip()

    # Validate required timestamp
    raw_time = (
        flat.get("UtcTime")
        or flat.get("TimeCreated")
        or flat.get("time")
        or flat.get("event_time")
    )
    if not raw_time or not str(raw_time).strip():
        raise SysmonParseError("Sysmon EID 1 record missing required timestamp field ('UtcTime' or 'TimeCreated')")
    normalized_time = _normalize_timestamp(str(raw_time))

    # Host / device
    host = (
        flat.get("Computer")
        or flat.get("ComputerName")
        or flat.get("host")
        or flat.get("hostname")
        or "unknown-host"
    )
    host = str(host).strip()

    # Parent process name
    parent_image = flat.get("ParentImage") or flat.get("parent_image") or ""
    parent_name = _extract_process_name(str(parent_image))

    # Determine event_id
    if not event_id:
        if "event_id" in flat and flat["event_id"]:
            event_id = str(flat["event_id"]).strip()
        elif "EventRecordID" in flat and flat["EventRecordID"]:
            event_id = f"SYSMON-{flat['EventRecordID']}"
        elif "ProcessGuid" in flat and flat["ProcessGuid"]:
            guid = str(flat["ProcessGuid"]).strip().strip("{}")
            event_id = f"SYSMON-{guid}"
        else:
            raise SysmonParseError(
                "Sysmon EID 1 record missing event identifier (event_id, EventRecordID, or ProcessGuid)"
            )

    # Split domain and username if present
    raw_user = user
    if "\\" in raw_user:
        domain, username = raw_user.split("\\", 1)
    elif "@" in raw_user:
        username, domain = raw_user.split("@", 1)
    else:
        domain, username = "", raw_user

    ev = ocsf.build_process_activity(
        event_id=event_id,
        time=normalized_time,
        user=username,
        host=host,
        process_name=process_name,
        cmd_line=cmd_line,
        parent_name=parent_name,
        site_id=site_id,
        scenario_id=scenario_id,
        severity_id=severity_id,
        **ext_kwargs,
    )

    if domain:
        ev["user"]["domain"] = domain

    # OCSF Process and Actor specifications
    ev["process"]["file"] = {
        "path": image,
        "name": process_name,
    }

    actor_user: dict[str, Any] = {"name": username, "type": "User"}
    if domain:
        actor_user["domain"] = domain

    ev["actor"] = {
        "user": actor_user,
        "process": {
            "name": parent_name,
            "file": {
                "path": str(parent_image),
                "name": parent_name,
            },
        },
    }

    return ev


# Aliases for convenience and caller compatibility
parse_sysmon_event = parse_sysmon_eid1
sysmon_to_ocsf = parse_sysmon_eid1
