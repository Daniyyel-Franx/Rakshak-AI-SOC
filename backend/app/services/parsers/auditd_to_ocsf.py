"""Linux auditd events to OCSF parser.

Target schemas:
- EXECVE -> OCSF Process Activity (class_uid 1007) via ocsf.build_process_activity()
- File watch rule -> OCSF File Activity (class_uid 1001) via ocsf.build_file_activity()
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from .. import ocsf


class AuditdParseError(ValueError):
    """Raised when an auditd record is malformed, truncated, or missing required fields."""
    pass


def _extract_process_name(path_or_exe: str) -> str:
    """Extract executable name from path."""
    if not path_or_exe:
        return ""
    clean = path_or_exe.strip().strip('"').strip("'")
    return clean.replace("\\", "/").split("/")[-1]


def _normalize_auditd_timestamp(ts: Any) -> str:
    """Normalize auditd timestamp (epoch, msg=audit(epoch:serial), or ISO) to ISO-8601 UTC string."""
    if ts is None:
        raise AuditdParseError("Missing timestamp")

    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
        except Exception as e:
            raise AuditdParseError(f"Invalid numeric epoch timestamp '{ts}': {e}") from e

    s = str(ts).strip()
    if not s:
        raise AuditdParseError("Empty timestamp")

    # Match audit(1705284000.123:456)
    m = re.search(r"audit\((\d+(?:\.\d+)?)(?::\d+)?\)", s)
    if m:
        epoch_str = m.group(1)
        try:
            return datetime.fromtimestamp(float(epoch_str), tz=timezone.utc).isoformat()
        except Exception as e:
            raise AuditdParseError(f"Invalid audit epoch timestamp '{epoch_str}': {e}") from e

    # Raw epoch string e.g. "1705284000.123"
    try:
        val = float(s)
        return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
    except ValueError:
        pass

    # Try ISO parsing
    try:
        if " " in s and "T" not in s:
            dt = datetime.fromisoformat(s.replace(" ", "T"))
        elif s.endswith("Z"):
            dt = datetime.fromisoformat(s[:-1] + "+00:00")
        else:
            dt = datetime.fromisoformat(s)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception as e:
        raise AuditdParseError(f"Invalid timestamp format '{s}': {e}") from e


def _clean_arg(val: Any) -> str:
    """Unquote or clean an argument string from auditd execve."""
    if val is None:
        return ""
    s = str(val).strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1]
    return s


def parse_execve(
    record: dict[str, Any] | str,
    *,
    site_id: str = "site-01",
    scenario_id: str = "SCENARIO_1_SSH_COMPROMISE",
    event_id: str | None = None,
    severity_id: int = 3,
    **ext_kwargs: Any,
) -> dict[str, Any]:
    """Parse an auditd EXECVE record into an OCSF Process Activity event.

    Reconstructs cmd_line from a0..aN in order.
    """
    if record is None:
        raise AuditdParseError("Auditd record cannot be None")

    if isinstance(record, str):
        s = record.strip()
        if not s:
            raise AuditdParseError("Auditd record string is empty")
        try:
            record = json.loads(s)
        except json.JSONDecodeError as e:
            raise AuditdParseError(f"Malformed JSON auditd record: {e}") from e

    if not isinstance(record, dict) or not record:
        raise AuditdParseError("Auditd record must be a non-empty dictionary")

    # Reconstruct command line from a0..aN in order
    args: list[str] = []
    if "argc" in record:
        try:
            argc = int(record["argc"])
            if argc < 1:
                raise AuditdParseError(f"Invalid argc: {argc}")
            for i in range(argc):
                key = f"a{i}"
                if key not in record:
                    raise AuditdParseError(f"Missing argument '{key}' for argc={argc}")
                args.append(_clean_arg(record[key]))
        except ValueError as e:
            raise AuditdParseError(f"Invalid argc value '{record['argc']}': {e}") from e
    else:
        # Scan for existing a0, a1, ... keys in order
        i = 0
        while f"a{i}" in record:
            args.append(_clean_arg(record[f"a{i}"]))
            i += 1

    if args:
        cmd_line = " ".join(args)
    elif "cmd_line" in record:
        cmd_line = str(record["cmd_line"]).strip()
    elif "command_line" in record:
        cmd_line = str(record["command_line"]).strip()
    elif "exe" in record:
        cmd_line = str(record["exe"]).strip()
    else:
        raise AuditdParseError("Missing executable arguments (a0..aN or cmd_line) in execve record")

    # Executable path
    exe = record.get("exe") or (args[0] if args else None)
    if not exe or not str(exe).strip():
        raise AuditdParseError("Missing 'exe' or 'a0' in execve record")
    exe = str(exe).strip()
    process_name = _extract_process_name(exe)
    if not process_name:
        raise AuditdParseError("Could not extract valid process name from exe")

    # User identification
    user = (
        record.get("user")
        or record.get("auid")
        or record.get("uid")
        or record.get("comm_user")
    )
    if user is None or not str(user).strip():
        raise AuditdParseError("Missing user/auid/uid in execve record")
    user = str(user).strip()

    # Timestamp
    raw_time = (
        record.get("time")
        or record.get("epoch")
        or record.get("timestamp")
        or record.get("msg")
    )
    if raw_time is None or (isinstance(raw_time, str) and not raw_time.strip()):
        raise AuditdParseError("Missing timestamp in execve record")
    normalized_time = _normalize_auditd_timestamp(raw_time)

    # Host
    host = record.get("host") or record.get("node") or record.get("hostname") or "unknown-host"
    host = str(host).strip()

    # Parent process name
    parent_name = str(record.get("parent_name") or record.get("comm") or "")
    if parent_name == process_name:
        parent_name = ""

    # Event ID
    if not event_id:
        if "event_id" in record and record["event_id"]:
            event_id = str(record["event_id"]).strip()
        elif "serial" in record and record["serial"]:
            event_id = f"AUDITD-{record['serial']}"
        elif "id" in record and record["id"]:
            event_id = f"AUDITD-{record['id']}"
        else:
            raise AuditdParseError("Missing event identifier (event_id, serial, or id) in execve record")

    ev = ocsf.build_process_activity(
        event_id=event_id,
        time=normalized_time,
        user=user,
        host=host,
        process_name=process_name,
        cmd_line=cmd_line,
        parent_name=parent_name,
        site_id=site_id,
        scenario_id=scenario_id,
        severity_id=severity_id,
        **ext_kwargs,
    )

    ev["process"]["file"] = {
        "path": exe,
        "name": process_name,
    }
    ev["actor"] = {
        "user": {"name": user, "type": "User"},
        "process": {"name": parent_name} if parent_name else {},
    }

    return ev


def parse_file_watch(
    record: dict[str, Any] | str,
    *,
    site_id: str = "site-01",
    scenario_id: str = "SCENARIO_2_INSIDER_MISUSE",
    event_id: str | None = None,
    severity_id: int | None = None,
    **ext_kwargs: Any,
) -> dict[str, Any]:
    """Parse an auditd watch rule event into an OCSF File Activity event."""
    if record is None:
        raise AuditdParseError("Auditd record cannot be None")

    if isinstance(record, str):
        s = record.strip()
        if not s:
            raise AuditdParseError("Auditd record string is empty")
        try:
            record = json.loads(s)
        except json.JSONDecodeError as e:
            raise AuditdParseError(f"Malformed JSON auditd record: {e}") from e

    if not isinstance(record, dict) or not record:
        raise AuditdParseError("Auditd record must be a non-empty dictionary")

    # File path
    file_path = record.get("path") or record.get("name") or record.get("file_path")
    if not file_path or not str(file_path).strip():
        raise AuditdParseError("Missing required file 'path' or 'name' in file watch record")
    file_path = str(file_path).strip()
    file_name = file_path.replace("\\", "/").split("/")[-1]
    if not file_name:
        raise AuditdParseError("Invalid file path in file watch record")

    # User
    user = (
        record.get("user")
        or record.get("auid")
        or record.get("uid")
    )
    if user is None or not str(user).strip():
        raise AuditdParseError("Missing required user/auid/uid in file watch record")
    user = str(user).strip()

    # Host
    host = record.get("host") or record.get("node") or record.get("hostname") or "unknown-host"
    host = str(host).strip()

    # Key / Canary / Severity
    key = str(record.get("key") or "")
    is_canary = (key == "canary" or record.get("is_canary", False) or "canary" in file_path.lower())

    if severity_id is None:
        severity_id = 4 if key in ("cred_access", "persistence") or is_canary else 3

    # Timestamp
    raw_time = (
        record.get("time")
        or record.get("epoch")
        or record.get("timestamp")
        or record.get("msg")
    )
    if raw_time is None or (isinstance(raw_time, str) and not raw_time.strip()):
        raise AuditdParseError("Missing timestamp in file watch record")
    normalized_time = _normalize_auditd_timestamp(raw_time)

    # Event ID
    if not event_id:
        if "event_id" in record and record["event_id"]:
            event_id = str(record["event_id"]).strip()
        elif "serial" in record and record["serial"]:
            event_id = f"AUDITD-WATCH-{record['serial']}"
        elif "id" in record and record["id"]:
            event_id = f"AUDITD-WATCH-{record['id']}"
        elif "pid" in record and raw_time:
            event_id = f"AUDITD-WATCH-{record['pid']}"
        else:
            raise AuditdParseError("Missing event identifier (event_id or serial) in file watch record")

    ev = ocsf.build_file_activity(
        event_id=event_id,
        time=normalized_time,
        user=user,
        host=host,
        file_path=file_path,
        file_name=file_name,
        is_canary=is_canary,
        site_id=site_id,
        scenario_id=scenario_id,
        severity_id=severity_id,
        **ext_kwargs,
    )

    # Enrich with process that touched the file if available
    exe = record.get("exe")
    if exe:
        ev["process"] = {
            "name": _extract_process_name(str(exe)),
            "file": {"path": str(exe)},
        }

    return ev
