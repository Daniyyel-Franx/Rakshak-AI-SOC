"""OpenSSH syslog auth lines to OCSF Authentication (class_uid 3002) parser."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .. import ocsf


class SshAuthParseError(ValueError):
    """Raised when an SSH auth log line cannot be parsed or is malformed."""
    pass


# Matches both RFC 3164 (Jan 15 02:00:20) and RFC 5424 (2026-01-15T02:00:20...)
_SYSLOG_PREFIX_RE = re.compile(
    r"^(?:(?P<ts_iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)|"
    r"(?P<ts_bsd>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+"
    r"(?:(?P<host>[a-zA-Z0-9._-]+)\s+)?"
    r"(?:sshd(?:\[(?P<pid>\d+)\])?:\s+)?"
)

_SSH_AUTH_RE = re.compile(
    r"(?P<action>Accepted|Failed)\s+"
    r"(?P<auth_method>[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)?)\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+)"
    r"(?:\s+port\s+(?P<port>\d+))?"
    r"(?:\s+ssh2)?"
)


def _parse_timestamp(raw_iso: str | None, raw_bsd: str | None, fallback_year: int = 2026) -> str:
    """Parse extracted syslog timestamp into standard ISO-8601 UTC."""
    if raw_iso:
        s = raw_iso.strip()
        if " " in s and "T" not in s:
            dt = datetime.fromisoformat(s.replace(" ", "T"))
        elif s.endswith("Z"):
            dt = datetime.fromisoformat(s[:-1] + "+00:00")
        else:
            dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    if raw_bsd:
        s = re.sub(r"\s+", " ", raw_bsd.strip())
        dt = datetime.strptime(f"{fallback_year} {s}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    raise SshAuthParseError("Missing timestamp in auth log line")


def parse_auth_log_line(
    line: str,
    *,
    site_id: str = "site-01",
    scenario_id: str = "SCENARIO_1_SSH_COMPROMISE",
    event_id: str | None = None,
    time: str | None = None,
    host: str | None = None,
    severity_id: int | None = None,
    **ext_kwargs: Any,
) -> dict[str, Any]:
    """Parse a raw sshd syslog line into an OCSF Authentication event (class_uid 3002).

    Parameters:
        line: Raw syslog string, e.g.
              "Jan 15 02:00:20 target-web-01 sshd[1234]: Accepted password for sysops from 203.0.113.45 port 54321 ssh2"
        site_id: Deployment site ID.
        scenario_id: Attack scenario ID.
        event_id: Explicit event ID override.
        time: Explicit timestamp override.
        host: Explicit destination host override.
        severity_id: OCSF severity ID override (defaults: 2 for success, 3 for failure).

    Returns:
        OCSF dict built via ocsf.build_authentication().
    """
    if line is None:
        raise SshAuthParseError("Auth log line cannot be None")

    if not isinstance(line, str):
        raise SshAuthParseError(f"Auth log line must be a string, got {type(line).__name__}")

    raw_line = line.strip()
    if not raw_line:
        raise SshAuthParseError("Auth log line is empty")

    # Match syslog prefix if present
    prefix_m = _SYSLOG_PREFIX_RE.match(raw_line)
    parsed_time = time
    parsed_host = host
    parsed_pid = None
    remainder = raw_line

    if prefix_m:
        if not parsed_time:
            parsed_time = _parse_timestamp(prefix_m.group("ts_iso"), prefix_m.group("ts_bsd"))
        if not parsed_host and prefix_m.group("host"):
            parsed_host = prefix_m.group("host")
        parsed_pid = prefix_m.group("pid")
        remainder = raw_line[prefix_m.end():]

    auth_m = _SSH_AUTH_RE.search(remainder)
    if not auth_m:
        raise SshAuthParseError(f"Line does not contain a recognized SSH auth event: '{line}'")

    action = auth_m.group("action")
    user = auth_m.group("user")
    src_ip = auth_m.group("ip")
    port_str = auth_m.group("port")
    port = int(port_str) if port_str else 22
    auth_method = auth_m.group("auth_method") or "password"

    success = (action == "Accepted")

    if not parsed_time:
        raise SshAuthParseError("Missing timestamp in auth log line and no time override provided")

    dst_host = parsed_host or "unknown-host"
    src_host = src_ip

    if severity_id is None:
        severity_id = 2 if success else 3

    if not event_id:
        if parsed_pid:
            event_id = f"SSH-{parsed_pid}-{port}"
        else:
            event_id = f"SSH-{src_ip}-{port}"

    ev = ocsf.build_authentication(
        event_id=event_id,
        time=parsed_time,
        user=user,
        src_ip=src_ip,
        src_host=src_host,
        dst_host=dst_host,
        success=success,
        auth_protocol="ssh",
        site_id=site_id,
        scenario_id=scenario_id,
        severity_id=severity_id,
        **ext_kwargs,
    )

    # Attach port info if present
    if port:
        ev["src_endpoint"]["port"] = port
        ev["auth_method"] = auth_method

    return ev
