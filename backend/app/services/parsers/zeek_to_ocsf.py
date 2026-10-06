"""Zeek conn.log TSV rows to OCSF Network Activity (class_uid 4001) parser."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .. import ocsf


class ZeekParseError(ValueError):
    """Raised when a Zeek record is malformed, truncated, or missing required fields."""
    pass


def _normalize_zeek_value(val: Any) -> Any:
    """Normalize Zeek '-' null markers into None."""
    if val is None or val == "-":
        return None
    if isinstance(val, str):
        s = val.strip()
        if s == "-":
            return None
        return s
    return val


def _normalize_zeek_timestamp(ts: Any) -> str:
    """Normalize Zeek timestamp (epoch float or ISO string) to ISO-8601 UTC."""
    if ts is None or ts == "-":
        raise ZeekParseError("Missing timestamp in Zeek record")

    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
        except Exception as e:
            raise ZeekParseError(f"Invalid epoch timestamp '{ts}': {e}") from e

    s = str(ts).strip()
    if not s or s == "-":
        raise ZeekParseError("Missing or empty timestamp in Zeek record")

    try:
        val = float(s)
        return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
    except ValueError:
        pass

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
        raise ZeekParseError(f"Invalid timestamp format '{s}': {e}") from e


def parse_conn_log(
    record: dict[str, Any] | str,
    *,
    site_id: str = "site-01",
    scenario_id: str = "SCENARIO_1_SSH_COMPROMISE",
    event_id: str | None = None,
    severity_id: int = 2,
    **ext_kwargs: Any,
) -> dict[str, Any]:
    """Parse a Zeek conn.log TSV row dictionary into an OCSF Network Activity event (class_uid 4001).

    Converts Zeek '-' null markers to None across all fields.
    """
    if record is None:
        raise ZeekParseError("Zeek record cannot be None")

    if isinstance(record, str):
        s = record.strip()
        if not s:
            raise ZeekParseError("Zeek record string is empty")
        try:
            record = json.loads(s)
        except json.JSONDecodeError as e:
            raise ZeekParseError(f"Malformed JSON Zeek record: {e}") from e

    if not isinstance(record, dict) or not record:
        raise ZeekParseError("Zeek record must be a non-empty dictionary")

    # Normalize all '-' fields to None
    norm: dict[str, Any] = {k: _normalize_zeek_value(v) for k, v in record.items()}

    # Timestamp
    raw_ts = norm.get("ts") or norm.get("time") or norm.get("timestamp")
    if raw_ts is None:
        raise ZeekParseError("Missing required timestamp ('ts') in Zeek record")
    normalized_time = _normalize_zeek_timestamp(raw_ts)

    # Source IP
    src_ip = norm.get("id.orig_h") or norm.get("src_ip") or norm.get("orig_h")
    if not src_ip or not str(src_ip).strip():
        raise ZeekParseError("Missing required source IP ('id.orig_h') in Zeek record")
    src_ip = str(src_ip).strip()

    # Destination IP
    dst_ip = norm.get("id.resp_h") or norm.get("dst_ip") or norm.get("resp_h")
    if not dst_ip or not str(dst_ip).strip():
        raise ZeekParseError("Missing required destination IP ('id.resp_h') in Zeek record")
    dst_ip = str(dst_ip).strip()

    # Destination Port
    raw_dst_port = norm.get("id.resp_p") if "id.resp_p" in norm else (norm.get("dst_port") or norm.get("resp_p"))
    if raw_dst_port is None:
        raise ZeekParseError("Missing required destination port ('id.resp_p') in Zeek record")
    try:
        dst_port = int(raw_dst_port)
        if not (0 <= dst_port <= 65535):
            raise ZeekParseError(f"Destination port out of range [0, 65535]: {dst_port}")
    except (ValueError, TypeError) as e:
        raise ZeekParseError(f"Invalid destination port value '{raw_dst_port}': {e}") from e

    # Source Port
    raw_src_port = norm.get("id.orig_p") if "id.orig_p" in norm else (norm.get("src_port") or norm.get("orig_p"))
    src_port: int | None = None
    if raw_src_port is not None:
        try:
            src_port = int(raw_src_port)
        except (ValueError, TypeError) as e:
            raise ZeekParseError(f"Invalid source port value '{raw_src_port}': {e}") from e

    # Protocol
    proto = str(norm.get("proto") or "tcp").lower()

    # Duration
    raw_dur = norm.get("duration")
    duration_ms: int | None = None
    if raw_dur is not None:
        try:
            duration_ms = int(float(raw_dur) * 1000)
        except (ValueError, TypeError) as e:
            raise ZeekParseError(f"Invalid duration value '{raw_dur}': {e}") from e

    # Bytes
    raw_orig_bytes = norm.get("orig_bytes") or norm.get("orig_ip_bytes")
    bytes_out: int | None = None
    if raw_orig_bytes is not None:
        try:
            bytes_out = int(raw_orig_bytes)
        except (ValueError, TypeError) as e:
            raise ZeekParseError(f"Invalid orig_bytes value '{raw_orig_bytes}': {e}") from e

    raw_resp_bytes = norm.get("resp_bytes") or norm.get("resp_ip_bytes")
    bytes_in: int | None = None
    if raw_resp_bytes is not None:
        try:
            bytes_in = int(raw_resp_bytes)
        except (ValueError, TypeError) as e:
            raise ZeekParseError(f"Invalid resp_bytes value '{raw_resp_bytes}': {e}") from e

    # Event ID
    if not event_id:
        uid = norm.get("uid")
        if uid:
            event_id = f"ZEEK-{uid}"
        else:
            event_id = f"ZEEK-{src_ip}-{dst_ip}-{dst_port}"

    # Build base OCSF network activity event
    ev = ocsf.build_network_activity(
        event_id=event_id,
        time=normalized_time,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=proto,
        bytes_out=bytes_out if bytes_out is not None else 0,
        bytes_in=bytes_in if bytes_in is not None else 0,
        duration_ms=duration_ms if duration_ms is not None else 0,
        url=str(norm.get("url") or ""),
        site_id=site_id,
        scenario_id=scenario_id,
        severity_id=severity_id,
        **ext_kwargs,
    )

    # Reflect None explicitly in traffic when Zeek marker was '-'
    ev["traffic"] = {
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "duration_ms": duration_ms,
    }

    if src_port is not None:
        ev["src_endpoint"]["port"] = src_port

    service = norm.get("service")
    if service is not None:
        ev["connection_info"]["service"] = service

    conn_state = norm.get("conn_state")
    if conn_state is not None:
        ev["connection_info"]["state"] = conn_state

    # Store normalized Zeek raw record (all '-' values are None)
    ev["unmapped"]["zeek"] = norm

    return ev
