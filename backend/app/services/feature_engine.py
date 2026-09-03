"""Behavioural feature extraction (UEBA-lite).

Features are computed deterministically from a window of events for one
identity (typically the acting user). Values are normalised to [0, 1] where
sensible so the deterministic risk formula behaves predictably.

A small in-repo baseline (known hosts / normal hours / typical bytes) is used
to decide "new" and "deviation" features. This is a prototype heuristic, not a
statistically calibrated model.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

# Prototype baseline knowledge (would be learned/persisted in production).
KNOWN_SOURCE_HOSTS = {
    "maint-user": {"maint-jump-01", "10.20.0.5"},
    "svc-backup": {"backup-01"},
    "admin": {"admin-ws-01"},
}
NORMAL_HOURS = range(8, 19)  # 08:00 - 18:59 local (UTC in prototype)
TYPICAL_BYTES = 50_000


def _parse_hour(ts: str) -> int:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
    except Exception:
        return 12


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


def compute_features(identity: str, events: Iterable[dict[str, Any]]) -> dict[str, float]:
    events = list(events)
    failed_auth = 0
    success_auth = 0
    src_hosts: set[str] = set()
    destinations: set[str] = set()
    privilege_actions = 0
    hours: list[int] = []
    total_bytes = 0
    decoy = 0
    zones: set[str] = set()

    for ev in events:
        cls = ev.get("event_class")
        unmapped = ev.get("unmapped") or {}
        hours.append(_parse_hour(ev.get("event_time") or ev.get("time") or ""))
        zones.add(unmapped.get("network_zone", "corp"))

        if cls == "authentication":
            if int(ev.get("status_id", 1)) == 2:
                failed_auth += 1
            else:
                success_auth += 1
            src = (ev.get("source") or ev.get("src_endpoint") or {})
            host = src.get("hostname") or src.get("ip")
            if host:
                src_hosts.add(host)
        elif cls == "network_activity":
            dst = (ev.get("destination") or ev.get("dst_endpoint") or {})
            d = dst.get("ip") or dst.get("hostname")
            if d:
                destinations.add(d)
            traffic = ev.get("traffic") or {}
            total_bytes += int(traffic.get("bytes_out", 0)) + int(traffic.get("bytes_in", 0))
        elif cls == "process_activity":
            proc = ev.get("process") or {}
            cmd = (proc.get("cmd_line") or "").lower()
            if any(k in cmd for k in ("sudo", "chmod 777", "useradd", "passwd", "systemctl", "chown root")):
                privilege_actions += 1
        elif cls == "file_activity":
            if unmapped.get("is_canary"):
                decoy += 1
        # decoy/deception marker on any class
        if unmapped.get("decoy_interaction"):
            decoy += 1

    known = KNOWN_SOURCE_HOSTS.get(identity, set())
    new_source_host = 1.0 if (src_hosts and not src_hosts.issubset(known)) else 0.0
    new_destination = _clamp(len(destinations) / 3.0) if destinations else 0.0

    off_hours = [h for h in hours if h not in NORMAL_HOURS]
    time_deviation = _clamp(len(off_hours) / max(1, len(hours))) if hours else 0.0

    # peer_group_deviation: crude proxy — high when both new host and privilege
    peer_group_deviation = _clamp(0.5 * new_source_host + 0.5 * _clamp(privilege_actions / 2.0))

    bytes_deviation = _clamp((total_bytes - TYPICAL_BYTES) / (TYPICAL_BYTES * 4)) if total_bytes else 0.0
    decoy_interaction = 1.0 if decoy else 0.0
    cross_zone_activity = 1.0 if len(zones) > 1 else 0.0

    return {
        "failed_auth_count_5m": float(failed_auth),
        "successful_auth_count_5m": float(success_auth),
        "new_source_host": new_source_host,
        "new_destination": new_destination,
        "privilege_action_count": float(privilege_actions),
        "time_deviation": time_deviation,
        "peer_group_deviation": peer_group_deviation,
        "bytes_deviation": bytes_deviation,
        "decoy_interaction": decoy_interaction,
        "cross_zone_activity": cross_zone_activity,
    }
