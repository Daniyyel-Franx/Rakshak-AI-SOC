"""Deterministic temporal attack-graph construction.

The LLM NEVER builds the graph. Given the same events (same order after a
stable sort), this produces identical nodes and edges, including IDs and
positions. ATT&CK labels are attached only where the event evidence supports
them.

Node types: attacker_ip, user, source_host, target_host, process, service,
file, payload, decoy, site, incident.
"""
from __future__ import annotations

from typing import Any

import networkx as nx

from .detection.sigma_engine import SigmaEngine

_SIGMA_ENGINE = SigmaEngine()

# Layer index controls deterministic left-to-right layout.
LAYER = {
    "site": 0,
    "attacker_ip": 1,
    "user": 2,
    "source_host": 3,
    "target_host": 4,
    "process": 5,
    "service": 5,
    "file": 6,
    "payload": 6,
    "decoy": 6,
    "incident": 7,
}

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_FROM_ID = {1: "low", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical"}


def _sev_name(sid: int) -> str:
    return SEV_FROM_ID.get(int(sid), "low")


def _max_sev(a: str, b: str) -> str:
    return a if SEV_RANK.get(a, 1) >= SEV_RANK.get(b, 1) else b


class _GraphState:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}

    def add_node(self, node_id: str, ntype: str, label: str, severity: str = "low",
                 evidence: list[str] | None = None, extra: dict[str, Any] | None = None) -> str:
        if node_id in self.nodes:
            n = self.nodes[node_id]
            n["data"]["severity"] = _max_sev(n["data"]["severity"], severity)
            for e in (evidence or []):
                if e not in n["data"]["evidence_event_ids"]:
                    n["data"]["evidence_event_ids"].append(e)
            return node_id
        self.nodes[node_id] = {
            "id": node_id,
            "type": ntype,
            "data": {
                "label": label,
                "entity_type": ntype,
                "severity": severity,
                "evidence_event_ids": list(evidence or []),
                **(extra or {}),
            },
        }
        return node_id

    def add_edge(self, edge_id: str, source: str, target: str, label: str, timestamp: str,
                 technique_id: str = "", technique_name: str = "",
                 evidence: list[str] | None = None, severity: str = "low",
                 animated: bool = False, extra: dict[str, Any] | None = None) -> None:
        if edge_id in self.edges:
            existing = self.edges[edge_id]
            for e in (evidence or []):
                if e not in existing["evidence_event_ids"]:
                    existing["evidence_event_ids"].append(e)
            existing["severity"] = _max_sev(existing["severity"], severity)
            existing["animated"] = existing["animated"] or animated
            if extra:
                existing.update(extra)
            return
        self.edges[edge_id] = {
            "id": edge_id,
            "source": source,
            "target": target,
            "label": label,
            "timestamp": timestamp,
            "technique_id": technique_id,
            "technique_name": technique_name,
            "evidence_event_ids": list(evidence or []),
            "severity": severity,
            "animated": animated,
            **(extra or {}),
        }


def _sort_key(ev: dict[str, Any]) -> tuple[str, str, str]:
    return (
        ev.get("event_time") or ev.get("time") or "",
        ev.get("received_time") or "",
        ev.get("event_id") or "",
    )


def build_graph(events: list[dict[str, Any]], incident_id: str = "", engine: SigmaEngine | None = None) -> dict[str, Any]:
    sigma_eng = engine or _SIGMA_ENGINE
    st = _GraphState()
    ordered = sorted(events, key=_sort_key)

    site_id = ""
    failed_auth_streak = 0

    for ev in ordered:
        eid = ev.get("event_id", "")
        cls = ev.get("event_class")
        ts = ev.get("event_time") or ev.get("time") or ""
        sev = _sev_name(ev.get("severity_id", 1))
        unmapped = ev.get("unmapped") or {}
        site_id = ev.get("site_id") or unmapped.get("site_id") or site_id

        if site_id:
            st.add_node(f"site:{site_id}", "site", f"Site {site_id}", "low")

        sigma_matches = sigma_eng.evaluate(ev)

        if cls == "authentication":
            src = ev.get("source") or ev.get("src_endpoint") or {}
            dst = ev.get("destination") or ev.get("dst_endpoint") or {}
            user = (ev.get("user") or {}).get("name", "unknown")
            ip = src.get("ip", "")
            shost = src.get("hostname") or ip or "unknown-src"
            thost = dst.get("hostname", "unknown-dst")
            success = int(ev.get("status_id", 1)) == 1

            ip_node = st.add_node(f"attacker_ip:{ip}", "attacker_ip", ip or "unknown-ip", sev, [eid]) if ip else ""
            user_node = st.add_node(f"user:{user}", "user", user, sev, [eid])
            shost_node = st.add_node(f"source_host:{shost}", "source_host", shost, sev, [eid])
            thost_node = st.add_node(f"target_host:{thost}", "target_host", thost,
                                     _max_sev("medium", sev), [eid])

            if ip_node:
                st.add_edge(f"e:ip_user:{ip}:{user}", ip_node, user_node, "authenticates as", ts,
                            evidence=[eid], severity=sev)
            st.add_edge(f"e:user_shost:{user}:{shost}", user_node, shost_node, "from host", ts,
                        evidence=[eid], severity=sev)

            if not success:
                failed_auth_streak += 1
            else:
                # successful auth after failures => brute force + SSH lateral movement
                tid, tname = ("T1021.004", "Remote Services: SSH")
                animated = True
                st.add_edge(f"e:shost_thost:{shost}:{thost}", shost_node, thost_node,
                            "SSH login", ts, tid, tname, [eid], _max_sev("high", sev), animated)
                if failed_auth_streak >= 2:
                    st.add_edge(f"e:bruteforce:{shost}:{thost}", shost_node, thost_node,
                                "brute-force then success", ts, "T1110", "Brute Force",
                                [eid], "high", True)
                failed_auth_streak = 0

        elif cls == "network_activity":
            src = ev.get("source") or ev.get("src_endpoint") or {}
            dst = ev.get("destination") or ev.get("dst_endpoint") or {}
            ip = src.get("ip", "")
            dip = dst.get("ip", "")
            url = (ev.get("url") or {}).get("url_string", "")
            src_node = st.add_node(f"attacker_ip:{ip}", "attacker_ip", ip or "src", sev, [eid]) if ip else ""
            if url or "payload" in (url.lower() if url else ""):
                pay_node = st.add_node(f"payload:{url or dip}", "payload",
                                       url or dip or "payload", _max_sev("high", sev), [eid],
                                       {"synthetic": True})
                anchor = src_node or st.add_node(f"attacker_ip:{dip}", "attacker_ip", dip, sev, [eid])
                st.add_edge(f"e:download:{anchor}:{url or dip}", anchor, pay_node,
                            "synthetic payload retrieval", ts, "T1105", "Ingress Tool Transfer",
                            [eid], "high", True)
            elif dip:
                dst_node = st.add_node(f"target_host:{dip}", "target_host", dip, sev, [eid])
                anchor = src_node or dst_node
                st.add_edge(f"e:net:{anchor}:{dip}", anchor, dst_node, "network flow", ts,
                            evidence=[eid], severity=sev)

        elif cls in ("process_activity", "process_access"):
            user = (ev.get("user") or {}).get("name", "unknown")
            host = (ev.get("device") or {}).get("hostname", "unknown-host")
            proc = ev.get("process") or {}
            pname = proc.get("name", "process")
            cmd = proc.get("cmd_line", "")
            host_node = st.add_node(f"target_host:{host}", "target_host", host, _max_sev("medium", sev), [eid])
            user_node = st.add_node(f"user:{user}", "user", user, sev, [eid])
            proc_node = st.add_node(f"process:{host}:{pname}", "process", pname,
                                    _max_sev("high", sev), [eid], {"cmd_line": cmd})
            if sigma_matches:
                match = sigma_matches[0]
                tid = match.technique_ids[0] if match.technique_ids else ""
                tname = match.rule_title
                st.add_edge(f"e:host_proc:{host}:{pname}", host_node, proc_node, "executes", ts,
                            tid, tname, [eid], _max_sev("high", sev), True, extra={"evidence": match.evidence})
                st.add_edge(f"e:user_proc:{user}:{pname}", user_node, proc_node, "spawned by", ts,
                            evidence=[eid], severity=sev)
            else:
                tid, tname = "", ""
                if any(s in cmd.lower() for s in ("bash", "sh -c", "curl", "wget")):
                    tid, tname = "T1059.004", "Command and Scripting Interpreter: Unix Shell"
                st.add_edge(f"e:host_proc:{host}:{pname}", host_node, proc_node, "executes", ts,
                            tid, tname, [eid], _max_sev("high", sev), True)
                st.add_edge(f"e:user_proc:{user}:{pname}", user_node, proc_node, "spawned by", ts,
                            evidence=[eid], severity=sev)
                # payload download initiated by process
                if any(s in cmd.lower() for s in ("curl", "wget", "http://", "https://")):
                    pay = st.add_node(f"payload:{pname}:{eid}", "payload", "synthetic payload",
                                      "high", [eid], {"synthetic": True})
                    st.add_edge(f"e:proc_payload:{pname}:{eid}", proc_node, pay,
                                "downloads (synthetic)", ts, "T1105", "Ingress Tool Transfer",
                                [eid], "high", True)

        elif cls == "file_activity":
            user = (ev.get("user") or {}).get("name", "unknown")
            host = (ev.get("device") or {}).get("hostname", "unknown-host")
            f = ev.get("file") or {}
            path = f.get("path", "file")
            is_canary = bool(unmapped.get("is_canary"))
            user_node = st.add_node(f"user:{user}", "user", user, sev, [eid])
            if sigma_matches:
                match = sigma_matches[0]
                tid = match.technique_ids[0] if match.technique_ids else ""
                tname = match.rule_title
                node = st.add_node(f"file:{path}", "file", f.get("name", path),
                                   _max_sev("high", sev), [eid])
                st.add_edge(f"e:user_file:{user}:{path}", user_node, node, "accessed", ts,
                            tid, tname, [eid], _max_sev("high", sev), True, extra={"evidence": match.evidence})
            elif is_canary:
                node = st.add_node(f"decoy:{path}", "decoy", f"canary: {f.get('name', path)}",
                                   "critical", [eid], {"synthetic": True})
                st.add_edge(f"e:user_decoy:{user}:{path}", user_node, node,
                            "touched canary", ts, "T1005", "Data from Local System",
                            [eid], "critical", True)
            else:
                node = st.add_node(f"file:{path}", "file", f.get("name", path),
                                   _max_sev("medium", sev), [eid])
                st.add_edge(f"e:user_file:{user}:{path}", user_node, node, "accessed", ts,
                            evidence=[eid], severity=sev)

    # attach incident node linking to the highest-severity entities
    if incident_id:
        inc = st.add_node(f"incident:{incident_id}", "incident", incident_id, "critical")
        for nid, n in list(st.nodes.items()):
            if nid == inc:
                continue
            if SEV_RANK.get(n["data"]["severity"], 1) >= SEV_RANK["high"]:
                st.add_edge(f"e:inc:{incident_id}:{nid}", inc, nid, "correlated", "",
                            evidence=[], severity="high", animated=False)

    _layout(st)
    return {
        "incident_id": incident_id,
        "nodes": list(st.nodes.values()),
        "edges": list(st.edges.values()),
    }


def _layout(st: _GraphState) -> None:
    """Deterministic layered layout by node type."""
    per_layer: dict[int, int] = {}
    for node in st.nodes.values():
        layer = LAYER.get(node["type"], 5)
        idx = per_layer.get(layer, 0)
        per_layer[layer] = idx + 1
        # Increase separation to avoid label collision
        node["position"] = {"x": float(layer * 280), "y": float(idx * 150)}


def ground_truth_counts(events: list[dict[str, Any]]) -> tuple[int, int]:
    g = build_graph(events)
    return len(g["nodes"]), len(g["edges"])


def graph_signature(graph: dict[str, Any]) -> tuple[frozenset[str], frozenset[str]]:
    """Return (node_ids, edge_ids) for deterministic comparison / F1 scoring."""
    nodes = frozenset(n["id"] for n in graph["nodes"])
    edges = frozenset(e["id"] for e in graph["edges"])
    return nodes, edges


def to_networkx(graph: dict[str, Any]) -> nx.DiGraph:
    g = nx.DiGraph()
    for n in graph["nodes"]:
        g.add_node(n["id"], **n["data"])
    for e in graph["edges"]:
        g.add_edge(e["source"], e["target"], **{k: v for k, v in e.items() if k not in ("source", "target")})
    return g
