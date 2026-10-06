---
name: ocsf-contract
description: Use when writing or editing any log parser (Sysmon, auditd, Zeek) that must emit OCSF-shaped events matching ocsf.py's existing field structure.
---

Target schema (from backend/app/services/ocsf.py — do not redesign):
- Process events → class_uid 1007, fields: actor.user.name, actor.user.domain,
  process.file.path, process.cmd_line, time
- Network events → class_uid 4001, fields: src_endpoint.ip, dst_endpoint.ip,
  dst_endpoint.port, connection_info.protocol_name, time

Every new parser must emit dicts matching this shape exactly — field names,
nesting, and types — so normalizer.py and graph_builder.py work unchanged.
Do not invent new field names even if they seem clearer.