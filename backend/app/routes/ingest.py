"""Forensic log ingestion routes (Sysmon, auditd, SSH auth.log, Zeek).

Parses raw log events into OCSF-compatible dictionaries and pipes them
into the live detection and graph pipeline with source="live".
"""
from __future__ import annotations

import json
import re
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlmodel import Session

from ..database import get_session
from ..schemas import IngestResponse, RawIngestRequest
from ..services import pipeline
from ..services.parsers.auditd_to_ocsf import AuditdParseError, parse_execve, parse_file_watch
from ..services.parsers.ssh_auth_to_ocsf import SshAuthParseError, parse_auth_log_line
from ..services.parsers.sysmon_to_ocsf import SysmonParseError, parse_sysmon_eid1
from ..services.parsers.zeek_to_ocsf import ZeekParseError, parse_conn_log

router = APIRouter(prefix="/api/ingest", tags=["ingest"])

_AUDITD_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def _parse_auditd_line(line: str) -> dict[str, Any]:
    matches = _AUDITD_KV_RE.findall(line)
    if not matches:
        return {}
    d: dict[str, Any] = {}
    for k, v_quoted, v_unquoted in matches:
        d[k] = v_quoted if v_quoted != "" else v_unquoted
    m = re.search(r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)", line)
    if m:
        d["time"] = m.group(1)
        d["serial"] = m.group(2)
        d["event_id"] = f"auditd-{m.group(1)}-{m.group(2)}"
    return d


def _parse_single_record(record: Any, source_type: str, site_id: str) -> dict[str, Any]:
    if source_type in ("sysmon", "sysmon_eid1"):
        return parse_sysmon_eid1(record, site_id=site_id)
    elif source_type in ("auditd_execve", "execve"):
        if isinstance(record, str) and not record.strip().startswith("{"):
            record = _parse_auditd_line(record)
        elif isinstance(record, dict):
            record = dict(record)
            if "serial" not in record and "event_id" not in record:
                m = re.search(r"audit\((\d+(?:\.\d+)?):(\d+)\)", str(record.get("msg", "")))
                if m:
                    record["time"] = record.get("time") or m.group(1)
                    record["serial"] = m.group(2)
        return parse_execve(record, site_id=site_id)
    elif source_type in ("auditd_file", "file_watch"):
        if isinstance(record, str) and not record.strip().startswith("{"):
            record = _parse_auditd_line(record)
        elif isinstance(record, dict):
            record = dict(record)
            if "serial" not in record and "event_id" not in record:
                m = re.search(r"audit\((\d+(?:\.\d+)?):(\d+)\)", str(record.get("msg", "")))
                if m:
                    record["time"] = record.get("time") or m.group(1)
                    record["serial"] = m.group(2)
        return parse_file_watch(record, site_id=site_id)
    elif source_type in ("ssh_auth", "auth_log", "auth"):
        if isinstance(record, dict):
            line = record.get("message") or record.get("line") or str(record)
        else:
            line = str(record)
        return parse_auth_log_line(line, site_id=site_id)
    elif source_type in ("zeek", "zeek_conn", "conn_log"):
        return parse_conn_log(record, site_id=site_id)
    else:
        raise ValueError(f"Unsupported source_type: '{source_type}'")


@router.post("/raw", response_model=IngestResponse)
def ingest_raw(
    req: RawIngestRequest,
    session: Session = Depends(get_session),
) -> IngestResponse:
    if not req.records:
        return IngestResponse(
            source_type=req.source_type,
            ingested=0,
            duplicates=0,
            errors=["No records provided"],
            status="no_data",
        )

    parsed_events: list[dict[str, Any]] = []
    errors: list[str] = []

    for idx, rec in enumerate(req.records):
        try:
            ocsf_ev = _parse_single_record(rec, req.source_type, req.site_id)
            parsed_events.append(ocsf_ev)
        except Exception as e:
            errors.append(f"Record {idx}: {e}")

    if not parsed_events:
        return IngestResponse(
            source_type=req.source_type,
            ingested=0,
            duplicates=0,
            errors=errors,
            status="error",
        )

    res = pipeline.ingest_events(session, parsed_events, source="live")
    return IngestResponse(
        source_type=req.source_type,
        ingested=res.get("ingested", 0),
        duplicates=res.get("duplicates", 0),
        errors=errors,
        incident_id=res.get("incident_id"),
        status="success" if not errors else "partial",
    )


@router.post("/file", response_model=IngestResponse)
async def ingest_file(
    file: UploadFile = File(...),
    source_type: str = Form(...),
    site_id: str = Form("site-01"),
    session: Session = Depends(get_session),
) -> IngestResponse:
    content = await file.read()
    text = content.decode("utf-8", errors="replace")

    records: list[Any] = []
    if source_type in ("sysmon", "sysmon_eid1"):
        xml_events = re.findall(r"<Event[\s\S]*?<\/Event>", text)
        if xml_events:
            records = xml_events
        else:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        records.append(line)
    elif source_type in ("zeek", "zeek_conn", "conn_log"):
        fields: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split()[1:]
                continue
            if line.startswith("#"):
                continue
            if fields:
                parts = line.split("\t")
                if len(parts) == len(fields):
                    records.append(dict(zip(fields, parts)))
                else:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        records.append(line)
            else:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    records.append(line)
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append(line)

    req = RawIngestRequest(source_type=source_type, records=records, site_id=site_id)
    return ingest_raw(req, session)
