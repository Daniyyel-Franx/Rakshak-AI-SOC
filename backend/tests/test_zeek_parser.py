"""Tests for Zeek conn.log TSV -> OCSF Network Activity (class_uid 4001) parser."""
from __future__ import annotations

import pytest

from app.services import graph_builder, normalizer
from app.services.parsers.zeek_to_ocsf import ZeekParseError, parse_conn_log


@pytest.fixture
def zeek_normal_conn() -> dict:
    """Fixture with standard complete Zeek conn.log record matching Scenario 1 payload retrieval."""
    return {
        "ts": "1705284032.120",
        "uid": "CHkAv21xF39x318d41",
        "id.orig_h": "10.10.1.20",
        "id.orig_p": "49152",
        "id.resp_h": "127.0.0.1",
        "id.resp_p": "9",
        "proto": "tcp",
        "service": "http",
        "duration": "0.120",
        "orig_bytes": "512",
        "resp_bytes": "409600",
        "conn_state": "SF",
    }


@pytest.fixture
def zeek_dash_null_conn() -> dict:
    """Fixture containing Zeek '-' null markers (rejected/failed connection)."""
    return {
        "ts": "1705284035.500",
        "uid": "CRej123456789",
        "id.orig_h": "203.0.113.45",
        "id.orig_p": "55432",
        "id.resp_h": "10.10.1.10",
        "id.resp_p": "22",
        "proto": "tcp",
        "service": "-",
        "duration": "-",
        "orig_bytes": "-",
        "resp_bytes": "-",
        "conn_state": "REJ",
    }


def test_zeek_normal_conn_values_correct(zeek_normal_conn):
    """Verify parse_conn_log extracts accurate values from complete record."""
    result = parse_conn_log(zeek_normal_conn, site_id="site-01", scenario_id="SCENARIO_1_SSH_COMPROMISE")

    # Value-level assertions
    assert result["src_endpoint"]["ip"] == "10.10.1.20"
    assert result["src_endpoint"]["port"] == 49152
    assert result["dst_endpoint"]["ip"] == "127.0.0.1"
    assert result["dst_endpoint"]["port"] == 9
    assert result["connection_info"]["protocol_ver"] == "tcp"
    assert result["traffic"]["bytes_out"] == 512
    assert result["traffic"]["bytes_in"] == 409600
    assert result["traffic"]["duration_ms"] == 120
    assert result["event_id"] == "ZEEK-CHkAv21xF39x318d41"

    # OCSF schema assertions
    assert result["class_uid"] == 4001
    assert result["category_uid"] == 4
    assert result["event_class"] == "network_activity"

    # Pipeline integration: normalizer
    norm = normalizer.normalize(result)
    assert norm.event_class == "network_activity"
    assert norm.source_json.get("ip") == "10.10.1.20"
    assert norm.destination_json.get("ip") == "127.0.0.1"

    # Pipeline integration: graph_builder
    graph = graph_builder.build_graph([result])
    node_ids = {n["id"] for n in graph["nodes"]}
    assert "attacker_ip:10.10.1.20" in node_ids
    assert "target_host:127.0.0.1" in node_ids


def test_zeek_dash_fields_converted_to_none(zeek_dash_null_conn):
    """Confirm '-' fields are converted to None, and never passed through as literal '-' string."""
    result = parse_conn_log(zeek_dash_null_conn, site_id="site-01", scenario_id="SCENARIO_1_SSH_COMPROMISE")

    # 1. Direct value assertions on converted nulls
    assert result["traffic"]["duration_ms"] is None
    assert result["traffic"]["bytes_out"] is None
    assert result["traffic"]["bytes_in"] is None

    # 2. Assert no literal '-' marker exists in normalized raw unmapped fields
    zeek_raw = result["unmapped"]["zeek"]
    assert zeek_raw["service"] is None
    assert zeek_raw["duration"] is None
    assert zeek_raw["orig_bytes"] is None
    assert zeek_raw["resp_bytes"] is None

    # Verify no string value anywhere in zeek raw is '-'
    for k, v in zeek_raw.items():
        assert v != "-", f"Field {k} still contains literal '-' marker"

    # 3. Valid non-null fields remain intact
    assert result["src_endpoint"]["ip"] == "203.0.113.45"
    assert result["dst_endpoint"]["ip"] == "10.10.1.10"
    assert result["dst_endpoint"]["port"] == 22
    assert result["connection_info"]["protocol_ver"] == "tcp"

    # Pipeline integration: normalizer still accepts events with None traffic values
    norm = normalizer.normalize(result)
    assert norm.event_class == "network_activity"


@pytest.mark.parametrize(
    "malformed_record,error_match",
    [
        (
            # Missing ts
            {"id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2", "id.resp_p": 80},
            "Missing required timestamp",
        ),
        (
            # Missing source IP
            {"ts": "1705284000", "id.resp_h": "2.2.2.2", "id.resp_p": 80},
            "Missing required source IP",
        ),
        (
            # Missing destination IP
            {"ts": "1705284000", "id.orig_h": "1.1.1.1", "id.resp_p": 80},
            "Missing required destination IP",
        ),
        (
            # Missing destination port
            {"ts": "1705284000", "id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2"},
            "Missing required destination port",
        ),
        (
            # Destination port out of range
            {"ts": "1705284000", "id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2", "id.resp_p": 70000},
            "Destination port out of range",
        ),
        (
            # Destination port non-numeric
            {"ts": "1705284000", "id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2", "id.resp_p": "http"},
            "Invalid destination port value",
        ),
        (
            # Empty dict
            {},
            "must be a non-empty dictionary",
        ),
        (
            # None
            None,
            "cannot be None",
        ),
        (
            # Non-dict type
            [1, 2, 3],
            "must be a non-empty dictionary",
        ),
    ],
)
def test_parse_conn_log_malformed_input_raises_exception(malformed_record, error_match):
    """Assert malformed Zeek rows raise ZeekParseError with clear error messages."""
    with pytest.raises(ZeekParseError, match=error_match):
        parse_conn_log(malformed_record)
