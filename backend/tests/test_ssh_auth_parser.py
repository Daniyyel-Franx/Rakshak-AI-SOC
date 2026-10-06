"""Tests for SSH syslog authentication -> OCSF parser."""
from __future__ import annotations

import pytest

from app.services import graph_builder, normalizer
from app.services.parsers.ssh_auth_to_ocsf import SshAuthParseError, parse_auth_log_line


@pytest.fixture
def ssh_success_line() -> str:
    """Fixture for successful SSH login matching Scenario 1."""
    return "Jan 15 02:00:20 target-web-01 sshd[2845]: Accepted password for sysops from 203.0.113.45 port 54321 ssh2"


@pytest.fixture
def ssh_failure_line() -> str:
    """Fixture for failed SSH attempt matching Scenario 1 brute-force bursts."""
    return "Jan 15 02:00:05 target-web-01 sshd[2840]: Failed password for sysops from 203.0.113.45 port 54320 ssh2"


def test_ssh_auth_success_values_correct(ssh_success_line):
    """Verify parse_auth_log_line on successful authentication."""
    result = parse_auth_log_line(ssh_success_line, site_id="site-01", scenario_id="SCENARIO_1_SSH_COMPROMISE")

    # Value-level assertions
    assert result["user"]["name"] == "sysops"
    assert result["src_endpoint"]["ip"] == "203.0.113.45"
    assert result["src_endpoint"]["port"] == 54321
    assert result["dst_endpoint"]["hostname"] == "target-web-01"
    assert result["is_success"] is True
    assert result["status_id"] == 1
    assert result["activity_id"] == 1
    assert result["class_uid"] == 3002
    assert result["event_class"] == "authentication"
    assert result["time"] == "2026-01-15T02:00:20+00:00"

    # Pipeline integration: normalizer
    norm = normalizer.normalize(result)
    assert norm.event_class == "authentication"
    assert norm.user_json.get("name") == "sysops"
    assert norm.source_json.get("ip") == "203.0.113.45"

    # Pipeline integration: graph_builder
    graph = graph_builder.build_graph([result])
    node_ids = {n["id"] for n in graph["nodes"]}
    assert "attacker_ip:203.0.113.45" in node_ids
    assert "user:sysops" in node_ids
    assert "target_host:target-web-01" in node_ids


def test_ssh_auth_failure_values_correct(ssh_failure_line):
    """Verify parse_auth_log_line on failed authentication."""
    result = parse_auth_log_line(ssh_failure_line, site_id="site-01", scenario_id="SCENARIO_1_SSH_COMPROMISE")

    # Value-level assertions
    assert result["user"]["name"] == "sysops"
    assert result["src_endpoint"]["ip"] == "203.0.113.45"
    assert result["src_endpoint"]["port"] == 54320
    assert result["dst_endpoint"]["hostname"] == "target-web-01"
    assert result["is_success"] is False
    assert result["status_id"] == 2
    assert result["activity_id"] == 2
    assert result["class_uid"] == 3002
    assert result["event_class"] == "authentication"
    assert result["time"] == "2026-01-15T02:00:05+00:00"

    # Pipeline integration: normalizer
    norm = normalizer.normalize(result)
    assert norm.event_class == "authentication"
    assert norm.status_id == 2


@pytest.mark.parametrize(
    "malformed_line,error_match",
    [
        (
            # Random unrelated syslog message
            "Jan 15 02:00:00 host kernel: [    0.000000] Linux version 6.5.0",
            "does not contain a recognized SSH auth event",
        ),
        (
            # Incomplete SSH log line
            "Jan 15 02:00:20 host sshd[123]: Accepted password for",
            "does not contain a recognized SSH auth event",
        ),
        (
            # Missing IP
            "Jan 15 02:00:20 host sshd[123]: Failed password for root from",
            "does not contain a recognized SSH auth event",
        ),
        (
            # Missing timestamp with no override
            "Accepted password for sysops from 203.0.113.45 port 22 ssh2",
            "Missing timestamp in auth log line",
        ),
        (
            # Empty string
            "",
            "Auth log line is empty",
        ),
        (
            # None
            None,
            "cannot be None",
        ),
        (
            # Unsupported type
            ["invalid"],
            "must be a string",
        ),
    ],
)
def test_parse_auth_log_line_malformed_input_raises_exception(malformed_line, error_match):
    """Assert malformed or unparseable lines raise SshAuthParseError."""
    with pytest.raises(SshAuthParseError, match=error_match):
        parse_auth_log_line(malformed_line)
