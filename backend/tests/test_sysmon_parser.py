"""Tests for Windows Sysmon EID 1 (Process Creation) -> OCSF parser."""
from __future__ import annotations

import pytest

from app.services import graph_builder, normalizer, ocsf
from app.services.parsers.sysmon_to_ocsf import SysmonParseError, parse_sysmon_eid1


SAMPLE_EID1_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-01-15T02:15:30.123456Z" />
    <EventRecordID>1042</EventRecordID>
    <Correlation />
    <Execution ProcessID="2468" ThreadID="3579" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>FIN-WS-01.corp.local</Computer>
    <Security UserID="S-1-5-21-123456789-1001" />
  </System>
  <EventData>
    <Data Name="RuleName">technique_id=T1059.003,technique_name=Windows Command Shell</Data>
    <Data Name="UtcTime">2026-01-15 02:15:30.123</Data>
    <Data Name="ProcessGuid">{5770385F-0000-0000-0000-000000000001}</Data>
    <Data Name="ProcessId">4912</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="FileVersion">10.0.19041.1</Data>
    <Data Name="Description">Windows Command Processor</Data>
    <Data Name="Product">Microsoft® Windows® Operating System</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">Cmd.Exe</Data>
    <Data Name="CommandLine">cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc SUVY...</Data>
    <Data Name="CurrentDirectory">C:\\Users\\victim\\Downloads\\</Data>
    <Data Name="User">CORP\\victim</Data>
    <Data Name="LogonGuid">{5770385F-0000-0000-0000-000000000002}</Data>
    <Data Name="LogonId">0x3e7</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">Medium</Data>
    <Data Name="Hashes">SHA256=A1B2C3D4E5F67890</Data>
    <Data Name="ParentProcessGuid">{5770385F-0000-0000-0000-000000000003}</Data>
    <Data Name="ParentProcessId">2840</Data>
    <Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
    <Data Name="ParentCommandLine">"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "Q4_Invoice.docm"</Data>
    <Data Name="ParentUser">CORP\\victim</Data>
  </EventData>
</Event>"""


SAMPLE_EID1_DICT = {
    "EventID": 1,
    "EventRecordID": "1042",
    "TimeCreated": "2026-01-15T02:15:30.123456Z",
    "Computer": "FIN-WS-01.corp.local",
    "UtcTime": "2026-01-15 02:15:30.123",
    "Image": r"C:\Windows\System32\cmd.exe",
    "CommandLine": r"cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc SUVY...",
    "User": r"CORP\victim",
    "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "ParentCommandLine": r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "Q4_Invoice.docm"',
}


@pytest.fixture
def sysmon_eid1_xml() -> str:
    """Realistic Sysmon EID 1 XML sample (Office app spawning cmd.exe, T1566.001)."""
    return SAMPLE_EID1_XML


@pytest.fixture
def sysmon_eid1_dict() -> dict:
    """Pre-extracted dict matching Sysmon native field names (Office spawning cmd.exe)."""
    return dict(SAMPLE_EID1_DICT)


def test_sysmon_eid1_matches_ocsf_shape_field_for_field(sysmon_eid1_xml, sysmon_eid1_dict):
    """Assert output matches ocsf.py's Process Activity (1007) shape field-for-field."""
    # Test XML input parsing
    parsed_xml = parse_sysmon_eid1(sysmon_eid1_xml, site_id="site-01", scenario_id="T1566.001")

    # Build reference event using ocsf.py's canonical builder
    expected = ocsf.build_process_activity(
        event_id="SYSMON-1042",
        time="2026-01-15T02:15:30.123000+00:00",
        user="victim",
        host="FIN-WS-01.corp.local",
        process_name="cmd.exe",
        cmd_line=r"cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc SUVY...",
        parent_name="WINWORD.EXE",
        site_id="site-01",
        scenario_id="T1566.001",
        severity_id=3,
    )
    expected["user"]["domain"] = "CORP"
    expected["process"]["file"] = {
        "path": r"C:\Windows\System32\cmd.exe",
        "name": "cmd.exe",
    }
    expected["actor"] = {
        "user": {"name": "victim", "domain": "CORP", "type": "User"},
        "process": {
            "name": "WINWORD.EXE",
            "file": {
                "path": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                "name": "WINWORD.EXE",
            },
        },
    }

    # 1. Exact equality with ocsf.py reference builder
    assert parsed_xml == expected

    # 2. Strict field-for-field shape verification
    assert set(parsed_xml.keys()) == set(expected.keys())
    assert set(parsed_xml["process"].keys()) == set(expected["process"].keys())
    assert set(parsed_xml["process"]["parent_process"].keys()) == set(expected["process"]["parent_process"].keys())
    assert set(parsed_xml["user"].keys()) == set(expected["user"].keys())
    assert set(parsed_xml["actor"].keys()) == set(expected["actor"].keys())
    assert set(parsed_xml["device"].keys()) == set(expected["device"].keys())
    assert set(parsed_xml["metadata"].keys()) == set(expected["metadata"].keys())
    assert set(parsed_xml["unmapped"].keys()) == set(expected["unmapped"].keys())

    # 3. Core OCSF contract assertions
    assert parsed_xml["class_uid"] == 1007
    assert parsed_xml["category_uid"] == 1
    assert parsed_xml["activity_id"] == 1
    assert parsed_xml["type_uid"] == 100701
    assert parsed_xml["event_class"] == "process_activity"
    assert parsed_xml["process"]["name"] == "cmd.exe"
    assert parsed_xml["process"]["parent_process"]["name"] == "WINWORD.EXE"
    assert parsed_xml["user"]["name"] == "victim"
    assert parsed_xml["user"]["domain"] == "CORP"
    assert parsed_xml["actor"]["user"]["name"] == "victim"
    assert parsed_xml["device"]["hostname"] == "FIN-WS-01.corp.local"
    assert parsed_xml["unmapped"]["scenario_id"] == "T1566.001"

    # 4. Dict input parsing matches identically
    parsed_dict = parse_sysmon_eid1(sysmon_eid1_dict, site_id="site-01", scenario_id="T1566.001")
    assert parsed_dict == expected
    assert set(parsed_dict.keys()) == set(expected.keys())

    # 5. ElementTree Element parsing matches identically
    import xml.etree.ElementTree as ET
    parsed_elem = parse_sysmon_eid1(ET.fromstring(sysmon_eid1_xml), site_id="site-01", scenario_id="T1566.001")
    assert parsed_elem == expected

    # 6. python-evtx Record (object with .xml() method) matches identically
    class MockEvtxRecord:
        def xml(self):
            return sysmon_eid1_xml

    parsed_evtx = parse_sysmon_eid1(MockEvtxRecord(), site_id="site-01", scenario_id="T1566.001")
    assert parsed_evtx == expected

    # 7. Pipeline integration: normalizer.py accepts the parsed event deterministically
    norm_event = normalizer.normalize(parsed_xml)
    assert norm_event.event_id == "SYSMON-1042"
    assert norm_event.event_class == "process_activity"
    assert norm_event.user_json.get("name") == "victim"
    assert norm_event.process_json.get("name") == "cmd.exe"

    # 8. Pipeline integration: graph_builder.py builds attack path nodes and edges
    graph = graph_builder.build_graph([parsed_xml])
    node_ids = {n["id"] for n in graph["nodes"]}
    assert "target_host:FIN-WS-01.corp.local" in node_ids
    assert "user:victim" in node_ids
    assert "process:FIN-WS-01.corp.local:cmd.exe" in node_ids


def test_sysmon_eid1_field_values_correct():
    """Assert actual extracted values match known input precisely (parent/child, user split, time parsing)."""
    raw_sample = {
        "EventID": 1,
        "EventRecordID": "2048",
        "Computer": "FIN-WS-02.corp.local",
        "UtcTime": "2026-01-15 03:45:10.500",
        "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": r"cmd.exe /c calc.exe",
        "User": r"FINANCE\analyst_01",
        "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    }
    result = parse_sysmon_eid1(raw_sample)

    # 1. actor.process.file.path == input ParentImage (EXCEL.EXE)
    assert result["actor"]["process"]["file"]["path"] == raw_sample["ParentImage"]

    # 2. process.file.path == input Image (cmd.exe)
    assert result["process"]["file"]["path"] == raw_sample["Image"]

    # 3. actor.user.name == input User, correctly split domain/user
    assert result["actor"]["user"]["name"] == "analyst_01"
    assert result["actor"]["user"]["domain"] == "FINANCE"

    # 4. time == correctly parsed UtcTime, not raw string
    assert result["time"] == "2026-01-15T03:45:10.500000+00:00"
    assert result["time"] != raw_sample["UtcTime"]


@pytest.mark.parametrize(
    "malformed_input,error_match",
    [
        (
            # Truncated XML
            "<Event><System><EventID>1</EventID>",
            "Malformed or truncated",
        ),
        (
            # Wrong EventID (EID 3 Network Connection instead of EID 1 Process Creation)
            """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System><EventID>3</EventID><EventRecordID>1</EventRecordID></System>
              <EventData><Data Name="Image">cmd.exe</Data><Data Name="CommandLine">cmd</Data><Data Name="User">u</Data><Data Name="UtcTime">2026-01-15 02:00:00</Data></EventData>
            </Event>""",
            "Expected Sysmon Event ID 1",
        ),
        (
            # EID 1 XML missing EventData / Image
            """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System><EventID>1</EventID><EventRecordID>1</EventRecordID><Computer>host</Computer></System>
              <EventData><Data Name="User">victim</Data><Data Name="CommandLine">cmd</Data><Data Name="UtcTime">2026-01-15 02:00:00</Data></EventData>
            </Event>""",
            "missing required 'Image' field",
        ),
        (
            # Dict missing Image
            {"CommandLine": "cmd.exe", "User": "u", "UtcTime": "2026-01-15 02:00:00", "EventRecordID": "1"},
            "missing required 'Image' field",
        ),
        (
            # Dict missing CommandLine
            {"Image": r"C:\cmd.exe", "User": "u", "UtcTime": "2026-01-15 02:00:00", "EventRecordID": "1"},
            "missing required 'CommandLine' field",
        ),
        (
            # Dict missing User
            {"Image": r"C:\cmd.exe", "CommandLine": "cmd.exe", "UtcTime": "2026-01-15 02:00:00", "EventRecordID": "1"},
            "missing required 'User' field",
        ),
        (
            # Dict missing timestamp
            {"Image": r"C:\cmd.exe", "CommandLine": "cmd.exe", "User": "u", "EventRecordID": "1"},
            "missing required timestamp field",
        ),
        (
            # Dict with invalid timestamp format
            {"Image": r"C:\cmd.exe", "CommandLine": "cmd.exe", "User": "u", "UtcTime": "not-a-timestamp", "EventRecordID": "1"},
            "Invalid timestamp format",
        ),
        (
            # Dict missing event identifier
            {"Image": r"C:\cmd.exe", "CommandLine": "cmd.exe", "User": "u", "UtcTime": "2026-01-15 02:00:00"},
            "missing event identifier",
        ),
        (
            # Empty dict
            {},
            "record dictionary is empty",
        ),
        (
            # Empty string
            "",
            "record string is empty",
        ),
        (
            # None
            None,
            "cannot be None",
        ),
        (
            # Unsupported type
            12345,
            "Unsupported record type",
        ),
    ],
)
def test_sysmon_parser_malformed_input_raises_exception(malformed_input, error_match):
    """Assert malformed or truncated inputs raise SysmonParseError with clear message."""
    with pytest.raises(SysmonParseError, match=error_match):
        parse_sysmon_eid1(malformed_input)
