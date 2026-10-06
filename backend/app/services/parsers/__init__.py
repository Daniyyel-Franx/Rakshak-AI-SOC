"""Log parsers converting native telemetry to OCSF-compatible events."""
from .auditd_to_ocsf import (
    AuditdParseError,
    parse_execve,
    parse_file_watch,
)
from .ssh_auth_to_ocsf import (
    SshAuthParseError,
    parse_auth_log_line,
)
from .sysmon_to_ocsf import (
    SysmonParseError,
    parse_sysmon_eid1,
    parse_sysmon_event,
    sysmon_to_ocsf,
)
from .zeek_to_ocsf import (
    ZeekParseError,
    parse_conn_log,
)

__all__ = [
    "AuditdParseError",
    "SshAuthParseError",
    "SysmonParseError",
    "ZeekParseError",
    "parse_auth_log_line",
    "parse_conn_log",
    "parse_execve",
    "parse_file_watch",
    "parse_sysmon_eid1",
    "parse_sysmon_event",
    "sysmon_to_ocsf",
]
