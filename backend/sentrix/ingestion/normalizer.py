"""Security event normalization.

Converts vendor-specific payloads (Windows Security / Sysmon event JSON,
Linux syslog lines, firewall logs, EDR and cloud alerts) into a single
normalized event schema used by every downstream engine.

This module is fully deterministic. It does not read live OS logs itself;
logs are *pushed* to SENTRIX AI via the ingestion API (see
``scripts/forward_windows_events.ps1`` and ``scripts/send_events.py``).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentrix.schemas.events import EventIngest

# Windows Security / PowerShell / System channel event IDs -> canonical type
WINDOWS_EVENT_TYPES: dict[int, str] = {
    1102: "Audit Log Cleared",
    4104: "PowerShell Script Block",
    4624: "Successful Logon",
    4625: "Failed Logon",
    4634: "Logoff",
    4648: "Explicit Credential Logon",
    4662: "Directory Object Access",
    4663: "Object Access",
    4672: "Special Privileges Assigned",
    4688: "Process Creation",
    4697: "Service Installed",
    4698: "Scheduled Task Created",
    4720: "User Account Created",
    4724: "Password Reset Attempt",
    4728: "Member Added to Security Group",
    4732: "Member Added to Security Group",
    4740: "Account Locked Out",
    4756: "Member Added to Security Group",
    4768: "Kerberos TGT Requested",
    4769: "Kerberos Service Ticket Requested",
    4776: "Credential Validation",
    5140: "Network Share Accessed",
    5145: "Network Share Object Checked",
    7045: "Service Installed",
}

SYSMON_EVENT_TYPES: dict[int, str] = {
    1: "Process Creation",
    3: "Network Connection",
    7: "Image Loaded",
    8: "Remote Thread Created",
    10: "Process Access",
    11: "File Created",
    12: "Registry Object Modified",
    13: "Registry Value Set",
    15: "File Stream Created",
    22: "DNS Query",
    23: "File Deleted",
}

_SSH_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
_SSH_OK = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
_SUDO = re.compile(r"sudo:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)$")
_SYSLOG_HOST = re.compile(r"^\w{3}\s+\d+\s+[\d:]+\s+(?P<host>\S+)\s")


@dataclass
class NormalizedEvent:
    timestamp: datetime
    source: str
    source_format: str
    event_type: str
    severity_hint: str | None = None
    hostname: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    process: str | None = None
    command_line: str | None = None
    description: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable hash used for de-duplication of re-sent events."""
        basis = json.dumps(
            {
                "t": self.timestamp.isoformat(),
                "s": self.source,
                "e": self.event_type,
                "h": self.hostname,
                "u": self.user,
                "si": self.src_ip,
                "di": self.dst_ip,
                "dp": self.dst_port,
                "p": self.process,
                "c": self.command_line,
                "d": self.description,
                "r": self.raw,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(basis.encode()).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


def _naive_utc(dt: datetime) -> datetime:
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def _parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return _naive_utc(value)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), UTC).replace(tzinfo=None)
    s = str(value).strip()
    # PowerShell ConvertTo-Json legacy format: "/Date(1700000000000)/"
    m = re.match(r"^/Date\((\d+)\)/$", s)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, UTC).replace(tzinfo=None)
    try:
        return _naive_utc(datetime.fromisoformat(s.replace("Z", "+00:00")))
    except ValueError:
        return None


def _first(d: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, "", "-"):
            return d[k]
    return None


def _clean_user(u: Any) -> str | None:
    if not u:
        return None
    s = str(u).strip()
    if s in {"-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"} or s.endswith("$"):
        # machine accounts / built-ins are tracked by host, not as users
        return s if s == "SYSTEM" else None
    if "\\" in s:
        s = s.split("\\", 1)[1]
    return s.lower()[:100]


def _clean_ip(ip: Any) -> str | None:
    if not ip:
        return None
    s = str(ip).strip()
    if s in {"-", "::1", "127.0.0.1", "0.0.0.0"}:
        return None
    if s.startswith("::ffff:"):
        s = s[7:]
    return s


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _event_data(raw: dict[str, Any]) -> dict[str, Any]:
    """Windows event data may be nested under EventData / Properties."""
    data: dict[str, Any] = {}
    for key in ("EventData", "event_data", "Properties", "properties"):
        v = raw.get(key)
        if isinstance(v, dict):
            data.update(v)
    data.update({k: v for k, v in raw.items() if not isinstance(v, (dict, list))})
    return data


def _normalize_windows(raw: dict[str, Any], sysmon: bool) -> dict[str, Any]:
    data = _event_data(raw)
    event_id = _int(_first(data, "EventID", "EventId", "Id", "event_id"))
    table = SYSMON_EVENT_TYPES if sysmon else WINDOWS_EVENT_TYPES
    etype = table.get(event_id or -1, f"Windows Event {event_id}" if event_id else "Windows Event")
    out: dict[str, Any] = {
        "event_type": etype,
        "timestamp": _parse_time(_first(data, "TimeCreated", "UtcTime", "timestamp", "@timestamp")),
        "hostname": _first(data, "Computer", "MachineName", "Hostname", "WorkstationName"),
        "user": _clean_user(_first(data, "TargetUserName", "SubjectUserName", "User", "UserName")),
        "src_ip": _clean_ip(_first(data, "IpAddress", "SourceIp", "SourceAddress")),
        "dst_ip": _clean_ip(_first(data, "DestinationIp", "DestAddress")),
        "dst_port": _int(_first(data, "DestinationPort", "DestPort")),
        "process": _first(data, "NewProcessName", "Image", "ProcessName", "TargetImage"),
        "command_line": _first(data, "CommandLine", "ScriptBlockText", "ImagePath", "TaskContent"),
        "description": str(_first(data, "Message", "message") or etype)[:4000],
        "extra": {
            "event_id": event_id,
            "logon_type": _int(_first(data, "LogonType")),
            "target_image": _first(data, "TargetImage"),
            "granted_access": _first(data, "GrantedAccess"),
            "ticket_encryption": _first(data, "TicketEncryptionType"),
            "service_name": _first(data, "ServiceName", "TaskName"),
            "group_name": _first(data, "TargetUserName") if event_id in (4728, 4732, 4756) else None,
            "member": _first(data, "MemberName", "MemberSid"),
            "properties": _first(data, "Properties") if isinstance(raw.get("Properties"), str) else None,
            "query_name": _first(data, "QueryName"),
            "target_filename": _first(data, "TargetFilename"),
            "target_object": _first(data, "TargetObject"),
            "share_name": _first(data, "ShareName", "RelativeTargetName"),
            "parent": _first(data, "ParentImage", "ParentProcessName"),
        },
    }
    if event_id in (4728, 4732, 4756):
        # For group-change events TargetUserName is the *group*; the actor is the subject.
        out["user"] = _clean_user(_first(data, "SubjectUserName"))
    if out["extra"]["query_name"] and not out["description"].startswith("DNS"):
        out["description"] = f"DNS query for {out['extra']['query_name']}"
    return out


def _normalize_syslog(raw: dict[str, Any]) -> dict[str, Any]:
    msg = str(raw.get("message") or raw.get("msg") or "")
    out: dict[str, Any] = {"description": msg[:4000], "extra": {}}
    hm = _SYSLOG_HOST.match(msg)
    out["hostname"] = raw.get("host") or raw.get("hostname") or (hm.group("host") if hm else None)
    out["timestamp"] = _parse_time(raw.get("timestamp"))
    if m := _SSH_FAILED.search(msg):
        out.update(event_type="Failed Logon", user=m.group("user").lower(), src_ip=m.group("ip"))
        out["extra"]["service"] = "sshd"
    elif m := _SSH_OK.search(msg):
        out.update(event_type="Successful Logon", user=m.group("user").lower(), src_ip=m.group("ip"))
        out["extra"]["service"] = "sshd"
    elif m := _SUDO.search(msg):
        out.update(
            event_type="Privileged Command",
            user=m.group("user").lower(),
            command_line=m.group("cmd").strip(),
        )
    else:
        out["event_type"] = raw.get("event_type") or "Syslog Message"
    return out


def _normalize_firewall(raw: dict[str, Any]) -> dict[str, Any]:
    action = str(_first(raw, "action", "Action", "disposition") or "").lower()
    bytes_out = _int(_first(raw, "bytes_out", "sent_bytes", "bytes_sent"))
    etype = raw.get("event_type")
    if not etype:
        if bytes_out and bytes_out >= 100_000_000:
            etype = "Large Outbound Transfer"
        elif action in {"deny", "drop", "block", "blocked", "reject"}:
            etype = "Connection Blocked"
        else:
            etype = "Network Connection"
    return {
        "event_type": etype,
        "timestamp": _parse_time(_first(raw, "timestamp", "time", "@timestamp")),
        "hostname": _first(raw, "hostname", "device", "src_host"),
        "src_ip": _clean_ip(_first(raw, "src_ip", "src", "source_ip")),
        "dst_ip": _clean_ip(_first(raw, "dst_ip", "dst", "destination_ip")),
        "dst_port": _int(_first(raw, "dst_port", "dport", "destination_port")),
        "user": _clean_user(_first(raw, "user", "username")),
        "description": str(
            _first(raw, "message", "description")
            or f"{action or 'observed'} {raw.get('protocol', '')} connection".strip()
        ),
        "extra": {"action": action, "bytes_out": bytes_out, "protocol": raw.get("protocol")},
    }


def _normalize_alert(raw: dict[str, Any]) -> dict[str, Any]:
    """EDR / cloud / email security alerts."""
    return {
        "event_type": _first(raw, "event_type", "alert_name", "detection", "eventName", "title")
        or "Security Alert",
        "timestamp": _parse_time(_first(raw, "timestamp", "eventTime", "time", "@timestamp")),
        "hostname": _first(raw, "hostname", "device_name", "computer"),
        "user": _clean_user(_first(raw, "user", "userName", "userIdentity", "recipient")),
        "src_ip": _clean_ip(_first(raw, "src_ip", "sourceIPAddress", "ip")),
        "dst_ip": _clean_ip(_first(raw, "dst_ip")),
        "process": _first(raw, "process", "file_name", "image"),
        "command_line": _first(raw, "command_line", "cmdline"),
        "description": str(_first(raw, "description", "message", "threat_name") or "")[:4000],
        "severity_hint": str(raw["severity"]).lower() if raw.get("severity") else None,
        "dst_port": _int(_first(raw, "dst_port", "destination_port")),
        "extra": {
            **{
                k: raw.get(k)
                for k in (
                    "threat_name", "mfa_used", "country", "url", "attachment", "file_count",
                    "logon_type", "ticket_encryption", "target_image", "query_name",
                    "target_filename", "target_object", "share_name", "bytes_out",
                )
                if k in raw
            },
            "parent": _first(raw, "parent_process", "ParentImage", "parent"),
        },
    }


def normalize(event: EventIngest, now: datetime | None = None) -> NormalizedEvent:
    """Normalize one ingested event. Explicit top-level fields override parsed ones."""
    raw = event.raw or {}
    fmt = event.format
    parsed: dict[str, Any] = {}
    if raw:
        if fmt in ("windows", "sysmon"):
            parsed = _normalize_windows(raw, sysmon=fmt == "sysmon")
        elif fmt == "syslog":
            parsed = _normalize_syslog(raw)
        elif fmt == "firewall":
            parsed = _normalize_firewall(raw)
        elif fmt in ("edr", "cloud"):
            parsed = _normalize_alert(raw)
        else:
            parsed = _normalize_alert(raw)  # generic: best-effort key extraction

    def pick(name: str) -> Any:
        v = getattr(event, name, None)
        return v if v not in (None, "") else parsed.get(name)

    ts = event.timestamp or parsed.get("timestamp") or now or datetime.now(UTC)
    hostname = pick("hostname")
    severity_hint = event.severity.value if event.severity else parsed.get("severity_hint")
    return NormalizedEvent(
        timestamp=_naive_utc(ts),
        source=event.source,
        source_format=fmt,
        event_type=(pick("event_type") or "Unknown Event").strip()[:100],
        severity_hint=severity_hint,
        hostname=str(hostname).upper()[:100] if hostname else None,
        user=_clean_user(pick("user")),
        src_ip=_clean_ip(pick("src_ip")),
        dst_ip=_clean_ip(pick("dst_ip")),
        dst_port=pick("dst_port"),
        process=(str(pick("process"))[:255] if pick("process") else None),
        command_line=(str(pick("command_line"))[:8192] if pick("command_line") else None),
        description=str(pick("description") or pick("event_type") or "")[:4000],
        raw=raw,
        extra={k: v for k, v in (parsed.get("extra") or {}).items() if v is not None},
    )
