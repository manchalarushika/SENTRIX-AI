"""Threat classification rule base (deterministic).

Each rule maps observable conditions to a MITRE ATT&CK technique. Technique
IDs and names follow MITRE ATT&CK Enterprise (v14+). The base threat score
(0-100) reflects how strongly the observable indicates malicious activity on
its own; behavioural anomaly and asset criticality are combined later.

The taxonomy extends the original AEGIS-X ``ThreatRules`` table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    technique: str
    technique_name: str
    tactic: str
    category: str
    score: int
    event_types: frozenset[str] = frozenset()
    pattern: re.Pattern[str] | None = None  # matched against process + command line + description
    ports: frozenset[int] = frozenset()
    condition: str | None = None  # name of an extra-field predicate (see classifier)
    require_pattern: bool = False  # event type AND pattern must both match
    recommendation: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE)


def _types(*t: str) -> frozenset[str]:
    return frozenset(x.lower() for x in t)


RULES: list[Rule] = [
    # ---------------- Credential Access ----------------
    Rule("R-CRED-001", "LSASS memory access / credential dumping", "T1003.001",
         "OS Credential Dumping: LSASS Memory", "Credential Access", "Credential Theft", 88,
         pattern=_rx(r"mimikatz|sekurlsa|procdump(64)?(\.exe)?\s.*lsass|comsvcs(\.dll)?,\s*minidump|lsass\.dmp"),
         recommendation="Isolate host, reset credentials of logged-on accounts, hunt for reuse."),
    Rule("R-CRED-002", "Process opened handle to LSASS", "T1003.001",
         "OS Credential Dumping: LSASS Memory", "Credential Access", "Credential Theft", 80,
         event_types=_types("Process Access"), condition="lsass_target",
         recommendation="Validate accessing process; isolate if not a security tool."),
    Rule("R-CRED-003", "DCSync replication request", "T1003.006",
         "OS Credential Dumping: DCSync", "Credential Access", "Credential Theft", 92,
         event_types=_types("Directory Object Access"), condition="dcsync",
         recommendation="Treat domain as compromised: rotate KRBTGT twice, audit replication rights."),
    Rule("R-CRED-004", "Kerberoasting (RC4 service ticket)", "T1558.003",
         "Steal or Forge Kerberos Tickets: Kerberoasting", "Credential Access", "Credential Theft", 70,
         event_types=_types("Kerberos Service Ticket Requested"), condition="rc4_ticket",
         recommendation="Rotate service account passwords; enforce AES-only Kerberos."),
    Rule("R-CRED-005", "Authentication failure", "T1110",
         "Brute Force", "Credential Access", "Authentication", 22,
         event_types=_types("Failed Logon", "Credential Validation Failed"),
         recommendation="Review source; repeated failures are escalated by the behaviour engine."),
    Rule("R-CRED-006", "Brute force / password spraying", "T1110.003",
         "Brute Force: Password Spraying", "Credential Access", "Authentication", 55,
         event_types=_types("Brute Force Attack", "Password Spray", "Account Locked Out"),
         recommendation="Block source IP at the perimeter and enforce MFA."),
    Rule("R-CRED-007", "Credential theft alert (EDR)", "T1003",
         "OS Credential Dumping", "Credential Access", "Credential Theft", 85,
         event_types=_types("Credential Dumping", "Credential Theft"),
         recommendation="Isolate host and reset credentials of accounts used on it."),
    Rule("R-LAT-004", "Lateral movement alert (EDR/NDR)", "T1021",
         "Remote Services", "Lateral Movement", "Lateral Movement", 62,
         event_types=_types("Lateral Movement", "Remote Execution"),
         recommendation="Confirm the source host and account; contain both ends."),
    # ---------------- Execution ----------------
    Rule("R-EXEC-001", "Obfuscated / download-cradle PowerShell", "T1059.001",
         "Command and Scripting Interpreter: PowerShell", "Execution", "Malicious Execution", 68,
         pattern=_rx(r"powershell.*(-enc(odedcommand)?\s|-e\s+[A-Za-z0-9+/=]{20,}|frombase64string|"
                     r"downloadstring|downloadfile|invoke-expression|\biex\b|-nop.*-w\s+hidden|bypass)"),
         recommendation="Collect script block logs; isolate host if payload confirmed."),
    Rule("R-EXEC-002", "Suspicious PowerShell script block", "T1059.001",
         "Command and Scripting Interpreter: PowerShell", "Execution", "Malicious Execution", 60,
         event_types=_types("PowerShell Script Block"),
         pattern=_rx(r"invoke-mimikatz|invoke-shellcode|amsiutils|virtualalloc|reflection\.assembly|"
                     r"net\.webclient|downloadstring|frombase64string"),
         require_pattern=True,
         recommendation="Review full script block; block hash/URL."),
    Rule("R-EXEC-005", "Suspicious PowerShell alert", "T1059.001",
         "Command and Scripting Interpreter: PowerShell", "Execution", "Malicious Execution", 58,
         event_types=_types("Suspicious PowerShell"),
         recommendation="Review full script block; block hash/URL."),
    Rule("R-EXEC-003", "Remote service execution (PsExec-style)", "T1569.002",
         "System Services: Service Execution", "Execution", "Lateral Movement", 62,
         pattern=_rx(r"psexec|psexesvc|paexec|remcom|\\\\[\w.\-]+\\admin\$"),
         recommendation="Confirm admin activity; disable remote service creation for non-admins."),
    Rule("R-EXEC-004", "Malicious file executed / malware detected", "T1204.002",
         "User Execution: Malicious File", "Execution", "Malware", 75,
         event_types=_types("Malware Detection", "Malware Detected", "Threat Detected"),
         recommendation="Quarantine file, isolate endpoint, run full scan."),
    # ---------------- Persistence / Privilege ----------------
    Rule("R-PERS-001", "Scheduled task created", "T1053.005",
         "Scheduled Task/Job: Scheduled Task", "Persistence", "Persistence", 42,
         event_types=_types("Scheduled Task Created"),
         pattern=None,
         recommendation="Review task action and author."),
    Rule("R-PERS-002", "Scheduled task via command line", "T1053.005",
         "Scheduled Task/Job: Scheduled Task", "Persistence", "Persistence", 48,
         pattern=_rx(r"schtasks(\.exe)?\s+/create"),
         recommendation="Review task action and author."),
    Rule("R-PERS-003", "Registry Run key persistence", "T1547.001",
         "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence", "Persistence", 55,
         pattern=_rx(r"\\currentversion\\run(once)?\b"),
         recommendation="Remove autorun entry after collecting the referenced binary."),
    Rule("R-PERS-004", "New service installed", "T1543.003",
         "Create or Modify System Process: Windows Service", "Persistence", "Persistence", 45,
         event_types=_types("Service Installed"),
         recommendation="Validate service binary path and signer."),
    Rule("R-PERS-005", "Local/domain account created", "T1136",
         "Create Account", "Persistence", "Account Manipulation", 40,
         event_types=_types("User Account Created"),
         pattern=None,
         recommendation="Confirm account creation with change ticket."),
    Rule("R-PRIV-001", "Account added to privileged group", "T1098",
         "Account Manipulation", "Privilege Escalation", "Account Manipulation", 65,
         event_types=_types("Member Added to Security Group", "Privilege Escalation"),
         recommendation="Verify against change management; remove unauthorized membership."),
    Rule("R-PRIV-002", "Privileged command via sudo", "T1548.003",
         "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation",
         "Privilege Escalation", 35,
         event_types=_types("Privileged Command"),
         pattern=_rx(r"/etc/shadow|chmod\s+[0-7]*s|useradd|visudo|nc\s+-e|bash\s+-i|/dev/tcp/"),
         require_pattern=True,
         recommendation="Review command against expected admin activity."),
    # ---------------- Defense Evasion ----------------
    Rule("R-EVAS-001", "Security event log cleared", "T1070.001",
         "Indicator Removal: Clear Windows Event Logs", "Defense Evasion", "Defense Evasion", 78,
         event_types=_types("Audit Log Cleared"),
         recommendation="Preserve remaining forensic evidence; assume compromise."),
    Rule("R-EVAS-002", "Event log clearing via command line", "T1070.001",
         "Indicator Removal: Clear Windows Event Logs", "Defense Evasion", "Defense Evasion", 76,
         pattern=_rx(r"wevtutil(\.exe)?\s+(cl|clear-log)|clear-eventlog"),
         recommendation="Preserve remaining forensic evidence; assume compromise."),
    Rule("R-EVAS-003", "Endpoint protection tampering", "T1562.001",
         "Impair Defenses: Disable or Modify Tools", "Defense Evasion", "Defense Evasion", 74,
         pattern=_rx(r"set-mppreference.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection)|"
                     r"sc(\.exe)?\s+(stop|delete)\s+(windefend|sense)|disableantispyware"),
         event_types=_types("Defender Disabled", "Antivirus Disabled"),
         recommendation="Re-enable protection and investigate who changed the policy."),
    # ---------------- Discovery ----------------
    Rule("R-DISC-001", "Account / domain discovery commands", "T1087",
         "Account Discovery", "Discovery", "Reconnaissance", 28,
         pattern=_rx(r"net(1)?(\.exe)?\s+(user|group|localgroup)\b|nltest\s+/(dclist|domain_trusts)|"
                     r"whoami\s+/(all|priv|groups)|adfind|get-aduser|bloodhound|sharphound"),
         recommendation="Correlate with logon source; benign for admins, suspicious for users."),
    Rule("R-DISC-002", "Network service scanning", "T1046",
         "Network Service Discovery", "Discovery", "Reconnaissance", 35,
         event_types=_types("Port Scan", "Network Probe", "SMB Enumeration"),
         pattern=_rx(r"\bnmap\b|masscan|advanced_ip_scanner|angryip"),
         recommendation="Identify scanning host; block if unauthorized."),
    # ---------------- Lateral Movement ----------------
    Rule("R-LAT-001", "Remote Desktop logon", "T1021.001",
         "Remote Services: Remote Desktop Protocol", "Lateral Movement", "Lateral Movement", 30,
         event_types=_types("Successful Logon"), condition="rdp_logon",
         recommendation="Validate that the user normally uses RDP to this host."),
    Rule("R-LAT-002", "Admin share access", "T1021.002",
         "Remote Services: SMB/Windows Admin Shares", "Lateral Movement", "Lateral Movement", 45,
         event_types=_types("Network Share Accessed", "Network Share Object Checked"),
         pattern=_rx(r"\\(admin|c)\$"),
         require_pattern=True,
         recommendation="Confirm source host is an admin jump box."),
    Rule("R-LAT-003", "WMI / WinRM remote execution", "T1047",
         "Windows Management Instrumentation", "Execution", "Lateral Movement", 55,
         pattern=_rx(r"wmic(\.exe)?\s+/node:|invoke-wmimethod|invoke-command\s+-computername|winrs(\.exe)?\s"),
         recommendation="Validate remote management source; restrict WinRM to admin hosts."),
    # ---------------- Command and Control ----------------
    Rule("R-C2-001", "Command-and-control beacon", "T1071.001",
         "Application Layer Protocol: Web Protocols", "Command and Control", "Command and Control", 80,
         event_types=_types("Command and Control", "C2 Beacon", "Beaconing"),
         recommendation="Block destination, isolate host, capture memory."),
    Rule("R-C2-002", "Connection to common C2/RAT port", "T1571",
         "Non-Standard Port", "Command and Control", "Command and Control", 45,
         event_types=_types("Network Connection"), ports=frozenset({4444, 1337, 31337, 8443, 6667, 50050}),
         recommendation="Inspect destination reputation and process making the connection."),
    Rule("R-C2-003", "Suspicious DNS (tunnelling / DGA-like)", "T1071.004",
         "Application Layer Protocol: DNS", "Command and Control", "Command and Control", 55,
         event_types=_types("DNS Query"), condition="suspicious_dns",
         recommendation="Sinkhole domain; review host for implant."),
    Rule("R-C2-004", "Remote access tool execution", "T1219",
         "Remote Access Software", "Command and Control", "Command and Control", 50,
         pattern=_rx(r"anydesk|teamviewer|screenconnect|atera|ngrok|rclone"),
         recommendation="Confirm software is sanctioned; remove if not."),
    # ---------------- Exfiltration ----------------
    Rule("R-EXF-001", "Large outbound data transfer", "T1048",
         "Exfiltration Over Alternative Protocol", "Exfiltration", "Data Exfiltration", 72,
         event_types=_types("Large Outbound Transfer", "Data Exfiltration"),
         recommendation="Block destination, identify data set, engage DPO/legal."),
    Rule("R-EXF-002", "Exfiltration tooling", "T1567.002",
         "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "Exfiltration",
         "Data Exfiltration", 70,
         pattern=_rx(r"rclone(\.exe)?\s+(copy|sync)|megacmd|mega-put|curl.*(--upload-file|-T\s)"),
         recommendation="Block destination and revoke cloud tokens."),
    Rule("R-EXF-003", "Archive staging of data", "T1560.001",
         "Archive Collected Data: Archive via Utility", "Collection", "Data Exfiltration", 40,
         pattern=_rx(r"(7z|7za|rar|winrar)(\.exe)?\s+a\s|compress-archive"),
         recommendation="Review archived paths for sensitive data."),
    # ---------------- Impact ----------------
    Rule("R-IMP-001", "Shadow copy / backup deletion", "T1490",
         "Inhibit System Recovery", "Impact", "Ransomware", 90,
         pattern=_rx(r"vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|"
                     r"bcdedit(\.exe)?.*recoveryenabled\s+no|wbadmin(\.exe)?\s+delete"),
         event_types=_types("Shadow Copy Deletion", "Backup Deletion"),
         recommendation="Imminent ransomware: isolate host and protect backup infrastructure."),
    Rule("R-IMP-002", "Mass file encryption", "T1486",
         "Data Encrypted for Impact", "Impact", "Ransomware", 96,
         event_types=_types("Mass File Encryption", "File Encryption", "Ransomware"),
         pattern=_rx(r"\.(locked|encrypted|crypt|lockbit|ryuk)\b|readme_to_decrypt|how_to_recover"),
         recommendation="Isolate affected segment immediately; activate ransomware playbook."),
    Rule("R-IMP-003", "Service disruption / DoS", "T1498",
         "Network Denial of Service", "Impact", "Availability", 65,
         event_types=_types("DDoS", "Denial of Service"),
         recommendation="Enable upstream DDoS mitigation and rate limiting."),
    # ---------------- Initial Access ----------------
    Rule("R-INIT-001", "Exploit of public-facing application", "T1190",
         "Exploit Public-Facing Application", "Initial Access", "Web Attack", 70,
         event_types=_types("SQL Injection", "Web Exploit", "Exploit Attempt"),
         pattern=_rx(r"union(\s|%20|\+)+select|'\s*or\s*'?1'?\s*=\s*'?1|\$\{jndi:|\.\./\.\./|"
                     r"<script>|cmd\.exe\s*/c|/etc/passwd"),
         recommendation="Block request source, patch application, review web server for webshells."),
    Rule("R-INIT-002", "Phishing email delivered", "T1566.001",
         "Phishing: Spearphishing Attachment", "Initial Access", "Phishing", 55,
         event_types=_types("Phishing", "Phishing Email", "Malicious Attachment"),
         recommendation="Purge message from mailboxes; identify recipients who opened it."),
    Rule("R-INIT-003", "Office application spawned a shell", "T1566.001",
         "Phishing: Spearphishing Attachment", "Initial Access", "Phishing", 72,
         event_types=_types("Process Creation"), condition="office_child_shell",
         recommendation="Isolate host; retrieve the originating document."),
    Rule("R-INIT-004", "Login without MFA / unusual location", "T1078",
         "Valid Accounts", "Initial Access", "Account Compromise", 50,
         event_types=_types("Console Login", "Cloud Login", "Impossible Travel", "Successful Logon"),
         condition="cloud_risky_login",
         recommendation="Force re-authentication with MFA and review session activity."),
]

RULE_INDEX = {r.id: r for r in RULES}

# Canonical tactic order (kill-chain), used to measure attack progression.
TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]
