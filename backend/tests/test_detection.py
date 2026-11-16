"""Unit tests for normalization, classification, scoring and council math."""

from sentrix.agents.base import AgentOutput
from sentrix.council.consensus import deliberate
from sentrix.detection.classifier import classify
from sentrix.detection.scoring import event_threat_score, incident_risk, severity_from_score
from sentrix.ingestion.normalizer import normalize
from sentrix.schemas.events import EventIngest


def _cls(**kw):
    return classify(normalize(EventIngest(**kw)))


def test_windows_failed_logon_is_normalized():
    ev = normalize(EventIngest(format="windows", raw={
        "EventID": 4625, "TimeCreated": "2026-11-10T02:00:00Z", "Computer": "dc-01",
        "EventData": {"TargetUserName": "CORP\\Alice", "IpAddress": "203.0.113.9"}}))
    assert ev.event_type == "Failed Logon"
    assert ev.hostname == "DC-01"
    assert ev.user == "alice"
    assert ev.src_ip == "203.0.113.9"
    assert ev.timestamp.tzinfo is None and ev.timestamp.hour == 2


def test_syslog_ssh_failure_is_parsed():
    ev = normalize(EventIngest(format="syslog", raw={
        "message": "Nov 10 02:01:02 web-01 sshd[1]: Failed password for invalid user admin from 198.51.100.7 port 22 ssh2"}))
    assert (ev.event_type, ev.hostname, ev.user, ev.src_ip) == ("Failed Logon", "WEB-01", "admin", "198.51.100.7")


def test_firewall_large_transfer():
    ev = normalize(EventIngest(format="firewall", raw={"src_ip": "10.0.0.5", "dst_ip": "192.0.2.10",
                                                         "dst_port": 443, "bytes_out": 500_000_000}))
    assert ev.event_type == "Large Outbound Transfer"
    assert _cls(format="firewall", raw={"bytes_out": 500_000_000, "dst_ip": "192.0.2.10"}).technique == "T1048"


def test_rule_classification_maps_to_mitre():
    assert _cls(event_type="Mass File Encryption", hostname="fs").technique == "T1486"
    assert _cls(event_type="Backup Deletion", hostname="b").technique == "T1490"
    assert _cls(event_type="Password Spray", hostname="v").technique == "T1110.003"
    assert _cls(event_type="Audit Log Cleared", hostname="h").tactic == "Defense Evasion"
    rdp = _cls(format="windows", raw={"EventID": 4624, "Computer": "s",
                                      "EventData": {"TargetUserName": "bob", "LogonType": 10}})
    assert rdp.technique == "T1021.001"


def test_benign_events_are_not_classified():
    c = _cls(event_type="Process Creation", hostname="ws", process="C:\\Program Files\\chrome.exe")
    assert c.technique is None and c.base_score == 0
    share = _cls(event_type="Network Share Accessed", hostname="fs", description="share \\\\fs\\Finance")
    assert share.technique is None


def test_scoring_is_monotonic_and_bounded():
    low = event_threat_score(20, 0.0, "low")
    high = event_threat_score(20, 0.8, "critical")
    assert 0 <= low < high <= 100
    assert severity_from_score(90) == "critical" and severity_from_score(10) == "info"
    assert incident_risk(100, 10, 1000, "critical") == 100.0


def _out(name, conf, scores):
    return AgentOutput(agent=name, role="", method="deterministic", confidence=conf, summary="",
                       votes={k: {"score": v, "reason": name} for k, v in scores.items()})


def test_council_weighted_consensus():
    cands = [{"id": "A", "name": "A"}, {"id": "B", "name": "B"}]
    outputs = {
        "X": _out("X", 1.0, {"A": 1.0, "B": 0.0}),
        "Y": _out("Y", 1.0, {"A": 0.0, "B": 1.0}),
    }
    # Equal weights -> tie broken by order; heavier X wins decisively.
    res = deliberate(outputs, {"X": 3.0, "Y": 1.0}, cands)
    assert res["decision"] == "A"
    assert res["consensus_score"] == 0.75
    assert res["first_choice_share"] == 0.75
    assert res["dissent"][0]["agent"] == "Y"
    assert any(a["pivotal"] for a in res["ablation"] if a["without"] == "X")
    # Low confidence reduces an agent's influence
    res2 = deliberate({"X": _out("X", 0.1, {"A": 1.0, "B": 0.0}),
                       "Y": _out("Y", 1.0, {"A": 0.0, "B": 1.0})}, {"X": 3.0, "Y": 1.0}, cands)
    assert res2["decision"] == "B"
