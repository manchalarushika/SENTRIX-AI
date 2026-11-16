"""Oracle threat classifier: deterministic rule matching against normalized events."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from sentrix.detection.rules import RULES, Rule
from sentrix.ingestion.normalizer import NormalizedEvent

_OFFICE = re.compile(r"(winword|excel|powerpnt|outlook|mspub|onenote)\.exe", re.I)
_SHELL = re.compile(r"(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\.exe", re.I)
# Replication rights GUIDs used by DCSync (DS-Replication-Get-Changes[-All])
_DCSYNC = re.compile(
    r"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|"
    r"89e95b76-444d-4c62-991a-0facbeda640c",
    re.I,
)
_SUSP_TLD = (".top", ".xyz", ".tk", ".gq", ".ml", ".cf", ".zip", ".mov", ".ru", ".su")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _condition(name: str, ev: NormalizedEvent) -> bool:
    x = ev.extra
    if name == "lsass_target":
        target = str(x.get("target_image") or ev.process or "")
        return "lsass.exe" in target.lower()
    if name == "dcsync":
        return bool(_DCSYNC.search(f"{x.get('properties') or ''} {ev.description}"))
    if name == "rc4_ticket":
        return str(x.get("ticket_encryption", "")).lower() in {"0x17", "23", "rc4"}
    if name == "rdp_logon":
        return x.get("logon_type") == 10
    if name == "suspicious_dns":
        q = str(x.get("query_name") or ev.description.replace("DNS query for ", "")).lower().strip(".")
        if not q or " " in q:
            return False
        first_label = q.split(".")[0]
        return (
            q.endswith(_SUSP_TLD)
            or len(first_label) >= 40
            or (len(first_label) >= 16 and _entropy(first_label) > 3.8)
        )
    if name == "office_child_shell":
        parent = str(ev.raw.get("ParentImage") or ev.raw.get("parent_process") or x.get("parent") or "")
        return bool(_OFFICE.search(parent) and _SHELL.search(ev.process or ev.command_line or ""))
    if name == "cloud_risky_login":
        return x.get("mfa_used") is False or ev.event_type.lower() == "impossible travel"
    return False


@dataclass
class Classification:
    rule_ids: list[str]
    technique: str | None
    technique_name: str | None
    tactic: str | None
    category: str
    base_score: float
    indicators: list[dict[str, Any]]
    recommendation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_ids": self.rule_ids,
            "technique": self.technique,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "category": self.category,
            "base_score": self.base_score,
            "indicators": self.indicators,
            "recommendation": self.recommendation,
            "method": "deterministic-rules",
        }


def _matches(rule: Rule, ev: NormalizedEvent, text: str) -> str | None:
    """Return a human readable reason when the rule matches, else None."""
    et = ev.event_type.lower()
    type_ok = not rule.event_types or et in rule.event_types
    reasons: list[str] = []

    # A rule with both event_types and a pattern matches when the type matches AND
    # (pattern matches OR the rule has a condition that passes) - or when the
    # pattern alone matches for rules whose evidence is purely textual.
    if rule.condition:
        if not (type_ok and _condition(rule.condition, ev)):
            return None
        reasons.append(f"condition '{rule.condition}' satisfied")
    if rule.ports:
        if not (type_ok and ev.dst_port in rule.ports):
            return None
        reasons.append(f"destination port {ev.dst_port}")
    if rule.pattern is not None:
        m = rule.pattern.search(text)
        if rule.require_pattern and not (m and type_ok):
            return None
        if m:
            reasons.append(f"pattern matched '{m.group(0)[:60]}'")
        elif rule.event_types and type_ok and not rule.condition and not rule.ports:
            # type-only match is still valid for rules that list both
            reasons.append(f"event type '{ev.event_type}'")
        else:
            return None
    elif rule.event_types and not rule.condition and not rule.ports:
        if not type_ok:
            return None
        reasons.append(f"event type '{ev.event_type}'")
    return "; ".join(reasons) if reasons else None


def classify(ev: NormalizedEvent) -> Classification:
    extra_text = [
        str(ev.extra[k])
        for k in ("share_name", "target_filename", "target_object", "query_name", "url", "attachment")
        if ev.extra.get(k)
    ]
    text = " ".join(filter(None, [ev.process, ev.command_line, ev.description, *extra_text]))
    hits: list[tuple[Rule, str]] = []
    for rule in RULES:
        reason = _matches(rule, ev, text)
        if reason:
            hits.append((rule, reason))

    if not hits:
        return Classification(
            rule_ids=[],
            technique=None,
            technique_name=None,
            tactic=None,
            category="Other",
            base_score=0.0,
            indicators=[],
            recommendation="",
        )

    hits.sort(key=lambda h: h[0].score, reverse=True)
    top = hits[0][0]
    # Several independent indicators increase confidence (noisy-OR on scores)
    combined = 1.0
    for rule, _ in hits:
        combined *= 1 - rule.score / 100
    score = round(min(100.0, 100 * (1 - combined)), 1)
    return Classification(
        rule_ids=[r.id for r, _ in hits],
        technique=top.technique,
        technique_name=top.technique_name,
        tactic=top.tactic,
        category=top.category,
        base_score=score,
        indicators=[
            {
                "rule": r.id,
                "name": r.name,
                "technique": r.technique,
                "tactic": r.tactic,
                "score": r.score,
                "evidence": why,
            }
            for r, why in hits
        ],
        recommendation=top.recommendation,
    )
