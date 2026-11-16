"""Threat-intelligence knowledge base: loading, seeding and importers.

Seed content lives in ``backend/data/intel``. Importers accept the official
MITRE ATT&CK STIX bundle (``enterprise-attack.json``) and the CISA KEV JSON
feed (``known_exploited_vulnerabilities.json``) so the knowledge base can be
refreshed from authoritative sources.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentrix.core.config import DATA_DIR
from sentrix.core.logging import get_logger
from sentrix.db.models import IntelDocument

log = get_logger("intel")
INTEL_DIR = DATA_DIR / "intel"


@lru_cache
def mitre_techniques() -> dict[str, dict[str, Any]]:
    items = json.loads((INTEL_DIR / "mitre_techniques.json").read_text(encoding="utf-8"))
    return {t["id"]: t for t in items}


@lru_cache
def vulnerabilities() -> list[dict[str, Any]]:
    return json.loads((INTEL_DIR / "vulnerabilities.json").read_text(encoding="utf-8"))["items"]


@lru_cache
def playbooks() -> list[dict[str, Any]]:
    return json.loads((DATA_DIR / "playbooks" / "playbooks.json").read_text(encoding="utf-8"))


def playbook_index() -> dict[str, dict[str, Any]]:
    return {p["id"]: p for p in playbooks()}


def match_vulnerabilities(software: list[str]) -> list[dict[str, Any]]:
    """Match an asset's software inventory against the KEV seed (keyword match)."""
    text = " ".join(software).lower()
    if not text:
        return []
    return [v for v in vulnerabilities() if any(k in text for k in v["match"])]


def _seed_docs() -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for t in mitre_techniques().values():
        docs.append({
            "doc_id": t["id"],
            "doc_type": "mitre_technique",
            "title": f"{t['id']} {t['name']}",
            "body": f"Tactic: {t['tactic']}.\n{t['description']}\nDetection: {t['detection']}\n"
                    f"Mitigation: {t['mitigation']}",
            "tags": [t["tactic"], t["id"].split(".")[0]],
            "source": "MITRE ATT&CK (curated summary)",
            "url": f"https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/",
        })
    for v in vulnerabilities():
        docs.append({
            "doc_id": v["id"],
            "doc_type": "cve",
            "title": f"{v['id']} {v['name']}",
            "body": f"Vendor: {v['vendor']}. Product: {v['product']}. Severity: {v['severity']}. "
                    f"Known exploited: {'yes' if v['kev'] else 'no'}. "
                    f"Known ransomware use: {'yes' if v.get('ransomware') else 'unknown'}.\n"
                    f"{v['description']}\nRequired action: {v['action']}\n"
                    f"Related techniques: {', '.join(v['mitre'])}",
            "tags": [v["vendor"], *v["mitre"], "KEV" if v["kev"] else "CVE"],
            "source": "CISA KEV (curated summary)",
            "url": f"https://nvd.nist.gov/vuln/detail/{v['id']}",
        })
    for p in playbooks():
        steps = "\n".join(f"- {a['description']} (risk: {a['risk_level']})" for a in p["actions"])
        docs.append({
            "doc_id": p["id"],
            "doc_type": "playbook",
            "title": f"Playbook: {p['name']}",
            "body": f"{p['description']}\nApplies to: {', '.join(p['categories'])}\nSteps:\n{steps}",
            "tags": p["categories"],
            "source": "SENTRIX AI playbook library",
            "url": None,
        })
    return docs


def seed_knowledge(db: Session) -> int:
    existing = set(db.scalars(select(IntelDocument.doc_id)).all())
    added = 0
    for d in _seed_docs():
        if d["doc_id"] not in existing:
            db.add(IntelDocument(**d))
            added += 1
    if added:
        db.commit()
        log.info("seeded %d threat-intel documents", added)
    return added


def upsert_docs(db: Session, docs: list[dict[str, Any]]) -> tuple[int, int]:
    added = updated = 0
    for d in docs:
        row = db.scalar(select(IntelDocument).where(IntelDocument.doc_id == d["doc_id"]))
        if row is None:
            db.add(IntelDocument(**d))
            added += 1
        else:
            for k, v in d.items():
                setattr(row, k, v)
            updated += 1
    db.commit()
    return added, updated


def parse_cisa_kev(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse the official CISA KEV JSON feed format."""
    out = []
    for v in payload.get("vulnerabilities", []):
        cve = v.get("cveID")
        if not cve:
            continue
        out.append({
            "doc_id": cve,
            "doc_type": "cve",
            "title": f"{cve} {v.get('vulnerabilityName', '')}".strip()[:255],
            "body": (
                f"Vendor: {v.get('vendorProject')}. Product: {v.get('product')}. Known exploited: yes. "
                f"Known ransomware use: {v.get('knownRansomwareCampaignUse', 'Unknown')}. "
                f"Added to KEV: {v.get('dateAdded')}.\n{v.get('shortDescription', '')}\n"
                f"Required action: {v.get('requiredAction', '')}"
            ),
            "tags": [t for t in (v.get("vendorProject"), "KEV") if t],
            "source": "CISA KEV",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        })
    return out


def parse_mitre_stix(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse the official MITRE ATT&CK STIX 2.x bundle (enterprise-attack.json)."""
    out = []
    for obj in payload.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext or not ext.get("external_id"):
            continue
        tactics = [p["phase_name"].replace("-", " ").title() for p in obj.get("kill_chain_phases", [])]
        out.append({
            "doc_id": ext["external_id"],
            "doc_type": "mitre_technique",
            "title": f"{ext['external_id']} {obj.get('name', '')}"[:255],
            "body": f"Tactic: {', '.join(tactics)}.\n{(obj.get('description') or '')[:6000]}\n"
                    f"Detection: {(obj.get('x_mitre_detection') or '')[:3000]}",
            "tags": tactics + [ext["external_id"].split(".")[0]],
            "source": "MITRE ATT&CK",
            "url": ext.get("url"),
        })
    return out


def load_json_file(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
