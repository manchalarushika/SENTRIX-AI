"""Demo data loader (clearly synthetic).

Provides a fictional enterprise ("Meridian Energy"), seven days of benign
baseline telemetry so behavioural baselines exist, and alert-level attack
scenarios. Everything is replayed through the *real* ingestion API pipeline,
so the demo exercises the same code paths as production telemetry.
"""

from __future__ import annotations

import json
import random
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentrix.core.config import DATA_DIR
from sentrix.db.models import Asset, SecurityEvent, utcnow
from sentrix.schemas.events import EventIngest
from sentrix.services.ingest import IngestOutcome, ingest_many

SCENARIO_DIR = DATA_DIR / "scenarios"
BENIGN_PROCESSES = ["C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                    "C:\\Users\\Public\\AppData\\Local\\Microsoft\\Teams\\ms-teams.exe"]
BENIGN_DOMAINS = ["outlook.office365.com", "teams.microsoft.com", "www.google.com",
                  "intranet.meridian.local", "sharepoint.com"]


def enterprise() -> dict[str, Any]:
    return json.loads((SCENARIO_DIR / "demo_enterprise.json").read_text(encoding="utf-8"))


def list_scenarios() -> list[dict[str, Any]]:
    out = []
    for p in sorted(SCENARIO_DIR.glob("*.json")):
        if p.stem == "demo_enterprise":
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        out.append({"name": d["name"], "title": d["title"], "description": d["description"],
                    "events": len(d["events"])})
    return out


def load_assets(db: Session) -> int:
    added = 0
    for a in enterprise()["assets"]:
        row = db.scalar(select(Asset).where(Asset.hostname == a["hostname"]))
        if row is None:
            db.add(Asset(**a, status="online", risk_score=0.0))
            added += 1
    db.commit()
    return added


def baseline_events(days: int = 7, seed: int = 42) -> list[EventIngest]:
    rng = random.Random(seed)
    users = enterprise()["users"]
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    events: list[EventIngest] = []
    for d in range(days, 0, -1):
        day = now - timedelta(days=d)
        if day.weekday() >= 5:
            continue
        for user, host in users.items():
            for _ in range(rng.randint(10, 14)):
                ts = day.replace(hour=rng.randint(8, 17), minute=rng.randint(0, 59))
                kind = rng.choice(["logon", "process", "dns", "net"])
                base = dict(source="baseline-synthetic", timestamp=ts, hostname=host, user=user)
                if kind == "logon":
                    events.append(EventIngest(event_type="Successful Logon", src_ip="10.2.0.1", **base))
                elif kind == "process":
                    events.append(EventIngest(event_type="Process Creation", process=rng.choice(BENIGN_PROCESSES), **base))
                elif kind == "dns":
                    q = rng.choice(BENIGN_DOMAINS)
                    events.append(EventIngest(event_type="DNS Query", description=f"DNS query for {q}", **base))
                else:
                    events.append(EventIngest(event_type="Network Connection", dst_ip="10.1.0.30", dst_port=445, **base))
    return events


def load_baseline(db: Session) -> IngestOutcome:
    exists = db.scalar(select(SecurityEvent.id).where(SecurityEvent.source == "baseline-synthetic").limit(1))
    if exists:
        return IngestOutcome()
    return ingest_many(db, baseline_events())


def scenario_events(name: str) -> list[EventIngest]:
    path = SCENARIO_DIR / f"{name}.json"
    if not path.is_file() or name == "demo_enterprise":
        raise FileNotFoundError(name)
    d = json.loads(path.read_text(encoding="utf-8"))
    span = max(e["offset_min"] for e in d["events"])
    start = utcnow() - timedelta(minutes=span + 2, hours=d.get("hours_ago", 0))
    if "start_hour_utc" in d:
        start = start.replace(hour=d["start_hour_utc"], minute=0)
        if start > utcnow():
            start -= timedelta(days=1)
    out = []
    for e in d["events"]:
        e = dict(e)
        ts = start + timedelta(minutes=e.pop("offset_min"), seconds=len(out))
        out.append(EventIngest(timestamp=ts, **e))
    return out
