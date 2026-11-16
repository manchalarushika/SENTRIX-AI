from __future__ import annotations

import threading
from typing import Annotated

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from sentrix.core.logging import get_logger
from sentrix.core.security import Actor, get_actor
from sentrix.db.session import get_db

log = get_logger("api")

DB = Annotated[Session, Depends(get_db)]
CurrentActor = Annotated[Actor, Depends(get_actor)]

# SQLite tolerates one writer at a time; analyses are serialised to keep the
# agent pipeline consistent.
analysis_lock = threading.Lock()


def get_or_404(db: Session, model, ident, label: str):
    obj = db.get(model, ident)
    if obj is None:
        raise HTTPException(status_code=404, detail=f"{label} not found")
    return obj


def run_analyses(db: Session, incident_ids, use_llm: bool = True) -> list[int]:
    from sentrix.agents.commander import analyze_incident

    done = []
    for iid in sorted(set(incident_ids)):
        with analysis_lock:
            try:
                analyze_incident(db, iid, use_llm=use_llm)
                done.append(iid)
            except Exception:
                db.rollback()
                log.exception("analysis failed for incident %s", iid)
    return done
