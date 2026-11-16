"""Audit logging service.

Every state-changing operation in SENTRIX AI writes an immutable audit record
(no update/delete endpoints exist for audit logs).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from sentrix.core.logging import get_logger
from sentrix.core.security import Actor
from sentrix.db.models import AuditLog

log = get_logger("audit")

SYSTEM_ACTOR = Actor(name="sentrix-system", ip=None)


def record(
    db: Session,
    actor: Actor,
    action: str,
    entity_type: str,
    entity_id: Any = None,
    details: dict[str, Any] | None = None,
    outcome: str = "success",
    commit: bool = False,
) -> AuditLog:
    entry = AuditLog(
        actor=actor.name,
        ip=actor.ip,
        action=action,
        entity_type=entity_type,
        entity_id=None if entity_id is None else str(entity_id),
        details=details or {},
        outcome=outcome,
    )
    db.add(entry)
    if commit:
        db.commit()
    log.info("audit %s %s:%s by %s (%s)", action, entity_type, entity_id, actor.name, outcome)
    return entry
