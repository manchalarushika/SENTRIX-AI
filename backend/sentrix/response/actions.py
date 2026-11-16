"""Incident response actions with human-in-the-loop approval.

SENTRIX AI never executes containment automatically. The council's decision
is translated into *proposed* actions. Every action must be approved by an
analyst before it is dispatched; high-risk actions (host isolation, account
disablement, zone segmentation...) additionally require a justification note.

Approved actions are dispatched either to a configured SOAR/ticketing
webhook (``SOAR_WEBHOOK_URL``) or, by default, recorded as manual tasks with
step-by-step instructions for the analyst, who then marks them completed.
"""

from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from sentrix.core.config import get_settings
from sentrix.core.logging import get_logger
from sentrix.db.models import Asset, Incident, ResponseAction, utcnow

log = get_logger("response")

MANUAL_INSTRUCTIONS = {
    "open_investigation": "Create a case in the ticketing system, assign an owner and link this incident.",
    "increase_logging": "Enable PowerShell script-block logging, command-line auditing and verbose EDR telemetry.",
    "threat_hunt": "Search all telemetry for the incident's hashes, IPs, users and command lines.",
    "reset_credentials": "Reset the account password in the identity provider and require change at next logon.",
    "revoke_sessions": "Revoke refresh tokens / sessions (e.g. Revoke-MgUserSignInSession) and purge Kerberos tickets.",
    "disable_account": "Disable the account in AD/IdP. Record the reason; re-enable only after investigation.",
    "enforce_mfa": "Require MFA re-registration and review registered authentication methods.",
    "isolate_host": "Use the EDR console to network-isolate the host (keeps EDR management channel).",
    "collect_forensics": "Capture memory and a triage package (e.g. KAPE/Velociraptor) before remediation.",
    "block_hash": "Add the file hashes to the EDR block list.",
    "block_ip": "Add a deny rule on the perimeter firewall/proxy for the address and log hits.",
    "restrict_zone_traffic": "Apply a temporary deny ACL between the affected zone and critical zones.",
    "protect_backups": "Set backup repositories to immutable/read-only and verify the latest restore point.",
    "notify_stakeholders": "Notify the incident commander and stakeholders per the communication plan.",
    "virtual_patch": "Deploy a WAF rule blocking the exploited request pattern.",
    "patch_application": "Schedule emergency patching via change management.",
    "preserve_evidence": "Export and hash relevant logs and transfer records to evidence storage.",
}


def _targets(db: Session, incident: Incident, scope: str, observer: dict[str, Any]) -> list[str]:
    if scope == "incident":
        return [incident.ref]
    if scope == "incident_hosts":
        return incident.hostnames or []
    if scope == "incident_users":
        return incident.users or []
    if scope == "external_ips":
        return observer.get("external_ips", [])[:20]
    if scope == "incident_zones":
        zones = db.scalars(
            select(Asset.network_zone).where(Asset.hostname.in_(incident.hostnames or []))
        ).all()
        return sorted(set(zones))
    if scope == "critical_assets":
        backups = db.scalars(select(Asset.hostname).where(Asset.asset_type == "backup")).all()
        if backups:
            return list(backups)[:5]
        return list(db.scalars(select(Asset.hostname).where(Asset.criticality == "critical")).all())[:5]
    return []


def propose(
    db: Session, incident: Incident, decision_id: int, playbook: dict[str, Any], observer: dict[str, Any]
) -> list[ResponseAction]:
    # Earlier proposals that were never reviewed are superseded by the new decision.
    for old in db.scalars(
        select(ResponseAction).where(ResponseAction.incident_id == incident.id,
                                     ResponseAction.status == "proposed")
    ):
        old.status = "superseded"
    created = []
    for a in playbook["actions"]:
        for target in _targets(db, incident, a["scope"], observer):
            row = ResponseAction(
                incident_id=incident.id,
                decision_id=decision_id,
                playbook=playbook["id"],
                action_type=a["type"],
                target=str(target)[:255],
                description=a["description"],
                risk_level=a["risk_level"],
                requires_approval=a["risk_level"] in ("medium", "high"),
                status="proposed",
            )
            db.add(row)
            created.append(row)
    db.flush()
    return created


class ReviewError(ValueError):
    pass


def review(db: Session, action: ResponseAction, decision: str, reviewer: str, note: str | None) -> None:
    if action.status != "proposed":
        raise ReviewError(f"action is '{action.status}', only 'proposed' actions can be reviewed")
    if decision == "approve" and action.risk_level == "high" and not (note and note.strip()):
        raise ReviewError("high-risk actions require a justification note to approve")
    action.reviewed_by = reviewer
    action.reviewed_at = utcnow()
    action.review_note = note
    if decision == "reject":
        action.status = "rejected"
        return
    action.status = "approved"
    dispatch(action)


def dispatch(action: ResponseAction) -> None:
    s = get_settings()
    payload = {
        "action_id": action.id,
        "incident_id": action.incident_id,
        "playbook": action.playbook,
        "action": action.action_type,
        "target": action.target,
        "description": action.description,
        "risk_level": action.risk_level,
        "approved_by": action.reviewed_by,
        "note": action.review_note,
    }
    if not s.soar_webhook_url:
        action.status = "pending_manual"
        action.dispatch_result = {
            "mode": "manual",
            "instructions": MANUAL_INSTRUCTIONS.get(action.action_type, action.description),
            "note": "No SOAR webhook configured; perform this step manually and mark it completed.",
        }
        return
    headers = {}
    if s.soar_webhook_token:
        headers["Authorization"] = f"Bearer {s.soar_webhook_token.get_secret_value()}"
    try:
        r = httpx.post(s.soar_webhook_url, json=payload, headers=headers, timeout=10)
        r.raise_for_status()
        action.status = "dispatched"
        action.dispatch_result = {"mode": "webhook", "http_status": r.status_code}
    except httpx.HTTPError as exc:
        log.warning("SOAR dispatch failed for action %s: %s", action.id, type(exc).__name__)
        action.status = "failed"
        action.dispatch_result = {"mode": "webhook", "error": type(exc).__name__}


def complete(action: ResponseAction, actor: str, note: str | None) -> None:
    if action.status not in ("pending_manual", "dispatched", "failed"):
        raise ReviewError(f"action is '{action.status}' and cannot be marked completed")
    action.status = "completed"
    action.dispatch_result = {**(action.dispatch_result or {}), "completed_by": actor,
                              "completed_at": utcnow().isoformat(), "completion_note": note}
