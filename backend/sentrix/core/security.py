"""Request authentication and actor identification.

SENTRIX AI supports an optional shared API key. When ``API_KEY`` is set in
the environment, all mutating requests must send ``X-API-Key``. Read-only
requests remain open so the dashboard can be demonstrated, unless
``app_env == production`` in which case reads also require the key.

The ``X-Actor`` header identifies the analyst performing an action and is
recorded in the audit log (defaults to ``anonymous-analyst``).
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request, status

from sentrix.core.config import get_settings

_ACTOR_RE = re.compile(r"^[A-Za-z0-9_.@\- ]{1,64}$")
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass(frozen=True)
class Actor:
    name: str
    ip: str | None


def _key_valid(provided: str | None) -> bool:
    expected = get_settings().api_key
    if expected is None or not expected.get_secret_value():
        return True
    if not provided:
        return False
    return hmac.compare_digest(provided.encode(), expected.get_secret_value().encode())


async def require_api_key(
    request: Request, x_api_key: str | None = Header(default=None)
) -> None:
    settings = get_settings()
    needs_key = request.method in MUTATING or settings.app_env == "production"
    if needs_key and not _key_valid(x_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-API-Key header",
        )


async def get_actor(request: Request, x_actor: str | None = Header(default=None)) -> Actor:
    name = (x_actor or "anonymous-analyst").strip()
    if not _ACTOR_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid X-Actor header")
    ip = request.client.host if request.client else None
    return Actor(name=name, ip=ip)
