"""AuthN/AuthZ + RBAC — token-based auth with roles.

Roles (ascending privilege): viewer < scanner < triager < admin.
  * viewer  — read findings, read + post comments
  * scanner — viewer + create scans
  * triager — scanner + change triage state / assignment
  * admin   — everything + suppression policy + PoC (RVD) access

Dev issues a single bootstrap admin token (config). Prod issues per-user signed
tokens. Tokens are opaque to clients; the server maps token -> principal.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.config import get_settings
from core.enums import Role


@dataclass(frozen=True)
class Principal:
    user_id: str
    email: str
    role: Role


class AuthError(Exception):
    pass


class Forbidden(Exception):
    pass


# Dev in-memory token store. Prod: signed JWT / opaque token table.
_TOKENS: dict[str, Principal] = {}


def bootstrap() -> None:
    """Register the dev bootstrap admin token."""
    settings = get_settings()
    _TOKENS[settings.bootstrap_admin_token] = Principal(
        user_id="user_bootstrap", email="admin@omniscan.local", role=Role.admin
    )


def issue_token(token: str, principal: Principal) -> None:
    _TOKENS[token] = principal


def authenticate(token: str | None) -> Principal:
    if not token:
        raise AuthError("missing bearer token")
    principal = _TOKENS.get(token)
    if principal is None:
        raise AuthError("invalid token")
    return principal


def require_role(principal: Principal, minimum: Role) -> None:
    if principal.role.rank < minimum.rank:
        raise Forbidden(f"role '{principal.role}' lacks required role '{minimum}'")


def can_view_poc(principal: Principal) -> bool:
    """PoC / exploit artifacts (RVD) are admin-gated (AGENT.md §2.6)."""
    return principal.role == Role.admin
