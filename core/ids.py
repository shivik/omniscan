"""Prefixed, sortable identifiers (e.g. ``scan_3f9c...``)."""

from __future__ import annotations

import secrets

_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


def _rand(n: int = 16) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def new_id(prefix: str) -> str:
    return f"{prefix}_{_rand()}"
