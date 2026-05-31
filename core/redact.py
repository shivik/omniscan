"""Redaction helper — Golden Rule #2.

Secrets never touch logs, errors, SARIF, or the DB in plaintext. Anything that
might carry a credential, token, or scanner API key flows through ``redact()``
before it is logged or surfaced.

This is intentionally aggressive: it scrubs known secret-shaped patterns and
masks values stored under sensitive keys in dicts.
"""

from __future__ import annotations

import re
from typing import Any

_MASK = "***REDACTED***"

# Key names whose values must always be masked.
_SENSITIVE_KEYS = re.compile(
    r"(?i)(secret|token|password|passwd|api[_-]?key|auth|credential|private[_-]?key|cookie|session)"
)

# Value patterns that look like secrets regardless of their key.
_VALUE_PATTERNS = [
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"(?i)\bvault://\S+"),  # secret references — mask the path too
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),  # GitHub tokens
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9]{20,}\b"),  # generic api keys
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
]


def redact(value: Any) -> Any:
    """Return ``value`` with anything secret-shaped masked.

    Recurses into dicts/lists/tuples. Strings are pattern-scrubbed. Other scalar
    types are returned unchanged.
    """
    if isinstance(value, dict):
        return {
            k: (_MASK if _SENSITIVE_KEYS.search(str(k)) else redact(v)) for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return type(value)(redact(v) for v in value)
    if isinstance(value, str):
        return _redact_str(value)
    return value


def _redact_str(s: str) -> str:
    for pat in _VALUE_PATTERNS:
        s = pat.sub(_MASK, s)
    return s
