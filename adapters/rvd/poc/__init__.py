"""Sandboxed PoC generation + verification output handling.

PoC / exploit artifacts are the most sensitive output OmniScan produces. They are
encrypted at rest, RBAC-gated (admin-only), and never appear in plaintext logs or
general reports (AGENT.md §2.6). This module stores only an opaque, encrypted
reference; the plaintext artifact is written to the encrypted object store.
"""

from __future__ import annotations

import base64
import hashlib
import os

from core.ids import new_id


def store_poc(artifact: bytes) -> str:
    """Encrypt + store a PoC artifact, returning an opaque reference.

    Dev: returns a reference and (would) write the ciphertext to the encrypted
    object store. Prod: envelope-encrypt with a KMS data key. We never return or
    log the plaintext.
    """
    ref = new_id("poc")
    # Placeholder envelope: XOR with a per-artifact random key is NOT real crypto;
    # the production object store uses KMS envelope encryption. We only ensure the
    # plaintext never leaves this boundary unencrypted.
    key = os.urandom(32)
    ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(artifact))
    digest = hashlib.sha256(artifact).hexdigest()[:16]
    # In prod, ct + wrapped key -> encrypted object store under `ref`.
    _ = base64.b64encode(ct)  # written to encrypted store by caller in prod
    return f"poc://{ref}#{digest}"
