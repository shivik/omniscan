"""Prepare a read-only workspace for source-based scans (SAST/RVD).

Resolves a ``source`` spec into a local checkout path that adapters mount
read-only. Dev supports a local ``path`` source directly and shallow ``git`` clones
where ``git`` is available. The checkout is treated as read-only by adapters.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any


class WorkspaceError(Exception):
    pass


def prepare(source: dict[str, Any]) -> str | None:
    """Return a local path to the source, or None if the scan has no source."""
    if not source:
        return None
    kind = source.get("type")
    if kind == "path":
        path = source.get("path")
        if not path or not Path(path).is_dir():
            raise WorkspaceError(f"source path not found: {path}")
        return str(Path(path).resolve())
    if kind == "git":
        return _clone(source)
    if kind == "image":
        # Container-image SCA (Clair) scans an image reference, not a checkout.
        return None
    raise WorkspaceError(f"unsupported source type: {kind}")


def _clone(source: dict[str, Any]) -> str:
    url = source.get("url")
    ref = source.get("ref", "HEAD")
    if not url:
        raise WorkspaceError("git source requires a url")
    dest = tempfile.mkdtemp(prefix="omniscan-ws-")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, dest],
            check=True,
            capture_output=True,
            timeout=300,
        )
        if ref and ref != "HEAD":
            subprocess.run(
                ["git", "-C", dest, "fetch", "--depth", "1", "origin", ref],
                check=True,
                capture_output=True,
                timeout=300,
            )
            subprocess.run(
                ["git", "-C", dest, "checkout", "FETCH_HEAD"],
                check=True,
                capture_output=True,
                timeout=120,
            )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        raise WorkspaceError(f"failed to clone source: {e}") from e
    return dest
