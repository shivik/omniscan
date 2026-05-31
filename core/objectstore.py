"""Object store for raw scanner output + rendered reports.

Dev: local filesystem under ``OMNISCAN_OBJECT_STORE_URL`` (file://). Prod:
S3-compatible (MinIO in dev infra). Returns an opaque key/ref; callers never
embed secrets in stored objects (output is already redacted upstream).
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from core.config import get_settings


def _root() -> Path:
    url = get_settings().object_store_url
    parsed = urlparse(url)
    if parsed.scheme not in ("file", ""):
        raise NotImplementedError(f"object store scheme not wired in dev: {parsed.scheme}")
    root = Path((parsed.netloc or "") + parsed.path) if url.startswith("file://") else Path(url)
    root.mkdir(parents=True, exist_ok=True)
    return root


def put(key: str, data: bytes) -> str:
    path = _root() / key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return f"obj://{key}"


def get(ref: str) -> bytes:
    key = ref.removeprefix("obj://")
    return (_root() / key).read_bytes()
