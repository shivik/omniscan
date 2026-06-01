"""Object store for raw scanner output + rendered reports.

Pluggable by the ``OMNISCAN_OBJECT_STORE_URL`` scheme:
  * ``file://`` (dev, default) — local filesystem, zero-infra.
  * ``s3://bucket/prefix`` (prod) — S3-compatible (AWS S3 / MinIO). ``boto3`` is
    imported lazily and only required when this scheme is selected; the endpoint
    (for MinIO) and credentials come from the environment.

Returns an opaque ``obj://`` ref. Callers never embed secrets in stored objects
(output is already redacted upstream).
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from core.config import get_settings


def _scheme() -> str:
    return urlparse(get_settings().object_store_url).scheme or "file"


# ---- filesystem backend (dev) ----
def _root() -> Path:
    url = get_settings().object_store_url
    parsed = urlparse(url)
    root = Path((parsed.netloc or "") + parsed.path) if url.startswith("file://") else Path(url)
    root.mkdir(parents=True, exist_ok=True)
    return root


# ---- S3 backend (prod) ----
def _s3_client_and_bucket() -> tuple[object, str, str]:
    try:
        import boto3  # noqa: PLC0415  (optional prod dependency)
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError("S3 object store requires boto3 (pip install 'omniscan[prod]')") from exc
    parsed = urlparse(get_settings().object_store_url)
    bucket = parsed.netloc
    prefix = parsed.path.lstrip("/")
    client = boto3.client(
        "s3",
        endpoint_url=os.environ.get("OMNISCAN_S3_ENDPOINT"),  # set for MinIO; unset for AWS
        region_name=os.environ.get("AWS_REGION", "us-east-1"),
    )
    return client, bucket, prefix


def put(key: str, data: bytes) -> str:
    if _scheme() == "s3":
        client, bucket, prefix = _s3_client_and_bucket()
        client.put_object(Bucket=bucket, Key=f"{prefix}{key}", Body=data)  # type: ignore[attr-defined]
        return f"obj://{key}"
    path = _root() / key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return f"obj://{key}"


def get(ref: str) -> bytes:
    key = ref.removeprefix("obj://")
    if _scheme() == "s3":
        client, bucket, prefix = _s3_client_and_bucket()
        obj = client.get_object(Bucket=bucket, Key=f"{prefix}{key}")  # type: ignore[attr-defined]
        return bytes(obj["Body"].read())
    return (_root() / key).read_bytes()
