"""Secrets resolution — Cross-cutting skill.

Adapters receive credentials only by *reference* (e.g. ``vault://omniscan/acme/login``).
The reference is resolved here and injected into the adapter container at runtime;
the plaintext value never appears in the API, logs, SARIF, or the DB.

Dev backend reads from the environment (``OMNISCAN_SECRET_<NAME>``). Prod wires a
Vault / cloud-secret-manager client behind the same interface.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

from core.config import get_settings


class SecretsBackend(ABC):
    @abstractmethod
    def resolve(self, ref: str) -> str:
        """Resolve a ``ref://path`` reference to its plaintext value."""


class EnvSecretsBackend(SecretsBackend):
    """Dev backend. ``vault://omniscan/acme/login`` -> env ``OMNISCAN_SECRET_ACME_LOGIN``."""

    def resolve(self, ref: str) -> str:
        scheme, _, path = ref.partition("://")
        if not path:
            raise SecretNotFound(ref)
        env_key = (
            "OMNISCAN_SECRET_" + path.split("/", 1)[-1].replace("/", "_").replace("-", "_").upper()
        )
        val = os.environ.get(env_key)
        if val is None:
            raise SecretNotFound(ref)
        return val


class VaultSecretsBackend(SecretsBackend):
    """HashiCorp Vault (KV v2). Ref form: ``vault://<mount>/<path>#<key>``.

    ``hvac`` is imported lazily and only required when this backend is selected.
    Reads ``VAULT_ADDR`` + ``VAULT_TOKEN`` from the environment. The resolved plaintext
    is injected into the adapter container only — never logged or persisted.
    """

    def __init__(self) -> None:
        try:
            import hvac  # noqa: PLC0415  (optional prod dependency)
        except ImportError as exc:  # pragma: no cover - depends on env
            raise RuntimeError(
                "Vault backend requires hvac (pip install 'omniscan[prod]')"
            ) from exc
        addr = os.environ.get("VAULT_ADDR")
        token = os.environ.get("VAULT_TOKEN")
        if not addr or not token:
            raise RuntimeError("Vault backend requires VAULT_ADDR and VAULT_TOKEN")
        self._client = hvac.Client(url=addr, token=token)

    def resolve(self, ref: str) -> str:
        _, _, rest = ref.partition("://")
        path, _, key = rest.partition("#")
        if not path or not key:
            raise SecretNotFound(ref)
        mount, _, secret_path = path.partition("/")
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(
                mount_point=mount, path=secret_path
            )
            value = resp["data"]["data"].get(key)
        except Exception as exc:  # noqa: BLE001
            raise SecretNotFound(ref) from exc
        if value is None:
            raise SecretNotFound(ref)
        return str(value)


class SecretNotFound(KeyError):
    def __init__(self, ref: str) -> None:
        # Never echo the ref's full path in a way that could leak structure broadly,
        # but the ref itself is not the secret value, so naming it for debugging is ok.
        super().__init__(f"secret reference could not be resolved: {ref}")


_BACKENDS: dict[str, type[SecretsBackend]] = {
    "env": EnvSecretsBackend,
    "vault": VaultSecretsBackend,
}


def get_secrets_backend() -> SecretsBackend:
    name = get_settings().secrets_backend
    backend_cls = _BACKENDS.get(name)
    if backend_cls is None:
        raise RuntimeError(f"unknown secrets backend: {name}")
    return backend_cls()


def is_secret_ref(value: str) -> bool:
    return "://" in value and value.split("://", 1)[0] in {"vault", "ref", "aws-sm", "gcp-sm"}
