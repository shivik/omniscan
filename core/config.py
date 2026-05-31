"""Application configuration.

Secrets are *referenced* here, never stored. Real secret values are resolved at
runtime through ``core.secrets`` (Vault / cloud secret manager). The ``.env`` file
holds only non-sensitive config + references.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OMNISCAN_", env_file=".env", extra="ignore")

    # --- general ---
    env: str = "dev"
    debug: bool = True

    # --- datastore ---
    # Dev default: SQLite (zero-infra). Prod: postgresql+asyncpg://...
    database_url: str = "sqlite+aiosqlite:///./omniscan.db"

    # --- job execution ---
    # "inprocess" (dev) runs adapters in a background task. "arq" (prod) uses Redis.
    job_backend: str = "inprocess"
    redis_url: str = "redis://localhost:6379/0"

    # --- object store (raw output + reports) ---
    object_store_url: str = "file://./var/objects"

    # --- secrets manager ---
    secrets_backend: str = "env"  # "env" (dev) | "vault" (prod)

    # --- auth ---
    # Dev convenience: a single bootstrap admin token. Prod issues per-user tokens.
    bootstrap_admin_token: str = "dev-admin-token"
    token_ttl_seconds: int = 3600

    @property
    def is_dev(self) -> bool:
        return self.env == "dev"


@lru_cache
def get_settings() -> Settings:
    return Settings()
