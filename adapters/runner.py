"""Sandbox runners — execute an adapter's ``ContainerSpec`` in isolation.

Golden Rule #3: scanners run isolated — own container, no inbound network,
constrained egress, resource limits, read-only target mount. The worker never runs
scanner binaries in-process.

Two runners:
  * ``NativeRunner`` — dev path for built-in ``native`` adapters (pure-Python, no
    subprocess, no network). Honors the network/mount constraints by construction
    (it cannot open sockets or spawn processes).
  * ``DockerContainerRunner`` — the real path for containerized adapters. Runs the
    pinned image via the Docker engine with the declared isolation: no inbound
    network, ``--network none`` for SAST, read-only root + read-only mounts, a
    writable tmpfs for scratch, and CPU/memory/time limits.

Secret refs in the spec are resolved at the boundary and injected as container env;
they never appear in logs (redacted) or persisted state.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Any, Protocol

from adapters.base import ContainerSpec, ScannerAdapter, ScanRequest
from core.redact import redact
from core.secrets import get_secrets_backend

log = logging.getLogger("omniscan.runner")


class RunnerError(RuntimeError):
    pass


def _enforce_sast_network(request: ScanRequest, spec: ContainerSpec) -> None:
    """SAST must not reach the network, with ONE documented exception: SCA (e.g. trivy)
    may use constrained ``egress`` for advisory-DB feeds (SKILLS.md §2). ``target``
    egress is a DAST concept and is never allowed for SAST."""
    if request.scan_class.value == "SAST" and spec.network == "target":
        raise RunnerError("SAST adapters must not use target egress")


class Runner(Protocol):
    def run(self, adapter: ScannerAdapter, spec: ContainerSpec, request: ScanRequest) -> bytes:
        """Execute the adapter in isolation and return its raw native output."""
        ...


class NativeRunner:
    """Dev runner for built-in native adapters."""

    def run(self, adapter: ScannerAdapter, spec: ContainerSpec, request: ScanRequest) -> bytes:
        if not adapter.native:
            raise RunnerError(f"adapter '{adapter.name}' is not native — use DockerContainerRunner")
        _enforce_sast_network(request, spec)
        return adapter.run_native(request)


class DockerContainerRunner:
    """Run a pinned scanner image in an isolated container via the Docker CLI."""

    def __init__(self, docker_bin: str | None = None) -> None:
        self._docker = docker_bin or shutil.which("docker")

    def run(self, adapter: ScannerAdapter, spec: ContainerSpec, request: ScanRequest) -> bytes:
        if self._docker is None:
            raise RunnerError("docker is not available to run containerized adapters")
        _enforce_sast_network(request, spec)
        if spec.image.endswith(":latest") or ":" not in spec.image:
            raise RunnerError(f"scanner image must be pinned to a version, not '{spec.image}'")

        # Resolve secret refs into container env only (never logged / persisted).
        secrets = get_secrets_backend()
        resolved_env = dict(spec.env)
        for env_var, ref in spec.secret_refs.items():
            resolved_env[env_var] = secrets.resolve(ref)

        cmd = self._build_command(spec, resolved_env)
        # Log a redacted command (env values masked) for traceability.
        log.info("running adapter %s: %s", adapter.name, redact(self._loggable(spec)))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=spec.limits.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RunnerError(
                f"adapter {adapter.name} timed out after {spec.limits.timeout_seconds}s"
            ) from exc

        if proc.returncode not in spec.success_exit_codes:
            stderr = redact(proc.stderr.decode("utf-8", "ignore"))[:2000]
            raise RunnerError(f"adapter {adapter.name} exited {proc.returncode}: {stderr}")
        return proc.stdout

    def _build_command(self, spec: ContainerSpec, env: dict[str, str]) -> list[str]:
        assert self._docker is not None
        cmd = [self._docker, "run", "--rm", "--init"]

        # Network: SAST/none get no network; egress/target get the default bridge.
        cmd += ["--network", "none" if spec.network == "none" else "bridge"]

        # No inbound surface, drop privileges, no privilege escalation.
        cmd += ["--cap-drop", "ALL", "--security-opt", "no-new-privileges"]

        if spec.read_only_root:
            cmd.append("--read-only")
        if spec.writable_tmp:
            cmd += ["--tmpfs", "/tmp:rw,exec,size=256m"]

        # Resource limits.
        cmd += ["--cpus", str(spec.limits.cpu), "--memory", f"{spec.limits.memory_mb}m"]
        cmd += ["--pids-limit", "512"]

        # Read-only mounts of the target/workspace and any aux files.
        for host_path, container_path in spec.mounts.items():
            cmd += ["-v", f"{host_path}:{container_path}:ro"]

        for key, value in env.items():
            cmd += ["-e", f"{key}={value}"]

        cmd.append(spec.image)
        cmd += spec.args
        return cmd

    @staticmethod
    def _loggable(spec: ContainerSpec) -> dict[str, Any]:
        return {
            "image": spec.image,
            "args": spec.args,
            "network": spec.network,
            "mounts": spec.mounts,
            "env": spec.env,  # redact() masks secret-shaped keys/values
            "secret_refs": list(spec.secret_refs.keys()),
        }


def get_runner(adapter: ScannerAdapter) -> Runner:
    return NativeRunner() if adapter.native else DockerContainerRunner()
