"""DemoScan — a built-in, dependency-free SAST adapter.

It exists so the platform runs end-to-end with zero external scanner images. It
performs a *safe* pure-Python pattern scan of a read-only checkout — no subprocess,
no network — matching a handful of well-known insecure-code patterns and emitting a
native JSON report, which ``parse_output`` converts to SARIF 2.1.0.

Real adapters (semgrep, codeql, bandit, ...) follow the same contract but declare a
pinned container image and run in an isolated container. See
``deploy/scanners/<name>/Dockerfile`` and AGENT.md §8.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from adapters.base import ContainerSpec, ResourceLimits, ScannerAdapter, ScanRequest
from core.enums import ScanClass
from normalize.sarif import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    Region,
    ReportingDescriptor,
    Result,
    Run,
    SarifLog,
    Tool,
    ToolComponent,
)

# (rule_id, title, severity, compiled pattern). Illustrative, not exhaustive.
_RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("DS001", "Use of eval()", "high", re.compile(r"\beval\s*\(")),
    (
        "DS002",
        "Shell injection via subprocess(shell=True)",
        "high",
        re.compile(r"shell\s*=\s*True"),
    ),
    (
        "DS003",
        "Insecure deserialization (pickle.loads)",
        "high",
        re.compile(r"pickle\.loads?\s*\("),
    ),
    (
        "DS004",
        "Hardcoded password literal",
        "medium",
        re.compile(r"(?i)password\s*=\s*['\"][^'\"]{3,}['\"]"),
    ),
    ("DS005", "Weak hash (md5)", "low", re.compile(r"(?i)hashlib\.md5\s*\(")),
    ("DS006", "Disabled TLS verification", "high", re.compile(r"verify\s*=\s*False")),
]

_SCANNABLE_SUFFIXES = {".py", ".js", ".ts", ".go", ".rb", ".java", ".php"}
_MAX_FILE_BYTES = 1_000_000


class DemoScanAdapter(ScannerAdapter):
    name = "demoscan"
    scan_class = ScanClass.SAST
    capabilities = ["pattern-match", "multi-language"]
    native = True

    def validate_inputs(self, request: ScanRequest) -> None:
        if request.scan_class is not ScanClass.SAST:
            raise ValueError("demoscan only handles SAST")
        if not request.workspace_path:
            raise ValueError("demoscan requires a checked-out workspace path")
        if not Path(request.workspace_path).is_dir():
            raise ValueError("workspace_path does not exist or is not a directory")

    def build_invocation(self, request: ScanRequest) -> ContainerSpec:
        # Declared for parity with containerized adapters; the native runner uses
        # run_native() in dev. SAST gets no network and a read-only workspace mount.
        return ContainerSpec(
            image="omniscan/demoscan:0.1.0",
            args=["scan", "/workspace"],
            mounts={request.workspace_path or ".": "/workspace"},
            read_only_root=True,
            network="none",
            limits=ResourceLimits(timeout_seconds=300),
        )

    def run_native(self, request: ScanRequest) -> bytes:
        root = Path(request.workspace_path or ".")
        results: list[dict[str, Any]] = []
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in _SCANNABLE_SUFFIXES:
                continue
            if any(part in {".git", "node_modules", ".venv", "venv"} for part in path.parts):
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(path.relative_to(root))
            for lineno, line in enumerate(text.splitlines(), start=1):
                for rule_id, title, severity, pattern in _RULES:
                    if pattern.search(line):
                        results.append(
                            {
                                "rule_id": rule_id,
                                "title": title,
                                "severity": severity,
                                "file": rel,
                                "line": lineno,
                                "snippet": line.strip()[:200],
                            }
                        )
        return json.dumps({"tool": "demoscan", "version": "0.1.0", "results": results}).encode()

    def parse_output(self, raw: bytes) -> SarifLog:
        data = json.loads(raw.decode())
        rule_ids = {(r[0]): r[1] for r in _RULES}
        seen_rules: dict[str, ReportingDescriptor] = {}
        sarif_results: list[Result] = []
        for item in data.get("results", []):
            rid = item["rule_id"]
            seen_rules.setdefault(
                rid,
                ReportingDescriptor(
                    id=rid, name=rule_ids.get(rid), shortDescription=Message(text=item["title"])
                ),
            )
            sarif_results.append(
                Result(
                    ruleId=rid,
                    level="error" if item["severity"] == "high" else "warning",
                    message=Message(text=f"{item['title']}: {item.get('snippet', '')}"),
                    locations=[
                        Location(
                            physicalLocation=PhysicalLocation(
                                artifactLocation=ArtifactLocation(uri=item["file"]),
                                region=Region(startLine=item["line"]),
                            )
                        )
                    ],
                    properties={"severity": item["severity"]},
                )
            )
        return SarifLog(
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="demoscan", version="0.1.0", rules=list(seen_rules.values())
                        )
                    ),
                    results=sarif_results,
                )
            ]
        )
