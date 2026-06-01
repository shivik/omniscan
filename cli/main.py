"""OmniScan CLI.

A thin client: every command maps to one or more API calls. There is no scan logic
here — if a capability isn't in the API, it doesn't exist in the CLI either.

    omniscan scan sast --repo . --tools demoscan --wait
    omniscan scan rvd  --repo . --focus isolation,deserialization --budget 1h --wait
    omniscan findings list --scan scan_xxx --min-severity medium
    omniscan findings triage find_xxx --status false_positive --reason "test fixture"
    omniscan report scan_xxx --format sarif
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="OmniScan — security scanner orchestration (thin API client).")
scan_app = typer.Typer(help="Create and inspect scans.")
findings_app = typer.Typer(help="List and triage findings.")
app.add_typer(scan_app, name="scan")
app.add_typer(findings_app, name="findings")

console = Console()

API = os.environ.get("OMNISCAN_API", "http://127.0.0.1:8000")
TOKEN = os.environ.get("OMNISCAN_TOKEN", "dev-admin-token")


def _client() -> httpx.Client:
    return httpx.Client(base_url=API, headers={"Authorization": f"Bearer {TOKEN}"}, timeout=30)


def _check(resp: httpx.Response) -> Any:
    if resp.status_code >= 400:
        try:
            problem = resp.json()
            console.print(f"[red]{problem.get('title')}[/red]: {problem.get('detail')}")
        except Exception:
            console.print(f"[red]HTTP {resp.status_code}[/red]: {resp.text}")
        raise typer.Exit(1)
    return resp.json()


def _poll(scan_id: str) -> Any:
    with _client() as c:
        while True:
            scan = _check(c.get(f"/api/v1/scans/{scan_id}"))
            status = scan["status"]
            console.print(f"  scan {scan_id}: [cyan]{status}[/cyan]")
            if status in {"completed", "failed", "cancelled"}:
                return scan
            time.sleep(1)


def _create_scan(payload: dict[str, Any], wait: bool) -> None:
    with _client() as c:
        scan = _check(c.post("/api/v1/scans", json=payload))
    console.print(f"created scan [green]{scan['id']}[/green] ({scan['scan_class']})")
    if wait:
        scan = _poll(scan["id"])
        if scan["status"] == "failed":
            console.print(f"[red]scan failed:[/red] {scan.get('error')}")
            raise typer.Exit(1)
        _print_findings(scan["id"])


@scan_app.command("sast")
def scan_sast(
    project: str = typer.Option(..., "--project", help="project id"),
    repo: str = typer.Option("", "--repo", help="local repo path (or use --url)"),
    url: str = typer.Option("", "--url", help="git repo URL to clone + scan"),
    ref: str = typer.Option("", "--ref", help="git ref/branch/tag (with --url)"),
    scope_allow: str = typer.Option(
        "", "--scope-allow", help="host allowlist for --url (e.g. github.com)"
    ),
    tools: str = typer.Option("", "--tools", help="comma-separated adapters"),
    wait: bool = typer.Option(False, "--wait"),
) -> None:
    if url:
        source: dict[str, Any] = {"type": "git", "url": url}
        if ref:
            source["ref"] = ref
    else:
        source = {"type": "path", "path": os.path.abspath(repo or ".")}
    payload: dict[str, Any] = {
        "scan_class": "SAST",
        "project_id": project,
        "source": source,
        "tools": [t for t in tools.split(",") if t] or None,
    }
    if scope_allow.strip():
        payload["scope"] = {"allow": [h.strip() for h in scope_allow.split(",") if h.strip()]}
    _create_scan(payload, wait)


@scan_app.command("rvd")
def scan_rvd(
    project: str = typer.Option(..., "--project"),
    repo: str = typer.Option(".", "--repo"),
    focus: str = typer.Option("", "--focus", help="e.g. isolation,deserialization"),
    budget: str = typer.Option("1h", "--budget"),
    backend: str = typer.Option("", "--backend"),
    wait: bool = typer.Option(False, "--wait"),
) -> None:
    payload = {
        "scan_class": "RVD",
        "project_id": project,
        "source": {"type": "path", "path": os.path.abspath(repo)},
        "rvd": {
            "budget": budget,
            "focus": [f for f in focus.split(",") if f],
            "backend": backend or None,
        },
    }
    _create_scan(payload, wait)


@scan_app.command("dast")
def scan_dast(
    project: str = typer.Option(..., "--project"),
    target: str = typer.Option(..., "--target", help="base URL of the authorized target"),
    scope_allow: str = typer.Option("", "--scope-allow", help="comma-separated host allowlist"),
    tools: str = typer.Option("nuclei", "--tools"),
    rate_limit: str = typer.Option("", "--rate-limit", help="e.g. 20rps"),
    wait: bool = typer.Option(False, "--wait"),
) -> None:
    payload: dict[str, Any] = {
        "scan_class": "DAST",
        "project_id": project,
        "target": {"base_url": target},
        "tools": [t for t in tools.split(",") if t] or None,
    }
    if scope_allow.strip():
        payload["scope"] = {"allow": [h.strip() for h in scope_allow.split(",") if h.strip()]}
    if rate_limit:
        payload["options"] = {"rate_limit": rate_limit}
    _create_scan(payload, wait)


@scan_app.command("status")
def scan_status(scan_id: str) -> None:
    with _client() as c:
        scan = _check(c.get(f"/api/v1/scans/{scan_id}"))
    console.print_json(data=scan)


@findings_app.command("list")
def findings_list(
    scan: str = typer.Option(None, "--scan"),
    project: str = typer.Option(None, "--project"),
    min_severity: str = typer.Option(None, "--min-severity"),
    scan_class: str = typer.Option(None, "--class"),
    chainable_only: bool = typer.Option(False, "--chainable-only"),
) -> None:
    params = {
        k: v
        for k, v in {
            "scan_id": scan,
            "project_id": project,
            "min_severity": min_severity,
            "scan_class": scan_class,
            "chainable_only": chainable_only or None,
        }.items()
        if v
    }
    with _client() as c:
        rows = _check(c.get("/api/v1/findings", params=params))
    _render_findings(rows)


@findings_app.command("triage")
def findings_triage(
    finding_id: str,
    status: str = typer.Option(..., "--status"),
    reason: str = typer.Option(None, "--reason"),
) -> None:
    with _client() as c:
        out = _check(
            c.patch(
                f"/api/v1/findings/{finding_id}/triage", json={"status": status, "reason": reason}
            )
        )
    console.print(f"triaged {finding_id} -> [yellow]{out['status']}[/yellow]")


@app.command("report")
def report(scan_id: str, format: str = typer.Option("json", "--format")) -> None:
    with _client() as c:
        out = _check(c.get(f"/api/v1/scans/{scan_id}/report", params={"format": format}))
    console.print_json(data=out)


@app.command("capabilities")
def capabilities() -> None:
    with _client() as c:
        out = _check(c.get("/api/v1/capabilities"))
    table = Table("adapter", "class", "capabilities")
    for a in out["adapters"]:
        table.add_row(a["name"], a["scan_class"], ", ".join(a["capabilities"]))
    console.print(table)


def _print_findings(scan_id: str) -> None:
    with _client() as c:
        rows = _check(c.get("/api/v1/findings", params={"scan_id": scan_id}))
    _render_findings(rows)


def _render_findings(rows: list[dict[str, Any]]) -> None:
    if not rows:
        console.print("[dim]no findings[/dim]")
        return
    table = Table("id", "severity", "status", "rule", "title", "chain")
    for f in rows:
        table.add_row(
            f["id"],
            f["effective_severity"],
            f["effective_status"],
            f["rule_id"],
            f["title"][:50],
            f"{f['chainability_score']:.2f}",
        )
    console.print(table)


if __name__ == "__main__":
    app()
