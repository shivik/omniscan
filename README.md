# OmniScan

One-stop application security scanner orchestration platform — **SAST · DAST · IAST · RVD**
behind a single REST API. The CLI, dashboard, and CI are thin clients over that API.

> RVD (Residual Vulnerability Discovery) is the flagship: an agentic
> comprehend → hypothesize → probe/verify → score-chainability loop for the
> *unknown-unknowns* signature scanners can't reach. See [`SKILLS.md`](./SKILLS.md) §R.

Read [`AGENT.md`](./AGENT.md) for architecture + the non-negotiable safety rules,
and [`SKILLS.md`](./SKILLS.md) for the capability catalog.

## Status — initial vertical slice

This repo currently implements a **runnable end-to-end backend slice** with zero
external infra (SQLite + in-process worker), keeping the production abstractions
(ContainerSpec, JobQueue, object store, secrets manager) pluggable:

```
project/target → POST /scans → planner (scope_guard) → scheduler
  → adapter (isolated runner) → SARIF → normalize → dedup
  → immutable Finding → triage / comment / report / CI gate
```

Implemented:
- **core/** — config, async DB + models, `scope_guard`, `redact`, secrets, RBAC, object store
- **engine/** — planner (scope-first), workspace prep, lifecycle state machine, scheduler
- **adapters/** — `ScannerAdapter` ABC, sandbox runners, registry. SAST: `demoscan`
  (zero-infra), **`semgrep`**, **`bandit`**, **`gitleaks`**, **`codeql`**; SCA: **`trivy`**
  (source manifests) + **`clair`** (container images). DAST: **`nuclei`**, **`zap`**. Plus
  the **RVD** engine — pluggable open-source backends (`ollama` local LLM → `heuristic`),
  residual-risk tiering, chainability, embargo
- **omniscan_iast/** — a real **Python IAST runtime agent**: instruments dangerous sinks in
  a running app and reports tainted source→sink flows to the collector (`/iast/sessions/{id}/events`)
- **migrations/** — Alembic (async); SQLite for dev, **PostgreSQL** (asyncpg) for prod
- **dashboard/Residual Risk** — flagship view tiering RVD findings into known-known /
  known-unknown / **unknown-unknown**, with reasoning trace, composition path, and confidence
- **normalize/** — SARIF 2.1.0 model, severity mapping, SARIF→Finding, fingerprint + dedup
- **api/** — FastAPI: auth, projects, targets, scans, findings, triage, comments, reports, CI gate
- **cli/** — Typer thin client
- **dashboard/** — React 18 + TypeScript + Vite vuln-management workspace (thin client):
  unified findings view with filters/search, finding detail with the RVD reasoning /
  composition / chainability panel (PoC admin-gated), triage + assignment, status-history
  timeline, threaded comments, scans list + new-scan wizard, projects

**Containerized scanning** is real across SAST *and* DAST. SAST (`tools=["semgrep","gitleaks"]`)
runs `--network none`; DAST (`tools=["nuclei"]`) runs with egress scoped to the authorized
target. All run in isolated containers — read-only root + read-only mounts, writable tmpfs,
dropped caps, `no-new-privileges`, CPU/mem/pids/time limits — and parse each scanner's native
output to SARIF. Everything runs offline (vendored pinned semgrep ruleset; gitleaks embedded
rules; vendored offline nuclei templates — no remote template fetch, no OOB callbacks).
Secret/exposure output is redacted at the source so raw secrets never reach logs/SARIF/DB.
`demoscan` remains the zero-infra default (no Docker needed).

**Postgres + migrations** are wired: dev uses zero-infra SQLite; prod uses PostgreSQL via
asyncpg, with the schema owned by Alembic migrations (`make migrate`). Datetime columns are
`TIMESTAMPTZ`. Verified end-to-end against a real Postgres.

**IAST is real for Python.** `POST /iast/sessions` issues a session, a one-time collector
token (only a hash is persisted), and a per-runtime injection snippet. The **`omniscan_iast`
Python agent** then instruments dangerous sinks (`os.system`, `subprocess(shell=True)`,
`eval`/`exec`, `pickle.loads`) inside the running app, correlates each sink hit with the
active request (route/param) to flag tainted source→sink flows, and POSTs redacted events to
the token-authenticated collector, which turns them into IAST findings (dedup by fingerprint).
Other runtimes (JVM/Node/.NET) ship the session lifecycle + injection snippet but need their
own language agents (bytecode/loader instrumentation) — documented, not faked.

**RVD backend** is real too and **fully open source** — no proprietary API, no API key.
The `ollama` backend drives a genuine agentic comprehend→hypothesize→probe loop using a
**local open-source LLM** (Llama / Qwen / DeepSeek / ... via [Ollama](https://ollama.com),
structured-output JSON over plain HTTP) on your authorized code. Quality is bounded by the
local model you run — findings are embargoed, unverified, and confidence-scored for human
triage. With no local model server it degrades gracefully to the heuristic backend.

Honest status — still **not** the complete platform. Not yet built: IAST agents for
non-Python runtimes, arq/Redis workers, MinIO/S3, Vault, webhooks/schedules, and a true
sandboxed-PoC path. `make check` (ruff + mypy --strict + tests) is green.

> **Live-verified vs fixture-verified:** `demoscan`, `semgrep`, `bandit`, `gitleaks`,
> `nuclei`, the Python IAST agent, and Postgres/Alembic are exercised live (real containers /
> real Postgres). `trivy` runs live where its advisory DB is reachable (skips on disk/network
> limits). `codeql`, `zap`, and `clair` are contract-tested against fixtures — their stacks are
> huge/multi-service, so the live run isn't executed in the test suite. Each ships a vendored
> Dockerfile / compose (`deploy/scanners/<tool>/`) to run for real.

## Quickstart

```bash
make setup     # one command: Python deps + dashboard + pinned scanner images
make run       # API (:8000, docs at /docs) + dashboard (:5173)
```

See **[`RUNNING.md`](./RUNNING.md)** for the full install & usage guide (CLI, dashboard,
real scanners, RVD backends, config, troubleshooting).

<details><summary>Manual / piecemeal</summary>

```bash
uv sync --extra dev                 # install
uv run uvicorn api.main:app         # run the API (http://127.0.0.1:8000/docs)

# in another shell — drive it with the CLI (thin client)
export OMNISCAN_TOKEN=dev-admin-token

# create a project + register the repo as an owned target
curl -s -X POST localhost:8000/api/v1/projects \
  -H "Authorization: Bearer dev-admin-token" -H "Content-Type: application/json" \
  -d '{"name":"demo","slug":"demo"}'

# scan this repo with the built-in SAST adapter
uv run omniscan scan sast --project <proj_id> --repo . --tools demoscan --wait

# real containerized scanners (need Docker)
uv run omniscan scan sast --project <proj_id> --repo . --tools semgrep,gitleaks --wait

# flagship RVD pass (heuristic fallback; run Ollama + `--backend ollama` for the real open-source engine)
uv run omniscan scan rvd --project <proj_id> --repo . --focus isolation,deserialization --wait
```

</details>

The dashboard proxies `/api` to the API on :8000. Sign in with any email and a role
(viewer/scanner/triager/admin) — dev issues a token via `POST /auth/token`. The UI is a
pure thin client: every action is a REST call, no scan/triage logic lives in the frontend.
Its **Residual Risk ✦** view tiers RVD findings known-known → known-unknown →
unknown-unknown — the flagship surface for compositional flaws signature scanners miss.

## Tests

```bash
uv run pytest -q          # unit + integration + adapter contract tests
```

## Safety

OmniScan is for **authorized** security testing only. `scope_guard` runs first on
every scan and there is no bypass; secrets flow only through the secrets manager and
are redacted everywhere else; scanners run isolated; findings are immutable (triage
is additive); RVD findings are embargoed by default and PoC artifacts are encrypted
and admin-gated. See [`AGENT.md`](./AGENT.md) §2.
