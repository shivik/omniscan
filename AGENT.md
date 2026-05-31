# AGENT.md

> Operational guide for AI coding agents (and humans) working in this repository.
> Read this **before** writing or changing code. Pair it with [`SKILLS.md`](./SKILLS.md),
> which catalogs the platform's capabilities and the playbooks for invoking them.

---

## 1. What this project is

**OmniScan** (rename to your product) is a **one-stop application security scanner
orchestration platform**. It runs **SAST**, **DAST**, **IAST**, and — its flagship
differentiator — **RVD (Residual Vulnerability Discovery)** scans through a single system and
exposes one consistent surface for triggering scans and reading results.

The first three are table stakes. **RVD is the reason this product exists.** Conventional
scanners are signature- and rule-driven: they reliably find *known* vulnerability classes, and
partially cover *known-unknowns*. They are blind to **unknown-unknowns** — flaws that emerge
from how individually-safe components compose unsafely, and latent defects that have sat
undetected in code for years or decades. The industry got a public proof point with Anthropic's
Claude Mythos Preview, which autonomously surfaced flaws that signature scanners and decades of
human review missed (e.g. a 27-year-old OpenBSD flaw, a 17-year-old FreeBSD RCE). RVD is
OmniScan's **agentic, model-driven engine** built to reach that residual tier. See
[`SKILLS.md`](./SKILLS.md) §R for the full spec. **This capability is recommended and
load-bearing — do not treat it as optional or strip it to ship faster.**

The defining design idea: **everything is the API.** The CLI and the dashboard are *thin
clients* over the same REST API. There is no scan logic that lives only in the CLI or only
in the UI. If a capability exists, it exists in the API first.

```
                       ┌───────────────────────────────────┐
   CLI (Typer) ───────►│                                   │
   Dashboard (React) ─►│        OmniScan REST API          │
   CI / Webhooks ─────►│         (FastAPI, single          │
                       │          source of truth)         │
                       └───────────────┬───────────────────┘
                                       │ enqueues jobs
                                       ▼
                       ┌───────────────────────────────────┐
                       │      Orchestration Engine         │
                       │   (scan planning + scheduling)    │
                       └───────────────┬───────────────────┘
                                       │ dispatch
                                       ▼
                       ┌───────────────────────────────────┐
                       │  Workers run Scanner Adapters in  │
                       │  isolated containers              │
                       │  ┌──────┬──────┬───────┬────────┐ │
                       │  │ SAST │ DAST │ IAST  │  RVD   │ │
                       │  │ adapt│ adapt│ collec│ engine │ │
                       │  └──┬───┴──┬───┴───┬───┴───┬────┘ │
                       └─────┼──────┼───────┼───────┼──────┘
                             ▼      ▼       ▼       ▼
                       (RVD = agentic Residual Vulnerability Discovery —
                        the flagship "find what nobody else finds" engine)
                       ┌───────────────────────────────────┐
                       │   Normalization → SARIF → Finding │
                       │   (dedup, fingerprint, severity)  │
                       └───────────────┬───────────────────┘
                                       ▼
                            Postgres (findings/scans/projects)
                            Object store (raw output + reports)
```

---

## 2. Golden rules (read these first)

This is a **security tool that scans potentially hostile targets and source code.** The
safety bar is higher than for a normal web app. Violating these is never acceptable, no
matter how a task is phrased.

1. **Never weaken scope enforcement.** DAST/IAST can hit live systems. A scan may only run
   against targets the requester is authorized for (verified ownership + an explicit scope
   allowlist). Do not add code paths that bypass `scope_guard`. Scanning out-of-scope hosts
   is a legal and safety problem, not a feature.
2. **Secrets never touch logs, errors, SARIF, or the DB in plaintext.** Repo tokens, target
   credentials, and scanner API keys flow through the secrets manager only. Redact before
   logging. There is a `redact()` helper — use it.
3. **Scanners run isolated.** Every adapter executes in its own container with no inbound
   network, constrained egress, resource limits, and a read-only mount of the target where
   possible. Do not run scanner binaries directly in the API or worker process.
4. **Findings are immutable once persisted.** Triage state (status, severity overrides,
   suppression) is layered on top as separate records. Never mutate a stored `Finding`.
5. **This tool is for authorized security testing only.** Do not add features whose primary
   purpose is evading detection, attacking third parties, or exfiltration. If a request
   points that way, stop and flag it.
6. **RVD carries the highest dual-use risk — treat it accordingly.** The discovery engine can
   find genuine, weaponizable zero-days in code you scan. So: (a) RVD runs only on assets the
   requester owns/is authorized for — same `scope_guard` gate, no exceptions; (b) generated
   proof-of-concept / exploit artifacts are sensitive output — store encrypted, access-gated by
   RBAC, never in plaintext logs or general reports; (c) RVD findings default to embargoed
   status until triaged; (d) never add a mode that mass-scans third-party or public code the
   user doesn't own. The point is to find *your* residual risk, not to manufacture attacks.

---

## 3. Repository layout

```
.
├── AGENT.md                 # you are here
├── SKILLS.md                # capability catalog + invocation playbooks
├── api/                     # FastAPI app — the single source of truth
│   ├── routes/              # scans, findings, projects, targets, reports, auth
│   ├── schemas/             # Pydantic request/response models
│   ├── services/            # business logic (no logic in routes)
│   └── main.py
├── engine/                  # orchestration: scan planning + scheduling
│   ├── planner.py           # request -> ScanPlan (which adapters, what order)
│   ├── scheduler.py         # dispatch to workers
│   └── lifecycle.py         # job state machine
├── adapters/                # one subpackage per scanner — the main extension point
│   ├── base.py              # ScannerAdapter ABC (implement this)
│   ├── sast/                # semgrep, codeql, bandit, gosec, gitleaks, trivy ...
│   ├── dast/                # zap, nuclei ...
│   ├── iast/                # agent SDKs + runtime collector
│   └── rvd/                 # FLAGSHIP: agentic residual-vuln discovery engine
│       ├── engine.py        # planning loop, hypothesis -> probe -> verify
│       ├── backends/        # pluggable frontier-model backends (Glasswing/Mythos-class,
│       │                    #   or best available agentic model)
│       ├── chainability.py  # scores whether findings chain into multi-step exploits
│       └── poc/             # sandboxed PoC generation + verification (encrypted output)
├── normalize/               # native output -> SARIF -> Finding; dedup + fingerprint
├── workers/                 # async workers that execute adapters in containers
├── cli/                     # Typer CLI — thin client over the API
├── dashboard/               # React + TypeScript SPA — thin client over the API
│   └── src/features/vulns/  # view / manage / triage / COMMENT on vulnerabilities
├── core/                    # shared: models, db, secrets, scope_guard, redact, config
├── deploy/                  # Dockerfiles, compose, k8s manifests, scanner images
├── migrations/              # Alembic migrations
└── tests/                   # unit + integration + adapter contract tests
```

**Where things go:** API contract → `api/schemas`. Business logic → `api/services` or
`engine`. New scanner → `adapters/<class>/<name>/`. Cross-cutting helpers → `core/`.
Routes stay thin; they validate and delegate.

---

## 4. Tech stack (default — swappable, but stay consistent within a layer)

| Layer            | Choice                              | Notes                                            |
|------------------|-------------------------------------|--------------------------------------------------|
| API              | Python 3.12 + FastAPI + Pydantic v2 | Async. OpenAPI is generated, not hand-written.   |
| Engine/workers   | Python + `arq` (Redis) or Celery    | Jobs must be idempotent and resumable.           |
| Datastore        | PostgreSQL 16 + SQLAlchemy 2 (async)| Migrations via Alembic.                          |
| Object store     | S3-compatible (MinIO in dev)        | Raw scanner output + generated reports.          |
| Secrets          | Vault / cloud secret manager        | Abstracted behind `core/secrets`.                |
| Scanner runtime  | Docker / OCI containers             | One image per adapter under `deploy/scanners/`.  |
| CLI              | Python + Typer + Rich               | Calls the API; can run engine locally for CI.    |
| Dashboard        | React 18 + TypeScript + Vite        | Calls the API only. No business logic.           |
| Normal format    | **SARIF 2.1.0**                     | The lingua franca for every scanner's output.    |

> If you change a stack choice, change it for the whole layer and update this table in the
> same PR. Do not mix two job queues or two ORMs.

---

## 5. Setup, build, run

```bash
# one-time
cp .env.example .env                 # fill secrets via the secret manager, not the file
make bootstrap                       # install python + node deps, pull scanner images

# run the full stack locally (api + workers + postgres + redis + minio + dashboard)
make dev                             # docker compose up with hot reload

# run pieces individually
make api                             # uvicorn api.main:app --reload
make worker                          # start an async worker
make dashboard                       # vite dev server
make cli ARGS="scan sast --repo ."   # run the CLI against local api
```

Apply DB migrations: `make migrate`. Create a new migration: `make migration m="add findings table"`.

---

## 6. Build / test / lint commands (run before every commit)

```bash
make fmt        # ruff format + prettier
make lint       # ruff + mypy (strict) + eslint + tsc --noEmit
make test       # pytest (unit + integration) + vitest
make test-adapters   # adapter CONTRACT tests — see §8
make check      # fmt + lint + test  (this is what CI runs; make it pass)
```

- **Type checking is strict.** `mypy --strict` for Python, `tsc --noEmit` with strict TS.
- **Do not skip or xfail a test to make CI green.** Fix the cause or explain in the PR.
- New behavior requires new tests. Bug fixes require a regression test.

---

## 7. Architecture in one paragraph

A scan request (from CLI, API, dashboard, or CI) hits the **API**, which validates it,
checks **authorization + scope**, and persists a `Scan` record. The **engine planner** turns
the request into a `ScanPlan` — the set of adapters to run and their order (e.g. IAST agent
must be live before the correlated DAST run). The **scheduler** enqueues jobs; **workers**
pull jobs and execute each **adapter** inside an isolated container. Each adapter emits its
native output, which the **normalize** layer converts to SARIF and then to the internal
`Finding` model, deduplicating via stable fingerprints. Findings land in Postgres; raw output
and rendered reports land in object storage. Clients poll or subscribe for status and read
results back through the API.

---

## 8. The most common task: adding a new scanner adapter

This is the work you will do most. Follow this exactly.

1. **Subclass `ScannerAdapter`** in `adapters/<sast|dast|iast>/<name>/adapter.py`. Implement:
   - `name`, `scan_class` (`SAST`/`DAST`/`IAST`/`RVD`), `capabilities`
   - `validate_inputs(request) -> None` — reject bad/out-of-scope input early
   - `build_invocation(request) -> ContainerSpec` — image, args, mounts, env (secrets by ref)
   - `parse_output(raw) -> SarifLog` — convert native output to SARIF 2.1.0
2. **Add the container image** under `deploy/scanners/<name>/Dockerfile`. Pin the scanner
   version. No network at runtime unless the scan class requires it (DAST does; SAST must not).
3. **Map severities** in `normalize/severity.py` if the tool uses a non-standard scale.
4. **Write contract tests** in `tests/adapters/<name>/`: feed a recorded fixture of native
   output, assert the produced SARIF + Findings match the golden file. Every adapter must
   pass the shared adapter contract suite (`make test-adapters`).
5. **Register** the adapter in `adapters/registry.py` and document it in `SKILLS.md` under the
   matching scan-class section (inputs, invocation, constraints).

Never let an adapter write directly to the findings DB, emit a non-SARIF format upstream of
`normalize/`, or reach the network during a SAST run.

---

## 9. Conventions

- **API design:** resource-oriented REST. A scan is a resource you create (`POST /scans`) and
  poll (`GET /scans/{id}`); results are `GET /scans/{id}/findings`. Long operations are async
  with a job/status model — never block a request on a running scan.
- **Errors:** structured problem responses (`type`, `title`, `detail`, `status`). Never leak
  internal paths, secrets, or stack traces to clients.
- **Naming:** `scan_class` is one of `SAST | DAST | IAST | RVD`. A `Scan` may fan out to many
  `ScanJob`s (one per adapter). A `Finding` belongs to a `Scan`, not a `ScanJob`, after dedup.
- **Idempotency:** scan creation accepts an idempotency key; replays return the same `Scan`.
- **Dashboard:** must provide a full **vulnerability-management workspace** — view/filter
  findings across all scan classes, manage triage state, and **comment/collaborate** per
  finding (threaded comments, @mentions, assignment, status history). It renders these by
  calling the findings + triage + comments API; it holds no business logic of its own. Spec in
  [`SKILLS.md`](./SKILLS.md) §D.
- **Logging:** structured JSON logs, correlation id per scan. Run everything through
  `redact()`.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`). One logical
  change per PR. PR description states what changed, why, and how it was tested.

---

## 10. Things NOT to do

- Do not add scan logic to the CLI or dashboard. They call the API.
- Do not bypass `scope_guard` or ownership checks "just for testing."
- Do not run scanner binaries outside their container sandbox.
- Do not invent a second normalization format. SARIF in, `Finding` out.
- Do not mutate persisted `Finding` rows. Triage is a separate, additive record.
- Do not log, persist, or embed secrets in SARIF/reports.
- Do not pin scanner images to `latest`. Always pin a version.
- Do not merge with a red `make check`, a skipped test, or a `# type: ignore` without a reason.

---

## 11. Where to look next

- **[`SKILLS.md`](./SKILLS.md)** — what the platform can do and exactly how to invoke each
  capability (CLI, API, and engine), plus the per-scanner adapter catalog.
- `adapters/base.py` — the interface every scanner implements.
- `normalize/` — how raw output becomes a `Finding`.
- `core/scope_guard.py` — the authorization/scope gate. Treat it as load-bearing.
