# Running OmniScan

A practical guide to installing and running the platform locally — backend API,
Typer CLI, React dashboard, the real containerized scanners, and the agentic RVD
engine.

---

## TL;DR — one command

```bash
make setup     # installs everything (Python + dashboard + scanner images)
make run       # starts API (:8000) + dashboard (:5173)
```

Then open:
- **Dashboard** → http://127.0.0.1:5173
- **API docs** → http://127.0.0.1:8000/docs

`make setup` is just `./scripts/install.sh`; `make run` is `./scripts/dev.sh`. Both are
idempotent and safe to re-run.

---

## Prerequisites

| Need it for | Tool | Notes |
|---|---|---|
| Backend | Python 3.12+ | `make setup` installs [`uv`](https://docs.astral.sh/uv/) if missing |
| Dashboard | Node 18+ / npm | optional — backend + CLI work without it |
| Real scanners (semgrep, gitleaks) | Docker | optional — the built-in `demoscan` SAST adapter needs no Docker |
| Real RVD model backend | [Ollama](https://ollama.com) + an open model | optional, fully local/open-source, no API key — RVD falls back to a heuristic backend without it |

Nothing else: dev uses SQLite + an in-process worker, so there's **no Postgres, Redis,
or object-store to stand up**.

---

## What `make setup` does

1. Installs `uv` (if needed) and the Python deps (`uv sync --extra dev --extra rvd`).
2. Creates `.env` from `.env.example` (non-sensitive config + secret *references* only).
3. Installs the dashboard deps (`npm install`) if `npm` is present.
4. Pre-pulls the pinned scanner images (`semgrep`, `gitleaks`) if Docker is running.

---

## Running pieces individually

```bash
make api          # backend only (uvicorn, hot reload) — http://127.0.0.1:8000
make dashboard    # UI only (Vite dev server)         — http://127.0.0.1:5173
make cli ARGS="capabilities"   # run the CLI against the local API
```

The dashboard dev server proxies `/api` → the backend on :8000, so run the API too.

---

## First scan in 60 seconds (CLI)

```bash
export OMNISCAN_API=http://127.0.0.1:8000
export OMNISCAN_TOKEN=dev-admin-token        # dev bootstrap admin token

# 1. see what scanners are available
uv run omniscan capabilities

# 2. create a project (grab the proj_… id from the response)
curl -s -X POST $OMNISCAN_API/api/v1/projects \
  -H "Authorization: Bearer $OMNISCAN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"demo","slug":"demo"}'

# 3a. SAST with the built-in adapter (no Docker needed)
uv run omniscan scan sast --project <proj_id> --repo . --tools demoscan --wait

# 3b. SAST with a REAL containerized scanner (needs Docker)
uv run omniscan scan sast --project <proj_id> --repo . --tools semgrep --wait
uv run omniscan scan sast --project <proj_id> --repo . --tools gitleaks --wait

# 3c. SAST on a remote git repo BY URL (engine clones it, scans in a no-network container)
#     A URL has a network host, so you must allowlist it (--scope-allow) or register
#     the repo as an owned target — scope_guard rejects unauthorized hosts.
uv run omniscan scan sast --project <proj_id> \
  --url https://github.com/your-org/your-repo --ref main \
  --scope-allow github.com --tools semgrep,gitleaks,trivy --wait

# 4. read + triage + report
uv run omniscan findings list --scan <scan_id> --min-severity medium
uv run omniscan findings triage <finding_id> --status false_positive --reason "test fixture"
uv run omniscan report <scan_id> --format sarif
```

### Scanning a git repo by URL

The engine clones the repo **host-side** (`git clone --depth 1`, optional `--ref`), then
the adapters scan the checkout in isolated, no-network containers.

- **CLI:** `--url <repo>` (with optional `--ref <branch/tag>` and `--scope-allow <host>`).
- **API:** `source: {"type": "git", "url": "...", "ref": "..."}` plus `scope: {"allow": ["github.com"]}`.
- **Authorization:** a URL introduces a network host, so a **scope allowlist covering that host
  is required** (or register the repo as an owned target). This is the "authorized assets only"
  guardrail — OmniScan will not clone + scan arbitrary third-party repos silently.
- **Private repos:** pass credentials by secret reference (`auth.ref`), never inline. (Authenticated
  clone is not yet wired into the clone step — public repos / host git credentials work today.)
- **Local path** still works too: `--repo /path/to/checkout` (no host, no allowlist needed).

```bash
# example: clone + scan a public repo with three SAST/SCA tools
uv run omniscan scan sast --project <proj_id> \
  --url https://github.com/shivik/k8s-cli-orchestrator --ref main \
  --scope-allow github.com --tools semgrep,gitleaks,trivy --wait
```

---

## Using the dashboard

1. `make run`, open http://127.0.0.1:5173
2. Sign in with any email and a role: **viewer** (read + comment), **scanner** (+ create
   scans), **triager** (+ change state), **admin** (+ PoC access). Dev issues a token via
   `POST /auth/token`.
3. **Security Dashboard** (home) — overview with engine (SAST/DAST/IAST/RVD) + trend-window
   filters, Applications/Projects/Scans KPI cards, a findings-by-severity donut, remediation
   analysis, a findings-over-time trend chart, and Top-10 Applications/Projects risk tables.
4. **Findings** — unified view across all scan classes, filters, search.
5. **Residual Risk ✦** — the flagship RVD view: candidate residual / compositional
   weaknesses tiered known-known → known-unknown → **unknown-unknown**, with reasoning
   traces and chainability. Embargoed + unverified until a human reproduces them.
6. **Inventory** — **Applications** (group projects), **Projects**, **Scans**.
7. **Scans → New scan** — wizard that issues the same `POST /scans` the CLI/CI use.
8. Open any finding for triage, assignment, status history, and threaded comments.
9. **Theme** (bottom of the sidebar): **Auto** follows time of day (light from sunrise→sunset,
   dark at night); **Light** / **Dark** are explicit overrides, remembered per browser.

---

## DAST (running-app scanning)

DAST needs an **authorized** target — register it with `ownership_verified: true` and a
scope allowlist, or scope_guard rejects the scan. Then:

```bash
uv run omniscan scan dast --project <proj_id> \
  --target https://staging.acme.test --scope-allow "*.staging.acme.test" --wait
```

Runs the vendored offline `nuclei` image with egress scoped to the target (no remote
template fetch, no out-of-band callbacks), parses JSONL → SARIF, and redacts output.

## Container-image scanning (Clair)

[Clair](https://github.com/quay/clair) scans built **container images** for vulnerable OS
and language packages. It's a service, so provision it once, then scan image refs:

```bash
docker compose -f deploy/scanners/clair/docker-compose.yml up -d   # Clair + Postgres + feeds
docker build -t omniscan/clairctl:0.1.0 deploy/scanners/clair       # the clairctl client
export OMNISCAN_CLAIR_URL=http://host.docker.internal:6060

curl -X POST localhost:8000/api/v1/scans -H "Authorization: Bearer dev-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"scan_class":"SAST","project_id":"<proj_id>",
       "source":{"type":"image","image":"alpine:3.18"},"tools":["clair"]}'
```

See `deploy/scanners/clair/README.md`. (Heavy multi-service stack — the report→SARIF logic
is contract-tested; the live scan runs via this compose.)

## IAST sessions

```bash
# create a session — returns a one-time collector token + an injection snippet
curl -s -X POST localhost:8000/api/v1/iast/sessions \
  -H "Authorization: Bearer dev-admin-token" -H "Content-Type: application/json" \
  -d '{"project_id":"<proj_id>","runtime":"jvm"}'
# ... inject the snippet into your app start, run traffic, then:
curl -s -X POST localhost:8000/api/v1/iast/sessions/<sess_id>/finalize \
  -H "Authorization: Bearer dev-admin-token"
```

For **Python apps**, attach the real runtime agent — it instruments dangerous sinks and
reports tainted source→sink flows to the collector:

```bash
OMNISCAN_IAST_SESSION=<sess_id> \
OMNISCAN_COLLECTOR_URL=http://127.0.0.1:8000 \
OMNISCAN_IAST_TOKEN=<collector_token> \
  python -m omniscan_iast.bootstrap your_module:app
# or in code:  import omniscan_iast; omniscan_iast.instrument(); app = omniscan_iast.wrap_wsgi(app)
```

> The session lifecycle works for every runtime. The **Python** agent (`omniscan_iast`) is
> fully implemented (sinks: `os.system`, `subprocess(shell=True)`, `eval`/`exec`,
> `pickle.loads`). JVM/Node/.NET agents need their own per-runtime instrumentation and
> are not built.

## PostgreSQL + migrations (prod)

Dev is zero-infra SQLite. For Postgres:

```bash
# point at your database
export OMNISCAN_DATABASE_URL="postgresql+asyncpg://user:pass@host:5432/omniscan"

make migrate                       # alembic upgrade head  (creates/updates the schema)
make migration m="add X"           # autogenerate a new revision after changing models
uv run uvicorn api.main:app        # the app uses the migrated schema (no create_all on PG)
```

A throwaway dev Postgres in Docker:

```bash
docker run -d --rm --name omni-pg -e POSTGRES_PASSWORD=omni -e POSTGRES_DB=omniscan \
  -p 5432:5432 postgres:16-alpine
export OMNISCAN_DATABASE_URL="postgresql+asyncpg://postgres:omni@localhost:5432/omniscan"
make migrate
```

## Production backends (queue / object store / secrets)

These are opt-in and need the `prod` extra (`uv sync --extra prod`). Bring up the
backing services with `make infra` (Postgres + Redis + MinIO + Vault), then:

```bash
# Redis-backed job queue + dedicated workers
export OMNISCAN_JOB_BACKEND=arq OMNISCAN_REDIS_URL=redis://localhost:6379/0
make api        # API enqueues scans to Redis
make worker     # arq worker(s) pull + execute  (run one or more, separate terminals)

# S3/MinIO object store for raw output + reports
export OMNISCAN_OBJECT_STORE_URL=s3://omniscan OMNISCAN_S3_ENDPOINT=http://localhost:9000
export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=minio123 AWS_REGION=us-east-1

# HashiCorp Vault for secret refs (vault://mount/path#key)
export OMNISCAN_SECRETS_BACKEND=vault VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=dev-root
```

See `deploy/docker-compose.prod.yml`. The default dev stack (SQLite + in-process worker
+ file object store + env secrets) needs none of this.

## Webhooks

```bash
# outbound: get HMAC-signed POSTs on scan.completed
curl -X POST localhost:8000/api/v1/webhooks -H "Authorization: Bearer dev-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"direction":"outbound","project_id":"<proj_id>","target_url":"https://ci.example/hook","events":["scan.completed"]}'
# response includes signing_secret ONCE — verify X-OmniScan-Signature: sha256=<hmac> on your receiver.

# inbound: trigger a scan on push (signature-verified, no bearer token)
curl -X POST localhost:8000/api/v1/webhooks -H "Authorization: Bearer dev-admin-token" \
  -H "Content-Type: application/json" -d '{"direction":"inbound","project_id":"<proj_id>"}'
# then your git provider POSTs to /api/v1/webhooks/{id}/inbound with X-OmniScan-Signature.
```

The inbound trigger scans the project's registered git target; outbound delivery is
best-effort and never blocks a scan.

## The flagship RVD engine

RVD (Residual Vulnerability Discovery) reasons over your **authorized** code for
residual/compositional flaws that signature scanners miss.

```bash
# heuristic backend (no model) — conservative structural pass, every hypothesis low-confidence
uv run omniscan scan rvd --project <proj_id> --repo . --focus isolation,deserialization --wait

# real agentic backend — fully open source, local, no API key. Install Ollama, then:
ollama serve &
ollama pull qwen2.5-coder:7b
uv run omniscan scan rvd --project <proj_id> --repo . \
  --focus isolation,deserialization,auth --backend ollama --wait
```

Important and deliberate:
- RVD runs **only on owned/authorized assets** — register the repo/target with
  `ownership_verified: true` first, or scope_guard rejects the scan.
- Findings are **embargoed** and **unverified** by default. The backend proposes
  candidates with self-assessed confidence; a human reproduces before action.
- It does **not** autonomously run exploits or generate PoCs.
- The `ollama` backend is fully open source and runs locally — no proprietary API, no
  API key. Quality is bounded by the local model you run; it makes no guarantee of
  finding novel zero-days.
- Backend selection degrades gracefully: `ollama` → `heuristic` if no local server/model.

Configure with `OMNISCAN_OLLAMA_URL` (default `http://localhost:11434`) and
`OMNISCAN_RVD_MODEL` (default `qwen2.5-coder:7b`).

---

## Tests, lint, types

```bash
make test            # pytest (unit + integration + adapter contract tests)
make test-adapters   # adapter contract tests only
make lint            # ruff + mypy
make fmt             # ruff format
```

Docker-gated integration tests (real semgrep/gitleaks containers) auto-skip when Docker
isn't available, so `make test` is green with or without Docker.

---

## Configuration (`.env`)

All keys are `OMNISCAN_`-prefixed; see `.env.example`. Highlights:

| Key | Default (dev) | Prod |
|---|---|---|
| `OMNISCAN_DATABASE_URL` | `sqlite+aiosqlite:///./omniscan.db` | `postgresql+asyncpg://…` |
| `OMNISCAN_JOB_BACKEND` | `inprocess` | `arq` (Redis) |
| `OMNISCAN_OBJECT_STORE_URL` | `file://./var/objects` | `s3://…` |
| `OMNISCAN_SECRETS_BACKEND` | `env` | `vault` |
| `OMNISCAN_BOOTSTRAP_ADMIN_TOKEN` | `dev-admin-token` | per-user tokens via IdP |
| `OMNISCAN_OLLAMA_URL` | `http://localhost:11434` | your Ollama host |
| `OMNISCAN_RVD_MODEL` | `qwen2.5-coder:7b` | any open model you've pulled |

Secrets (scan target creds, scanner keys) are referenced as `vault://…` and resolved at
runtime by the secrets manager — never stored in `.env`, logs, SARIF, or the DB.

---

## Troubleshooting

- **`docker not available` on a semgrep/gitleaks scan** — start Docker, or use
  `--tools demoscan` (no Docker needed).
- **RVD returns nothing on a small repo** — the heuristic backend is conservative
  (needs multiple interacting markers). Point it at a larger tree, or run Ollama
  (`ollama serve` + `ollama pull qwen2.5-coder:7b`) and use `--backend ollama`.
- **Dashboard can't reach the API** — make sure the API is up on :8000 (the Vite dev
  server proxies `/api` there).
- **Port already in use** — stop a previous `make run`, or change the ports in
  `scripts/dev.sh` / `dashboard/vite.config.ts`.
