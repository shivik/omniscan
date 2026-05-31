# SKILLS.md

> The capability catalog for **OmniScan**. Each "skill" is a discrete thing the platform can
> do, with its inputs, outputs, and exactly how to invoke it from the **CLI**, the **API**, and
> (where relevant) the **engine** directly. Read [`AGENT.md`](./AGENT.md) first for the
> architecture and the safety rules every skill inherits.

Every skill obeys the golden rules in `AGENT.md`: scope is enforced before anything runs,
secrets stay in the secrets manager, scanners run isolated, and all output normalizes to
**SARIF → `Finding`**. The CLI and dashboard never do scan work themselves — they call the API.

---

## How to read this file

Each skill follows the same shape:

- **Class** — `SAST` / `DAST` / `IAST` / `ORCHESTRATION` / `CROSS-CUTTING`
- **Purpose** — what it does in one line
- **Inputs** — what you must provide
- **Outputs** — what you get back
- **Invoke** — concrete CLI command and API call
- **Constraints** — guardrails and gotchas

---

## 0. The three invocation surfaces (all equivalent)

Any scan-capable skill can be triggered three ways. They converge on the same API.

```bash
# 1) CLI (thin client; great for local dev + CI)
omniscan scan sast --repo . --tools semgrep,bandit --wait

# 2) API (the source of truth; dashboard and CI use this too)
curl -X POST https://omniscan.local/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
        "scan_class": "SAST",
        "project_id": "proj_123",
        "source": {"type": "git", "url": "git@github.com:acme/app.git", "ref": "main"},
        "tools": ["semgrep", "bandit"]
      }'

# 3) Dashboard — "New Scan" wizard, which issues the same POST /scans under the hood.
```

A scan is **created** then **polled**:

```bash
omniscan scan status scan_abc            # CLI
GET /api/v1/scans/{scan_id}              # API  -> {status, progress, jobs[]}
GET /api/v1/scans/{scan_id}/findings     # API  -> normalized findings (filterable)
```

---

## 1. Orchestration skills

### 1.1 Plan a scan
- **Class:** ORCHESTRATION
- **Purpose:** Turn a scan request into a `ScanPlan` — which adapters run, in what order, with
  what dependencies (e.g. IAST agent live *before* the correlated DAST run).
- **Inputs:** `scan_class`, target/source, requested tools (optional — defaults per class).
- **Outputs:** `ScanPlan` with ordered `ScanJob`s and dependency edges.
- **Invoke:** `omniscan scan plan --dry-run ...` (prints the plan without running);
  `POST /scans?dry_run=true`.
- **Constraints:** Planning runs `scope_guard` first. An unauthorized target fails here, before
  any job is enqueued.

### 1.2 Run a scan (fan-out + lifecycle)
- **Class:** ORCHESTRATION
- **Purpose:** Execute a `ScanPlan`: enqueue jobs, run adapters in isolated containers, track the
  state machine (`queued → running → normalizing → completed | failed | cancelled`).
- **Inputs:** a created `Scan`.
- **Outputs:** per-job status, aggregated scan status, findings on completion.
- **Invoke:** `omniscan scan run scan_abc` / created automatically on `POST /scans`.
  Cancel: `omniscan scan cancel scan_abc` / `POST /scans/{id}/cancel`.
- **Constraints:** Jobs are idempotent and resumable; a worker crash re-runs the job, never
  duplicates findings (dedup handles re-emission).

### 1.3 Normalize to SARIF + Finding
- **Class:** ORCHESTRATION
- **Purpose:** Convert each adapter's native output to SARIF 2.1.0, then to internal `Finding`s.
- **Inputs:** raw adapter output (per job).
- **Outputs:** SARIF logs (archived) + persisted `Finding`s.
- **Invoke:** automatic post-job; manually re-run with `omniscan normalize --job job_xyz`.
- **Constraints:** SARIF is the only accepted intermediate format. Severity mapping lives in
  `normalize/severity.py`.

### 1.4 Deduplicate & fingerprint
- **Class:** ORCHESTRATION
- **Purpose:** Collapse the same issue reported by multiple tools / multiple runs into one
  `Finding` with a stable fingerprint (rule + location + symbol/route).
- **Inputs:** normalized findings.
- **Outputs:** deduped `Finding`s with `sources[]` listing which tools found it.
- **Constraints:** Fingerprints must be stable across re-scans so triage state carries over.

### 1.5 Triage
- **Class:** ORCHESTRATION
- **Purpose:** Set status (`open`/`confirmed`/`false_positive`/`accepted_risk`/`fixed`),
  override severity, suppress, assign.
- **Invoke:** `omniscan findings triage find_123 --status false_positive --reason "test fixture"`;
  `PATCH /findings/{id}/triage`.
- **Constraints:** Triage is an **additive** record layered on the immutable `Finding`.

### 1.6 Report
- **Class:** ORCHESTRATION
- **Purpose:** Render results: SARIF (machine), HTML/PDF (human), JSON, JUnit/SARIF for CI gates.
- **Invoke:** `omniscan report scan_abc --format html,sarif`;
  `GET /scans/{id}/report?format=sarif`.
- **Constraints:** Reports never contain secrets. CI gate format returns a pass/fail by policy
  (e.g. fail on new `high+`).

---

## 2. SAST skills (source / repository analysis)

**Shared contract.** Inputs: `source` (git url+ref or path), optional `tools`, `paths`,
`ruleset`. Output: SARIF → `Finding`s located by file/line/symbol. **Runs with no network**
(except an explicitly allowed package index for SCA resolution). Operates on a read-only
checkout.

| Skill (adapter) | Purpose | Notable inputs | Notes |
|-----------------|---------|----------------|-------|
| `semgrep`  | Multi-language pattern/dataflow SAST | `ruleset`, custom rules | Good default for breadth. |
| `codeql`   | Deep dataflow/taint analysis | language pack, `build_cmd` | Heavier; needs a build for compiled langs. |
| `bandit`   | Python security linter | `confidence`, `severity` | Python-only. |
| `gosec`    | Go security linter | — | Go-only. |
| `gitleaks` | Secret detection in code + history | `--full-history` | Secrets are findings; never echo the secret value. |
| `trivy` / `grype` | SCA — vulnerable dependencies | lockfiles, manifests | May fetch advisory DBs (allowed egress). |

**Invoke (example):**
```bash
omniscan scan sast --repo . --tools semgrep,gitleaks,trivy --wait --fail-on high
```
```http
POST /api/v1/scans
{ "scan_class": "SAST", "project_id": "...", "source": {...}, "tools": ["semgrep","gitleaks","trivy"] }
```
**Constraints:** Secret-scanner output is doubly sensitive — store a redacted fingerprint, never
the raw secret. SCA is the only SAST skill permitted limited egress (advisory feeds).

---

## 3. DAST skills (running-application analysis)

**Shared contract.** Inputs: `target` (base URL), `auth` (by secret reference), `scope`
(in/out allowlist), `crawl` options, `rate_limit`. Output: SARIF → `Finding`s located by
URL/route/parameter. **Requires network egress to the target only.**

| Skill (adapter) | Purpose | Notable inputs | Notes |
|-----------------|---------|----------------|-------|
| `zap`    | Full active+passive web scan, spidering, auth flows | `auth`, `context`, `attack_strength` | Workhorse for web apps. |
| `nuclei` | Template-based vuln/misconfig checks | `templates`, `severity` | Fast, signature-style; pairs well with ZAP. |

**Invoke (example):**
```bash
omniscan scan dast \
  --target https://staging.acme.test \
  --auth-ref vault://omniscan/acme/staging-login \
  --scope-allow "*.staging.acme.test" \
  --rate-limit 20rps --tools zap,nuclei --wait
```
```http
POST /api/v1/scans
{ "scan_class": "DAST",
  "target": {"base_url": "https://staging.acme.test"},
  "auth": {"ref": "vault://omniscan/acme/staging-login"},
  "scope": {"allow": ["*.staging.acme.test"], "deny": ["*"]},
  "rate_limit": "20rps", "tools": ["zap","nuclei"] }
```
**Constraints (critical):**
- `scope_guard` must verify target ownership **and** match every request against the allowlist.
  No allowlist → no scan.
- Respect `rate_limit` and any maintenance windows; active scanning can degrade live systems.
- Credentials come only by `ref`; never inline, never logged.

---

## 4. IAST skills (instrumented runtime analysis)

IAST observes the application **from the inside** while it runs (typically during functional
tests or a correlated DAST run), reporting tainted source→sink flows with request context.

### 4.1 Instrument the application (agent)
- **Class:** IAST
- **Purpose:** Attach a language agent that instruments the running app and streams runtime
  security telemetry to the collector.
- **Inputs:** runtime/language, agent config, `session_id`, collector endpoint + token (by ref).
- **Invoke:** the agent is injected at app start (e.g. JVM `-javaagent`, Python/Node hook). The
  platform issues a session and credentials:
  ```bash
  omniscan iast session create --project proj_123 --runtime jvm
  # -> prints SESSION_ID + injection snippet using a short-lived collector token
  ```
- **Constraints:** Agent only streams; it never opens an inbound port. Telemetry is scoped to
  one session and expires.

### 4.2 Correlate with traffic (IAST + DAST)
- **Class:** IAST
- **Purpose:** Run a DAST scan (or your functional test suite) against the instrumented app and
  correlate each finding's runtime sink with the triggering request.
- **Inputs:** an active IAST `session_id` + a DAST scan (or external test traffic header).
- **Invoke:**
  ```bash
  omniscan scan iast --session sess_456 --drive dast \
    --target https://staging.acme.test --scope-allow "*.staging.acme.test" --wait
  ```
  ```http
  POST /api/v1/scans
  { "scan_class": "IAST", "iast_session": "sess_456",
    "drive": {"mode": "dast", "target": {...}, "scope": {...}} }
  ```
- **Outputs:** SARIF → `Finding`s enriched with runtime flow + the request that exercised it
  (high signal, low false positives).
- **Constraints:** The planner guarantees the agent session is live **before** the driving
  traffic starts (see `AGENT.md` §7). Drive traffic still passes `scope_guard`.

### 4.3 Collect & finalize a session
- **Class:** IAST
- **Purpose:** Flush the collector, finalize findings, and tear down the session.
- **Invoke:** `omniscan iast session finalize sess_456`; `POST /iast/sessions/{id}/finalize`.

---

## R. Residual Vulnerability Discovery — the flagship skill *(recommended, not optional)*

> This is the capability that separates OmniScan from every signature-based scanner on the
> market. **Do not ship without it, and do not strip it down to "just run another linter."**
> If you must cut scope elsewhere, keep RVD.

### R.0 The problem RVD exists to solve

Every conventional scanner (SAST/DAST/IAST included) is fundamentally **pattern-driven**: it
matches code or traffic against a catalog of *known* vulnerability classes. Organize residual
risk into three tiers:

- **Known-knowns** — classes your stack reliably detects (SQLi, XSS, known-CVE deps). SAST/DAST
  handle these.
- **Known-unknowns** — classes you know exist but tools only partially cover (stateful logic
  flaws, auth-boundary confusion). IAST + careful SAST help, imperfectly.
- **Unknown-unknowns** — vulnerabilities that emerge from **composition**: how individually-safe
  components interact unsafely, multi-step chains, and latent defects that have sat undetected
  in production for **years or decades**. *No signature scanner finds these,* because there is
  no signature to match.

RVD targets the third tier. The public proof that this tier is real and reachable was
Anthropic's **Claude Mythos Preview**, which autonomously found flaws that survived decades of
human and automated review — a ~27-year-old OpenBSD remote-crash flaw, a 17-year-old FreeBSD
RCE, a 16-year-old FFmpeg bug — none of which appeared on any CVE list or tripped any scanner.
RVD is OmniScan's engine for that class of discovery on **your own authorized assets.**

### R.1 How RVD works (it is an agent, not a ruleset)

RVD is an **agentic reasoning loop** over your code and/or running system, not a pattern bank:

1. **Comprehend** — build a semantic model of the target: data flows, trust boundaries,
   component interactions, state machines, auth surfaces. (Goes beyond AST matching.)
2. **Hypothesize** — propose candidate residual weaknesses, especially *compositional* ones:
   "component A trusts B's normalization, but B's invariant breaks under input C."
3. **Probe & verify** — in an isolated sandbox, attempt to confirm the hypothesis (and, where
   authorized, generate a minimal proof-of-concept). Unverified hypotheses are reported at low
   confidence; verified ones at high confidence with reproduction.
4. **Score chainability** — a **first-class scoring dimension**: can this finding be chained
   with others into a multi-step exploit? Single-point scanners ignore this; RVD treats a
   chainable medium as potentially more dangerous than an isolated high.
5. **Normalize** — emit SARIF → `Finding`, enriched with the reasoning trace, the composition
   path, chainability graph edges, and (if generated) an encrypted PoC reference.

- **Class:** RVD
- **Inputs:** target (`source` repo+ref and/or a running `target`/IAST session for runtime
  reasoning), `depth`/`budget` (compute/time cap — RVD is expensive), `focus` (optional:
  auth, memory-safety, deserialization, isolation boundaries...), `backend` (model backend).
- **Outputs:** high-signal `Finding`s for residual/compositional flaws, each with a reasoning
  trace, chainability score + graph, and an optional sandboxed PoC (encrypted, RBAC-gated).
- **Constraints (read these):**
  - **Authorization is absolute.** RVD runs only on assets the requester owns/is authorized
    for. Same `scope_guard` gate as DAST. No public-/third-party mass-scan mode.
  - **PoCs are sensitive.** Generated exploit artifacts are encrypted at rest, gated by RBAC,
    never in plaintext logs or general reports. RVD findings default to **embargoed** status.
  - **It is compute-heavy and probabilistic.** Always run under a `budget`; expect cost.
    Treat it as continuous/background discovery, not a blocking CI gate.
  - **Verify before alarm.** Unverified hypotheses are clearly flagged low-confidence so the
    triage queue is not flooded with speculation.

### R.2 The model backend (pluggable — this is the key integration decision)

RVD's reasoning is delegated to a **pluggable frontier-model backend** behind
`adapters/rvd/backends/`. Implement the `RVDBackend` interface so the engine is
model-agnostic:

- **Glasswing / Mythos-class backend** — *if* your org has access to a Mythos-class model
  through Anthropic's Project Glasswing (access is restricted and not publicly available),
  wire it here. This is the highest-capability backend.
- **Best-available agentic backend** — otherwise, use the strongest agentic frontier model you
  can access (the current top Claude model, etc.) driving the comprehend→hypothesize→verify
  loop. Lower ceiling than Mythos-class, still well beyond signature scanners.
- The engine, chainability scoring, sandboxing, and normalization are **identical regardless of
  backend** — only capability/cost change. Design for graceful degradation.

### R.3 Invoke

```bash
# RVD over a repo, capped budget, focused on isolation/composition flaws
omniscan scan rvd --repo . --depth deep --budget 8h \
  --focus isolation,deserialization --backend glasswing --wait

# RVD over a running, instrumented system (reasons about runtime state too)
omniscan scan rvd --target https://staging.acme.test \
  --iast-session sess_456 --scope-allow "*.staging.acme.test" --budget 4h
```
```http
POST /api/v1/scans
{ "scan_class": "RVD",
  "project_id": "proj_123",
  "source": {"type": "git", "url": "...", "ref": "main"},
  "rvd": {"depth": "deep", "budget": "8h", "focus": ["isolation","deserialization"],
          "backend": "glasswing", "generate_poc": true} }
```
Read results like any other scan: `GET /scans/{id}/findings` (filter `scan_class=RVD`),
with the reasoning trace and chainability graph under each finding.

---


## 5. Cross-cutting skills

| Skill | Class | Purpose | Invoke |
|-------|-------|---------|--------|
| Scope guard | CROSS-CUTTING | Verify ownership + enforce target/source allowlist before any run | internal, runs first on every scan; `omniscan scope check --target ...` to preview |
| Secrets resolution | CROSS-CUTTING | Resolve `ref://` credentials at runtime, inject into the adapter container, redact everywhere else | automatic; never exposed via API |
| Projects & targets | CROSS-CUTTING | Register apps/repos/targets and their authorized scope | `omniscan project create`; `POST /projects`, `POST /targets` |
| AuthN/AuthZ + RBAC | CROSS-CUTTING | Token-based auth; roles (viewer/scanner/triager/admin); per-project isolation | `POST /auth/token`; bearer on every call |
| Policy / CI gate | CROSS-CUTTING | Pass/fail a build by rule (e.g. fail on new high+) | `omniscan gate scan_abc --policy default`; `GET /scans/{id}/gate` |
| Webhooks / schedules | CROSS-CUTTING | Trigger scans on push/PR/cron; notify on completion | `POST /webhooks`, `POST /schedules` |
| Audit log | CROSS-CUTTING | Immutable record of who triggered/triaged what | `GET /audit` |

---

## D. Dashboard — vulnerability-management workspace

The dashboard is a thin client (it holds no scan logic), but it is the primary human surface
for **managing, viewing, and collaborating on** vulnerabilities across every scan class
(SAST/DAST/IAST/RVD). Every capability below is backed by an API endpoint — the UI only
renders and calls.

### D.1 View
- **Unified findings view** across all scan classes and projects, with filters (severity,
  scan_class, status, project, tool/source, first-seen, chainable-only) and full-text search.
  Backed by `GET /findings?...`.
- **Finding detail** — location (file/line/symbol for SAST/RVD, URL/route/param for DAST,
  runtime flow for IAST), evidence, normalized SARIF, severity + CVSS-style score, and for RVD:
  the **reasoning trace, composition path, and chainability graph**. PoC artifacts shown only
  to RBAC-authorized roles, fetched from the encrypted store on demand.
- **Trend & posture dashboards** — open vs. fixed over time, residual-risk by tier
  (known-known / known-unknown / unknown-unknown), MTTR, scan history per project.

### D.2 Manage
- **Triage from the UI** — set status (`open` / `confirmed` / `false_positive` /
  `accepted_risk` / `fixed`), override severity (with reason), suppress, and bulk-action across
  selected findings. Calls `PATCH /findings/{id}/triage` (and a bulk variant). Remember:
  findings are immutable; triage is an additive layered record (see `AGENT.md` §2).
- **Assignment & ownership** — assign a finding to a user/team; track status history. Backed by
  `PATCH /findings/{id}/assignee` and surfaced from the audit log.
- **Status history timeline** — who changed what, when, and why — read from the immutable
  audit trail (`GET /findings/{id}/history`).

### D.3 Comment / collaborate
- **Threaded comments per finding** — `GET/POST /findings/{id}/comments`. Supports Markdown,
  **@mentions** (notify via the webhooks/notifications channel), and edit/delete by the author
  (edits keep an immutable revision history; the audit log records all of it).
- **Reactions / acknowledgements** — lightweight signals so a triager can mark "looked at" or
  agree with another reviewer.
- **Activity feed** — comments, status changes, and assignments interleaved per finding and
  per project, so a reviewer sees the full collaboration context in one place.
- **Permissions** — comment/triage actions are gated by RBAC (`viewer` can read + comment;
  `triager` can change state; `admin` can manage suppression policy and PoC access). Embargoed
  RVD findings and PoC artifacts respect the same role gates.

> Implementation note: all of the above lives under `dashboard/src/features/vulns/` and calls
> only the findings / triage / comments / audit endpoints. If a behavior the UI needs doesn't
> exist in the API yet, add it to the **API first** (see `AGENT.md` §1, "everything is the
> API"), then consume it.

---

## 6. How to add a new skill (scanner)

Adding a scanner = adding a skill. The full procedure lives in **[`AGENT.md`](./AGENT.md) §8**.
In short:

1. Subclass `ScannerAdapter` (`adapters/<class>/<name>/adapter.py`) implementing
   `validate_inputs`, `build_invocation`, `parse_output -> SARIF`.
2. Add a pinned container image under `deploy/scanners/<name>/`.
3. Map severities in `normalize/severity.py`.
4. Write contract tests against a recorded fixture (`make test-adapters`).
5. Register in `adapters/registry.py` **and document the skill here** under its scan class
   (inputs, invoke, constraints) so the CLI/API/dashboard expose it consistently.

A skill is not "done" until it appears in all three surfaces (CLI flag/subcommand, API
`tools` enum, dashboard option) — because they are all the same API.

---

## 7. Quick reference

```bash
# SAST on a repo, fail CI on new highs
omniscan scan sast --repo . --tools semgrep,bandit,gitleaks --fail-on high --wait

# DAST against an authorized staging target
omniscan scan dast --target https://staging.acme.test \
  --auth-ref vault://omniscan/acme/login --scope-allow "*.staging.acme.test" --wait

# IAST: instrument, then drive with DAST
omniscan iast session create --project proj_123 --runtime jvm
omniscan scan iast --session sess_456 --drive dast \
  --target https://staging.acme.test --scope-allow "*.staging.acme.test" --wait

# RVD (flagship): agentic discovery of residual / compositional flaws on YOUR assets
omniscan scan rvd --repo . --depth deep --budget 8h \
  --focus isolation,deserialization --backend glasswing --wait

# read + triage + report
omniscan findings list scan_abc --min-severity medium
omniscan findings triage find_123 --status false_positive --reason "..."
omniscan report scan_abc --format html,sarif
```
