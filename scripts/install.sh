#!/usr/bin/env bash
# OmniScan — one-command install & setup.
#
#   ./scripts/install.sh
#
# Installs the Python backend (via uv) and the dashboard (via npm), prepares the dev
# .env, and pre-pulls the containerized scanner images if Docker is available. Safe to
# re-run (idempotent).
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
echo "==> OmniScan setup in $ROOT"

# --- 1. Python backend (uv) ------------------------------------------------
if ! command -v uv >/dev/null 2>&1; then
  echo "==> installing uv (Python package manager)"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  # shellcheck disable=SC1090
  export PATH="$HOME/.local/bin:$PATH"
fi
echo "==> installing Python deps"
uv sync --extra dev

# --- 2. .env (non-sensitive config + secret references only) ---------------
if [ ! -f .env ]; then
  echo "==> creating .env from .env.example"
  cp .env.example .env
fi

# --- 3. Dashboard (npm) ----------------------------------------------------
if command -v npm >/dev/null 2>&1; then
  echo "==> installing dashboard deps"
  (cd dashboard && npm install --no-fund --no-audit)
else
  echo "!! npm not found — skipping dashboard install (install Node 18+ to use the UI)"
fi

# --- 4. Scanner images (optional; needed for real containerized adapters) --
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "==> pre-pulling pinned scanner images"
  docker pull semgrep/semgrep:1.97.0 || true
  docker pull ghcr.io/gitleaks/gitleaks:v8.21.2 || true
else
  echo "!! Docker not available — the built-in 'demoscan' SAST adapter still works."
  echo "   Real scanners (semgrep, gitleaks) require Docker."
fi

cat <<'EOF'

==> Setup complete.

Next:
  1. (optional) For the real, fully-open-source RVD model backend, install Ollama
     (https://ollama.com) and pull an open model — no API key, runs locally:
        ollama serve &
        ollama pull qwen2.5-coder:7b      # or llama3.1, deepseek-r1, mistral, ...
     Without it, RVD gracefully falls back to the heuristic backend.

  2. Run everything (API + dashboard):
        ./scripts/dev.sh
     API:        http://127.0.0.1:8000  (docs at /docs)
     Dashboard:  http://127.0.0.1:5173

  3. Or run pieces individually:
        make api          # backend only
        make dashboard    # UI only

See RUNNING.md for the full guide.
EOF
