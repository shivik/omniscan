#!/usr/bin/env bash
# Run the full OmniScan stack locally: API (:8000) + dashboard (:5173).
# Ctrl-C stops both.
set -euo pipefail
cd "$(dirname "$0")/.."

export PATH="$HOME/.local/bin:$PATH"

pids=()
cleanup() { echo; echo "==> stopping…"; for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

echo "==> starting API on http://127.0.0.1:8000 (docs at /docs)"
uv run uvicorn api.main:app --port 8000 &
pids+=($!)

if command -v npm >/dev/null 2>&1; then
  echo "==> starting dashboard on http://127.0.0.1:5173"
  (cd dashboard && npm run dev) &
  pids+=($!)
else
  echo "!! npm not found — running API only"
fi

echo "==> stack up. Press Ctrl-C to stop."
wait
