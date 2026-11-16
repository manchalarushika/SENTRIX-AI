#!/usr/bin/env bash
# Start the SENTRIX AI backend and frontend together for local development.
# Ctrl-C stops both.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT/backend"
if [ ! -d .venv ]; then
  echo "Creating backend virtualenv..."
  python3 -m venv .venv
  ./.venv/bin/pip install -q -r requirements.txt
fi
[ -f .env ] || cp .env.example .env

echo "Starting backend on http://127.0.0.1:8000 ..."
./.venv/bin/uvicorn sentrix.main:app --port 8000 &
BACKEND_PID=$!

cd "$ROOT/frontend"
[ -d node_modules ] || npm install
echo "Starting frontend on http://127.0.0.1:5173 ..."
npm run dev &
FRONTEND_PID=$!

trap 'echo; echo "Stopping..."; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true' INT TERM
wait
