# SENTRIX AI — Setup & Operations

## Prerequisites

- **Python 3.11+** (developed and tested on 3.13)
- **Node.js 20+** and npm (developed on Node 22)
- No external services required for the core platform.

## Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # optional; all defaults are safe
uvicorn sentrix.main:app --reload --port 8000
```

- API: <http://127.0.0.1:8000>  ·  Docs: <http://127.0.0.1:8000/docs>
- Dev dependencies (tests + lint): `pip install -r requirements-dev.txt`

### Database setup

No manual steps. On startup SENTRIX AI creates all tables and seeds the
threat-intelligence knowledge base automatically.

- **Default**: SQLite at `backend/sentrix.db` (WAL mode, foreign keys on).
  It is created on first run and git-ignored.
- **Reset**: stop the server and delete `backend/sentrix.db*`, or call
  `POST /api/demo/reset?confirm=RESET` (keeps assets, intel and audit log).
- **Postgres** (optional): set `DATABASE_URL=postgresql+psycopg://user:pass@host/db`
  and `pip install "psycopg[binary]"`. The same `create_all` bootstrap runs.

## Frontend

```bash
cd frontend
npm install
npm run dev                        # http://127.0.0.1:5173 (proxies /api and /ws)
```

Production build: `npm run build` → static assets in `frontend/dist/`
(serve behind any web server; set `VITE_API_URL` or reverse-proxy `/api` + `/ws`).

## Exact commands to start the whole application

Two terminals:

```bash
# Terminal 1 — backend
cd backend && source .venv/bin/activate && uvicorn sentrix.main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend && npm run dev
```

Or one command (starts both, Ctrl-C stops both):

```bash
./scripts/run_dev.sh
```

Then open <http://127.0.0.1:5173>, go to **System & Demo**, click
**Load assets & baseline telemetry**, pick a scenario and **Run**.

## Configuration (`backend/.env`)

All keys are documented in `backend/.env.example`. Highlights:

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | `development`/`production`/`test`. In production, reads also require the API key. |
| `DATABASE_URL` | SQLite file | Any SQLAlchemy URL. |
| `API_KEY` | *(empty)* | When set, mutating requests need `X-API-Key`. |
| `LLM_PROVIDER` | `none` | `none`/`openai`/`anthropic` for optional narrative analysis. |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | *(empty)* | LLM credentials (read from env only; never logged/returned). |
| `SOAR_WEBHOOK_URL` | *(empty)* | Approved actions POST here; otherwise they become manual tasks. |
| `CORRELATION_WINDOW_MINUTES` | `60` | Event-correlation window. |
| `TWIN_SIMULATION_RUNS` | `300` | Monte Carlo runs per playbook. |
| `COUNCIL_WEIGHT_*` | see file | Relative AI Council voting weights. |

## Tests & quality gates

```bash
cd backend
pytest                 # 30 tests
ruff check sentrix tests

cd ../frontend
npm run build          # tsc typecheck + vite production build
npm run lint           # oxlint
```

## Sending real telemetry

See [`SENDING_TELEMETRY.md`](SENDING_TELEMETRY.md). In short:

```bash
# Windows (run as Administrator to read the Security log)
cd backend/scripts; ./forward_windows_events.ps1 -Minutes 60

# Any JSON / JSON Lines file
python backend/scripts/send_events.py backend/samples/sample_events.jsonl

# Refresh threat intel from official feeds
python backend/scripts/import_intel.py cisa_kev --url <CISA KEV JSON URL>
```

## Troubleshooting

- **Dashboard says "Backend unreachable"** — ensure uvicorn is running on
  port 8000; the dev server proxies to `http://127.0.0.1:8000` (override with
  `SENTRIX_BACKEND_URL`).
- **401 Unauthorized** — `API_KEY` is set; enter it in **System & Demo → API key**.
- **No incidents after a scenario** — load assets + baseline first so behavioural
  baselines exist, then run a scenario.
- **LLM tab shows "disabled"** — expected without `LLM_PROVIDER` + a key; all
  other analysis works regardless.
